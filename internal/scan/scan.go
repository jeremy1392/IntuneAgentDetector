package scan

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"detectoragent/internal/catalog"
	"detectoragent/internal/winapi"
)

// Options tune a scan.
type Options struct {
	RecentDays int
	Now        time.Time
}

// Run collects every fact needed by the correlator. It never returns an
// error: failures of individual collectors are recorded in Snapshot.Errors
// and coverage gaps in Snapshot.Coverage.
func Run(ctx context.Context, cat *catalog.Catalog, opt Options) *Snapshot {
	if opt.Now.IsZero() {
		opt.Now = time.Now()
	}
	if opt.RecentDays <= 0 {
		opt.RecentDays = 30
	}
	since := opt.Now.AddDate(0, 0, -opt.RecentDays)
	id := winapi.Current()
	s := &Snapshot{
		StartedAt:  opt.Now,
		RunAsSID:   id.SID,
		RunAs:      id.Account,
		Elevated:   id.Elevated,
		IsSystem:   id.IsSystem(),
		SessionID:  id.SessionID,
		RecentDays: opt.RecentDays,
		DNS:        map[string][]net.IP{},
	}
	note := func(msgs ...string) { s.Coverage = append(s.Coverage, msgs...) }
	fail := func(what string, err error) {
		if err != nil {
			s.Errors = append(s.Errors, fmt.Sprintf("%s: %v", what, err))
		}
	}

	profiles, notes := listProfiles(id.Elevated || s.IsSystem, id.SID)
	s.Profiles = profiles
	note(notes...)

	// Each collector works on its own data in a goroutine and returns a
	// function that stores the result. Only this goroutine applies them, so
	// collectors that miss the deadline are simply ignored.
	type apply func()
	results := make(chan apply, 8)
	names := []string{}
	run := func(name string, f func() apply) {
		names = append(names, name)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					results <- func() { fail(name, fmt.Errorf("panic: %v", r)) }
				}
			}()
			results <- f()
		}()
	}
	run("processes", func() apply {
		procs, err := listProcesses()
		return func() { s.Processes = procs; fail("processes", err) }
	})
	run("network", func() apply {
		conns, listeners, err := tcpTable()
		return func() { s.Conns, s.Listeners = conns, listeners; fail("network", err) }
	})
	run("dns", func() apply {
		dns, err := dnsCache(cat)
		return func() {
			switch {
			case len(dns) == 0 && !id.Elevated && !id.IsSystem():
				note("DNS cache unreadable without administrator rights: network attribution limited to dedicated IP ranges")
			case err != nil:
				note("DNS cache enumeration unavailable: only exact catalog host names were looked up")
			}
			s.DNS = dns
		}
	})
	run("traces", func() apply {
		traces, notes := executionTraces(since)
		return func() { s.Traces = traces; note(notes...) }
	})
	run("inventory", func() apply {
		inv := inventory(cat, profiles, id.SID, since)
		return func() { s.Inventory = inv }
	})
	run("environment", func() apply {
		env := environment(cat, profiles, id.SID)
		return func() { s.EnvItems = env }
	})

	for received := 0; received < len(names); {
		select {
		case f := <-results:
			f()
			received++
		case <-ctx.Done():
			fail("scan", fmt.Errorf("%v: %d of %d collectors finished, results are partial", ctx.Err(), received, len(names)))
			received = len(names)
		}
	}

	if s.DNS == nil {
		s.DNS = map[string][]net.IP{}
	}
	if s.Processes == nil {
		s.Processes = map[uint32]*Process{}
	}
	s.Children = buildChildren(s.Processes)
	s.IPToHosts = invertDNS(s.DNS)
	inspectCandidates(s, cat)
	countDenied(s)
	return s
}

// inspectCandidates reads version info for every process, then signer,
// loaded modules and environment for the processes that matter.
func inspectCandidates(s *Snapshot, cat *catalog.Catalog) {
	netPIDs := map[uint32]bool{}
	toolPorts := map[uint16]bool{}
	for _, t := range cat.Tools {
		for _, p := range t.Ports {
			toolPorts[uint16(p)] = true
		}
	}
	for _, c := range s.Conns {
		if isLoopback(c.RemoteIP) {
			if toolPorts[c.RemotePort] {
				netPIDs[c.PID] = true
			}
			continue
		}
		if len(s.IPToHosts[c.RemoteIP.String()]) > 0 || cat.MatchIP(c.RemoteIP) != nil {
			netPIDs[c.PID] = true
		}
	}
	portPIDs := map[uint32]bool{}
	for _, l := range s.Listeners {
		if toolPorts[l.Port] {
			portPIDs[l.PID] = true
		}
	}

	type job struct {
		p                       *Process
		signer, modules, envvar bool
	}
	var jobs []job
	for _, p := range s.Processes {
		if p.Path == "" {
			continue
		}
		catalogHit := len(cat.ToolsForImage(p.Image)) > 0
		if !catalogHit {
			for _, t := range cat.Tools {
				if t.MatchPath(p.Path) || t.MatchCmdline(p.Cmdline) || t.MatchPackage(p.PackageFamily) {
					catalogHit = true
					break
				}
			}
		}
		interp := cat.Generic.IsInterpreter(p.Image)
		network := netPIDs[p.PID]
		listener := portPIDs[p.PID]
		sameUser := s.Elevated || s.IsSystem || strings.EqualFold(p.UserSID, s.RunAsSID)
		jobs = append(jobs, job{
			p:       p,
			signer:  catalogHit || network || listener,
			modules: (interp || network || listener) && sameUser,
			envvar:  (interp || network) && sameUser,
		})
	}

	work := make(chan job)
	var wg sync.WaitGroup
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	keep := envKeeper(cat)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range work {
				p := j.p
				id := identify(p.Path, false)
				p.Product, p.Company = id.Product, id.Company
				wantSigner := j.signer
				if !wantSigner {
					for _, t := range cat.Tools {
						if t.HasProduct(p.Product) {
							wantSigner = true
							break
						}
					}
				}
				if wantSigner {
					p.Signer = identify(p.Path, true).Signer
				}
				if j.modules {
					p.Modules = listModules(p.PID)
				}
				if j.envvar {
					if env, err := readEnvironment(p.PID, keep); err == nil {
						p.Env = env
					}
				}
				p.Inspected = true
			}
		}()
	}
	for _, j := range jobs {
		work <- j
	}
	close(work)
	wg.Wait()
}

func countDenied(s *Snapshot) {
	denied := 0
	for _, p := range s.Processes {
		if p.Denied {
			denied++
		}
	}
	if denied > 0 && !s.Elevated && !s.IsSystem {
		s.Coverage = append(s.Coverage, fmt.Sprintf("%d processes of other users or protected processes could not be inspected", denied))
	}
}
