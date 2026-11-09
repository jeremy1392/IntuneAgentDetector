// Package correlate turns the raw facts of a scan into findings: one finding
// per tool and per user, with graded level and confidence.
package correlate

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"detectoragent/internal/catalog"
	"detectoragent/internal/model"
	"detectoragent/internal/redact"
	"detectoragent/internal/scan"
	"detectoragent/internal/winapi"
)

const (
	maxEvidencePerFinding = 25
	maxAncestorDepth      = 8
)

// Build correlates a snapshot against the catalog.
func Build(cat *catalog.Catalog, s *scan.Snapshot) []model.Finding {
	a := &acc{
		cat:       cat,
		s:         s,
		findings:  map[string]*model.Finding{},
		procTools: map[uint32][]procMatch{},
		procKeys:  map[uint32][]string{},
		procEvIdx: map[string]int{},
		llmProcs:  map[uint32]bool{},
	}
	a.matchProcesses()
	a.network()
	a.localLLM()
	a.processEnvironment()
	a.modules()
	a.behavior()
	a.mcpServers()
	a.browserAutomation()
	a.traces()
	a.inventory()
	a.environment()
	return a.finish()
}

type procMatch struct {
	tool   *catalog.Tool
	conf   model.Confidence
	reason string
}

type acc struct {
	cat       *catalog.Catalog
	s         *scan.Snapshot
	findings  map[string]*model.Finding
	order     []string
	procTools map[uint32][]procMatch
	procKeys  map[uint32][]string // finding keys attached to a process (tools and generic)
	procEvIdx map[string]int      // groups processes sharing an image path
	llmProcs  map[uint32]bool     // processes talking to an LLM endpoint
}

func findingKey(toolID, sid string) string { return toolID + "|" + strings.ToLower(sid) }

// toolFinding returns (creating it if needed) the finding of a catalog tool.
func (a *acc) toolFinding(t *catalog.Tool, sid string) (*model.Finding, string) {
	key := findingKey(t.ID, sid)
	if f, ok := a.findings[key]; ok {
		return f, key
	}
	f := &model.Finding{ToolID: t.ID, ToolName: t.Name, Vendor: t.Vendor, Category: t.Category,
		UserSID: sid, Approved: a.cat.IsSanctioned(t.ID, nil)}
	a.findings[key] = f
	a.order = append(a.order, key)
	return f, key
}

// genericFinding returns (creating it if needed) a finding not tied to a catalog tool.
func (a *acc) genericFinding(id, name, category, sid string, approved bool) (*model.Finding, string) {
	key := findingKey(id, sid)
	if f, ok := a.findings[key]; ok {
		if approved {
			f.Approved = true
		}
		return f, key
	}
	f := &model.Finding{ToolID: id, ToolName: name, Category: category, UserSID: sid, Approved: approved}
	a.findings[key] = f
	a.order = append(a.order, key)
	return f, key
}

func addEvidence(f *model.Finding, e model.Evidence) {
	for _, x := range f.Evidence {
		if x.Kind == e.Kind && x.Detail == e.Detail && x.Path == e.Path {
			return
		}
	}
	f.Evidence = append(f.Evidence, e)
}

func (a *acc) attach(pid uint32, key string) {
	for _, k := range a.procKeys[pid] {
		if k == key {
			return
		}
	}
	a.procKeys[pid] = append(a.procKeys[pid], key)
}

// ----------------------------------------------------------------- processes

func (a *acc) matchProcesses() {
	pids := sortedPIDs(a.s.Processes)
	for _, pid := range pids {
		p := a.s.Processes[pid]
		matches := matchProcess(a.cat, p)
		if len(matches) == 0 {
			continue
		}
		a.procTools[pid] = matches
		for _, m := range matches {
			f, key := a.toolFinding(m.tool, p.UserSID)
			a.attach(pid, key)
			groupKey := key + "|" + strings.ToLower(p.Path)
			if idx, ok := a.procEvIdx[groupKey]; ok {
				e := &f.Evidence[idx]
				e.Detail = bumpProcessCount(e.Detail)
				continue
			}
			e := model.Evidence{Kind: "process", PID: p.PID, Path: p.Path, Level: model.LevelActive, Confidence: m.conf,
				Cmdline: cmdline(p), Detail: fmt.Sprintf("running %s (pid %d, matched by %s)", p.Image, p.PID, m.reason)}
			f.Evidence = append(f.Evidence, e)
			a.procEvIdx[groupKey] = len(f.Evidence) - 1
		}
	}
}

func matchProcess(cat *catalog.Catalog, p *scan.Process) []procMatch {
	var best []procMatch
	bestConf := model.ConfidenceUnknown
	for _, t := range cat.Tools {
		conf, reason := matchTool(t, p)
		if conf == model.ConfidenceUnknown {
			continue
		}
		if conf > bestConf {
			best, bestConf = best[:0], conf
		}
		if conf == bestConf {
			best = append(best, procMatch{tool: t, conf: conf, reason: reason})
		}
	}
	return best
}

func matchTool(t *catalog.Tool, p *scan.Process) (model.Confidence, string) {
	switch {
	case p.PackageFamily != "" && t.MatchPackage(p.PackageFamily):
		return model.ConfidenceHigh, "package " + p.PackageFamily
	case t.MatchPath(p.Path):
		return model.ConfidenceHigh, "install path"
	case t.MatchCmdline(p.Cmdline):
		return model.ConfidenceHigh, "command line"
	case t.HasProduct(p.Product) && t.HasSigners() && t.MatchSigner(p.Signer):
		return model.ConfidenceHigh, fmt.Sprintf("product %q signed by %s", p.Product, p.Signer)
	case t.HasImage(p.Image) && t.HasSigners() && t.MatchSigner(p.Signer):
		return model.ConfidenceHigh, "signed by " + p.Signer
	case t.HasProduct(p.Product) && !t.HasSigners():
		return model.ConfidenceHigh, fmt.Sprintf("product %q", p.Product)
	case t.HasProduct(p.Product):
		return model.ConfidenceMedium, fmt.Sprintf("product %q, unexpected signer %q", p.Product, p.Signer)
	case t.HasImage(p.Image):
		return model.ConfidenceMedium, "executable name"
	}
	return model.ConfidenceUnknown, ""
}

func bumpProcessCount(detail string) string {
	const marker = " processes)"
	if i := strings.LastIndex(detail, ", "); i > 0 && strings.HasSuffix(detail, marker) {
		var n int
		if _, err := fmt.Sscanf(detail[i+2:], "%d processes)", &n); err == nil {
			return detail[:i] + fmt.Sprintf(", %d processes)", n+1)
		}
	}
	return strings.TrimSuffix(detail, ")") + ", 2 processes)"
}

// ------------------------------------------------------------------- network

type netHit struct {
	ep        *catalog.Endpoint
	host      string
	dedicated bool
}

func (a *acc) network() {
	seen := map[string]bool{}
	for _, c := range a.s.Conns {
		p := a.s.Processes[c.PID]
		if p == nil || c.RemoteIP == nil || c.RemoteIP.IsLoopback() {
			continue
		}
		hit, ok := a.resolve(c)
		if !ok {
			continue
		}
		dedupe := fmt.Sprintf("%d|%s", c.PID, hit.ep.Provider)
		if seen[dedupe] {
			continue
		}
		seen[dedupe] = true
		detail := fmt.Sprintf("connected to %s (%s, %s) from %s pid %d", hit.host, hit.ep.Provider, hit.ep.Category, p.Image, p.PID)

		if matches := a.procTools[c.PID]; len(matches) > 0 {
			a.llmProcs[c.PID] = true
			for _, m := range matches {
				f, _ := a.toolFinding(m.tool, p.UserSID)
				addEvidence(f, model.Evidence{Kind: "network", Detail: detail, PID: p.PID, Path: p.Path,
					Level: model.LevelActive, Confidence: m.conf})
			}
			continue
		}
		if a.cat.Generic.IsBrowser(p.Image) {
			continue // web use of AI services is the web proxy's job
		}
		a.llmProcs[c.PID] = true
		conf := model.ConfidenceLow
		if hit.dedicated && !hit.ep.Shared {
			conf = model.ConfidenceMedium
		}
		id := "llm-api:" + slug(hit.ep.Provider) + ":" + strings.ToLower(p.Image)
		name := fmt.Sprintf("%s used by %s", hit.ep.Provider, p.Image)
		f, key := a.genericFinding(id, name, hit.ep.Category, p.UserSID, a.cat.IsSanctioned("", hit.ep))
		a.attach(c.PID, key)
		addEvidence(f, model.Evidence{Kind: "network", Detail: detail, PID: p.PID, Path: p.Path,
			Cmdline: cmdline(p), Level: model.LevelActive, Confidence: conf})
	}
}

// resolve maps a connection to a catalog endpoint, by DNS cache first and by
// dedicated address range second.
func (a *acc) resolve(c scan.Conn) (netHit, bool) {
	var hit netHit
	if e := a.cat.MatchIP(c.RemoteIP); e != nil {
		hit = netHit{ep: e, host: c.RemoteIP.String(), dedicated: true}
	}
	for _, h := range a.s.IPToHosts[c.RemoteIP.String()] {
		if e := a.cat.MatchHost(h); e != nil {
			hit.ep, hit.host = e, h
			break
		}
	}
	return hit, hit.ep != nil
}

// ----------------------------------------------------------- local runtimes

func (a *acc) localLLM() {
	portOwner := map[uint16]uint32{}
	for _, l := range a.s.Listeners {
		var tools []*catalog.Tool
		for _, t := range a.cat.Tools {
			if t.HasPort(int(l.Port)) {
				tools = append(tools, t)
			}
		}
		if len(tools) == 0 {
			continue
		}
		p := a.s.Processes[l.PID]
		if p == nil {
			continue
		}
		portOwner[l.Port] = l.PID
		matched := false
		for _, m := range a.procTools[l.PID] {
			for _, t := range tools {
				if m.tool == t {
					f, _ := a.toolFinding(t, p.UserSID)
					addEvidence(f, model.Evidence{Kind: "listener", PID: p.PID, Path: p.Path, Level: model.LevelActive,
						Confidence: m.conf, Detail: fmt.Sprintf("serving an LLM API on port %d", l.Port)})
					matched = true
				}
			}
		}
		if matched || len(a.procTools[l.PID]) > 0 {
			continue
		}
		conf := model.ConfidenceLow
		if l.Port == 11434 || hasInferenceModule(a.cat, p) {
			conf = model.ConfidenceMedium
		}
		id := fmt.Sprintf("local-llm-server:%s:%d", strings.ToLower(p.Image), l.Port)
		f, key := a.genericFinding(id, fmt.Sprintf("Local LLM server on port %d (%s)", l.Port, p.Image), "local-llm", p.UserSID, false)
		a.attach(p.PID, key)
		addEvidence(f, model.Evidence{Kind: "listener", PID: p.PID, Path: p.Path, Level: model.LevelActive, Confidence: conf,
			Detail: fmt.Sprintf("%s listens on port %d, used by %s", p.Image, l.Port, toolNames(tools))})
	}

	for _, c := range a.s.Conns {
		if c.RemoteIP == nil || !c.RemoteIP.IsLoopback() {
			continue
		}
		owner, ok := portOwner[c.RemotePort]
		if !ok || owner == c.PID {
			continue
		}
		p := a.s.Processes[c.PID]
		if p == nil || a.cat.Generic.IsBrowser(p.Image) {
			continue
		}
		a.llmProcs[c.PID] = true
		detail := fmt.Sprintf("%s pid %d talks to the local LLM server on port %d", p.Image, p.PID, c.RemotePort)
		if matches := a.procTools[c.PID]; len(matches) > 0 {
			for _, m := range matches {
				f, _ := a.toolFinding(m.tool, p.UserSID)
				addEvidence(f, model.Evidence{Kind: "network", Detail: detail, PID: p.PID, Level: model.LevelActive, Confidence: m.conf})
			}
			continue
		}
		id := "local-llm-client:" + strings.ToLower(p.Image)
		f, key := a.genericFinding(id, "Local LLM used by "+p.Image, "local-llm", p.UserSID, false)
		a.attach(c.PID, key)
		addEvidence(f, model.Evidence{Kind: "network", Detail: detail, PID: p.PID, Path: p.Path,
			Level: model.LevelActive, Confidence: model.ConfidenceLow})
	}
}

func hasInferenceModule(cat *catalog.Catalog, p *scan.Process) bool {
	for _, m := range p.Modules {
		if cat.Generic.InferenceModule(m) {
			return true
		}
	}
	return false
}

// ------------------------------------------------------ process environment

func (a *acc) processEnvironment() {
	for _, pid := range sortedPIDs(a.s.Processes) {
		p := a.s.Processes[pid]
		for _, v := range p.Env {
			switch {
			case a.cat.Generic.IsBaseURLVar(v.Name) && v.Value != "":
				a.baseURL(v.Name, v.Value, p.UserSID, model.LevelActive, fmt.Sprintf("in %s pid %d", p.Image, p.PID), p)
			case a.cat.Generic.IsAPIKeyVar(v.Name):
				for _, key := range a.procKeys[pid] {
					addEvidence(a.findings[key], model.Evidence{Kind: "env", Level: model.LevelActive,
						Confidence: model.ConfidenceMedium, PID: p.PID,
						Detail: fmt.Sprintf("%s is set in %s pid %d (value not recorded)", v.Name, p.Image, p.PID)})
				}
			}
		}
	}
}

// baseURL handles an LLM base URL found in a process or a persistent variable.
func (a *acc) baseURL(varName, host, sid string, level model.Level, where string, p *scan.Process) {
	if isLocalHost(host) {
		return
	}
	detail := fmt.Sprintf("%s points to %s %s", varName, host, where)
	ev := model.Evidence{Kind: "base-url", Detail: detail, Level: level, Confidence: model.ConfidenceMedium}
	if p != nil {
		ev.PID, ev.Path = p.PID, p.Path
		if len(a.procTools[p.PID]) > 0 {
			for _, m := range a.procTools[p.PID] {
				f, _ := a.toolFinding(m.tool, sid)
				addEvidence(f, ev)
			}
			return
		}
		// A variable that every process inherits from the persistent
		// environment, or that sits in a process with no outbound
		// connection, describes configuration, not use: it must not turn
		// that process into an LLM client (and its children into agent
		// actions). The persistent variable is reported on its own.
		switch {
		case a.persistentBaseURL(varName, host, sid):
			ev.Confidence = model.ConfidenceLow
			ev.Detail += " (inherited from the persistent environment)"
			p = nil
		case !a.hasOutboundConn(p.PID):
			ev.Confidence = model.ConfidenceLow
			ev.Detail += " (no outbound connection)"
			p = nil
		}
	}
	if ep := a.cat.MatchHost(host); ep != nil {
		id := "llm-config:" + slug(ep.Provider)
		f, key := a.genericFinding(id, ep.Provider+" configured as LLM API base", ep.Category, sid, a.cat.IsSanctioned("", ep))
		addEvidence(f, ev)
		if p != nil {
			a.attach(p.PID, key)
			a.llmProcs[p.PID] = true
		}
		return
	}
	id := "relay-candidate:" + host
	f, key := a.genericFinding(id, "Unknown LLM relay "+host, "relay", sid, a.cat.IsSanctionedHost(host))
	addEvidence(f, ev)
	if p != nil {
		a.attach(p.PID, key)
		a.llmProcs[p.PID] = true
	}
}

// persistentBaseURL reports whether the same variable with the same host is
// set in the persistent machine environment or in this user's environment.
func (a *acc) persistentBaseURL(varName, host, sid string) bool {
	for _, it := range a.s.EnvItems {
		if it.Kind != "base-url" || !strings.EqualFold(it.Var, varName) || !strings.EqualFold(it.Host, host) {
			continue
		}
		if it.UserSID == "" || sid == "" || strings.EqualFold(it.UserSID, sid) {
			return true
		}
	}
	return false
}

// hasOutboundConn reports whether a process holds an established connection
// to a remote, non-loopback address.
func (a *acc) hasOutboundConn(pid uint32) bool {
	for _, c := range a.s.Conns {
		if c.PID == pid && c.RemoteIP != nil && !c.RemoteIP.IsLoopback() && !c.RemoteIP.IsUnspecified() {
			return true
		}
	}
	return false
}

func isLocalHost(h string) bool {
	switch h {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal":
		return true
	}
	return strings.HasPrefix(h, "127.")
}

// ------------------------------------------------------------------- modules

func (a *acc) modules() {
	for _, pid := range sortedPIDs(a.s.Processes) {
		p := a.s.Processes[pid]
		var inference, tokenizer []string
		for _, m := range p.Modules {
			switch {
			case a.cat.Generic.InferenceModule(m):
				inference = append(inference, m)
			case a.cat.Generic.TokenizerModule(m):
				tokenizer = append(tokenizer, m)
			}
		}
		if len(inference) > 0 {
			detail := fmt.Sprintf("%s pid %d loads inference runtime %s", p.Image, p.PID, strings.Join(limit(inference, 4), ", "))
			if matches := a.procTools[pid]; len(matches) > 0 {
				for _, m := range matches {
					f, _ := a.toolFinding(m.tool, p.UserSID)
					addEvidence(f, model.Evidence{Kind: "module", Detail: detail, PID: pid, Level: model.LevelActive, Confidence: m.conf})
				}
			} else {
				id := "local-llm-runtime:" + strings.ToLower(p.Image)
				f, key := a.genericFinding(id, "Local LLM runtime in "+p.Image, "local-llm", p.UserSID, false)
				a.attach(pid, key)
				addEvidence(f, model.Evidence{Kind: "module", Detail: detail, PID: pid, Path: p.Path,
					Level: model.LevelActive, Confidence: model.ConfidenceMedium})
			}
		}
		if len(tokenizer) > 0 && a.llmProcs[pid] {
			for _, key := range a.procKeys[pid] {
				addEvidence(a.findings[key], model.Evidence{Kind: "module", PID: pid, Level: model.LevelActive,
					Confidence: model.ConfidenceMedium,
					Detail:     fmt.Sprintf("%s pid %d loads LLM tokenizer %s", p.Image, pid, strings.Join(limit(tokenizer, 3), ", "))})
			}
		}
	}
}

// ------------------------------------------------------------------ behavior

// behavior flags processes that talk to an LLM and run shells: the defining
// pattern of an agent.
func (a *acc) behavior() {
	for _, pid := range sortedPIDs(a.s.Processes) {
		if !a.llmProcs[pid] {
			continue
		}
		p := a.s.Processes[pid]
		shells := a.shellDescendants(pid, 2)
		if len(shells) == 0 {
			continue
		}
		detail := fmt.Sprintf("%s pid %d talks to an LLM and runs %s", p.Image, pid, strings.Join(limit(shells, 6), ", "))
		if matches := a.procTools[pid]; len(matches) > 0 {
			for _, m := range matches {
				f, _ := a.toolFinding(m.tool, p.UserSID)
				addEvidence(f, model.Evidence{Kind: "behavior", Detail: detail, PID: pid, Level: model.LevelActive, Confidence: m.conf})
			}
			continue
		}
		id := "probable-agent:" + strings.ToLower(p.Image)
		f, key := a.genericFinding(id, "Probable custom AI agent ("+p.Image+")", "custom-agent", p.UserSID, a.processApproved(pid))
		a.attach(pid, key)
		addEvidence(f, model.Evidence{Kind: "behavior", Detail: detail, PID: pid, Path: p.Path,
			Cmdline: cmdline(p), Level: model.LevelActive, Confidence: model.ConfidenceMedium})
	}
}

// processApproved is true when every LLM finding of the process is approved.
func (a *acc) processApproved(pid uint32) bool {
	keys := a.procKeys[pid]
	if len(keys) == 0 {
		return false
	}
	for _, k := range keys {
		if f := a.findings[k]; f == nil || !f.Approved {
			return false
		}
	}
	return true
}

func (a *acc) shellDescendants(pid uint32, depth int) []string {
	var out []string
	var walk func(pid uint32, d int)
	walk = func(pid uint32, d int) {
		if d > depth {
			return
		}
		for _, c := range a.s.Children[pid] {
			cp := a.s.Processes[c]
			if cp == nil {
				continue
			}
			if a.cat.Generic.IsShell(cp.Image) {
				out = appendUnique(out, strings.ToLower(cp.Image))
			}
			walk(c, d+1)
		}
	}
	walk(pid, 1)
	sort.Strings(out)
	return out
}

// owner returns the finding keys of the nearest ancestor attached to a tool
// or an LLM finding.
func (a *acc) owner(pid uint32) (uint32, []string) {
	seen := map[uint32]bool{}
	cur := a.s.Processes[pid]
	for depth := 0; cur != nil && depth < maxAncestorDepth; depth++ {
		parent, ok := a.s.Processes[cur.PPID]
		if !ok || seen[cur.PPID] || cur.PPID == cur.PID {
			return 0, nil
		}
		if !parent.Created.IsZero() && !cur.Created.IsZero() && parent.Created.After(cur.Created) {
			return 0, nil // PID reused by a newer process
		}
		seen[cur.PPID] = true
		if keys := a.procKeys[parent.PID]; len(keys) > 0 {
			return parent.PID, keys
		}
		cur = parent
	}
	return 0, nil
}

// ---------------------------------------------------------------- MCP servers

func (a *acc) mcpServers() {
	for _, pid := range sortedPIDs(a.s.Processes) {
		p := a.s.Processes[pid]
		m := a.cat.Generic.MCPMatch(p.Cmdline)
		if m == "" {
			continue
		}
		label := strings.ToLower(strings.Trim(m, `"\/ `))
		detail := fmt.Sprintf("MCP server %s running as %s pid %d", label, p.Image, pid)
		if _, keys := a.owner(pid); len(keys) > 0 {
			for _, k := range keys {
				f := a.findings[k]
				addEvidence(f, model.Evidence{Kind: "mcp-server", Detail: detail, PID: pid,
					Level: model.LevelActive, Confidence: currentConfidence(f)})
			}
			continue
		}
		id := "mcp-server:" + slug(label)
		f, _ := a.genericFinding(id, "MCP server "+label+" (host not identified)", "mcp", p.UserSID, false)
		addEvidence(f, model.Evidence{Kind: "mcp-server", Detail: detail, PID: pid, Path: p.Path,
			Cmdline: cmdline(p), Level: model.LevelActive, Confidence: model.ConfidenceMedium})
	}
}

// --------------------------------------------------------- browser automation

func (a *acc) browserAutomation() {
	for _, pid := range sortedPIDs(a.s.Processes) {
		p := a.s.Processes[pid]
		if !a.cat.Generic.IsBrowser(p.Image) {
			continue
		}
		flag := a.cat.Generic.AutomationFlag(p.Cmdline)
		if flag == "" || strings.Contains(p.Cmdline, "--type=") {
			continue
		}
		detail := fmt.Sprintf("%s pid %d is driven by automation (%s)", p.Image, pid, flag)
		if _, keys := a.owner(pid); len(keys) > 0 {
			for _, k := range keys {
				f := a.findings[k]
				addEvidence(f, model.Evidence{Kind: "browser-automation", Detail: detail, PID: pid,
					Level: model.LevelActive, Confidence: currentConfidence(f)})
			}
			continue
		}
		id := "browser-automation:" + strings.ToLower(p.Image)
		f, _ := a.genericFinding(id, "Automated browser ("+p.Image+")", "browser-automation", p.UserSID, false)
		addEvidence(f, model.Evidence{Kind: "browser-automation", Detail: detail, PID: pid, Path: p.Path,
			Level: model.LevelActive, Confidence: model.ConfidenceLow})
	}
}

// -------------------------------------------------------------------- traces

func (a *acc) traces() {
	for _, tr := range a.s.Traces {
		t := tr.Time
		switch {
		case tr.Package != "":
			for _, tool := range a.cat.Tools {
				if tool.MatchPackage(tr.Package) {
					f, _ := a.toolFinding(tool, tr.UserSID)
					addEvidence(f, model.Evidence{Kind: "execution-trace", Time: &t, Level: model.LevelRecent,
						Confidence: model.ConfidenceHigh, Detail: fmt.Sprintf("%s last ran %s (BAM)", tr.Package, t.Format(time.RFC3339))})
				}
			}
		case tr.Source == "bam":
			matched := false
			for _, tool := range a.cat.Tools {
				if tool.MatchPath(tr.Path) {
					f, _ := a.toolFinding(tool, tr.UserSID)
					addEvidence(f, model.Evidence{Kind: "execution-trace", Time: &t, Path: tr.Path, Level: model.LevelRecent,
						Confidence: model.ConfidenceHigh, Detail: fmt.Sprintf("%s last ran %s (BAM)", filepath.Base(tr.Path), t.Format(time.RFC3339))})
					matched = true
				}
			}
			if !matched {
				a.traceByImage(tr, filepath.Base(tr.Path), "BAM")
			}
		case tr.Source == "prefetch":
			a.traceByImage(tr, tr.Path, "Prefetch")
		}
	}
}

// traceByImage attributes a trace by executable name only when exactly one
// tool claims that name.
func (a *acc) traceByImage(tr scan.Trace, image, source string) {
	tools := a.cat.ToolsForImage(image)
	if len(tools) != 1 {
		return
	}
	t := tr.Time
	f, _ := a.toolFinding(tools[0], tr.UserSID)
	addEvidence(f, model.Evidence{Kind: "execution-trace", Time: &t, Path: pathIfFull(tr.Path), Level: model.LevelRecent,
		Confidence: model.ConfidenceMedium, Detail: fmt.Sprintf("%s last ran %s (%s)", image, t.Format(time.RFC3339), source)})
}

func pathIfFull(p string) string {
	if strings.Contains(p, `\`) {
		return p
	}
	return ""
}

// ----------------------------------------------------------------- inventory

func (a *acc) inventory() {
	for _, te := range a.s.Inventory {
		baseID, _, _ := strings.Cut(te.ToolID, ":")
		tool := a.cat.Tool(baseID)
		if tool == nil {
			continue
		}
		if te.ToolID == tool.ID {
			f, _ := a.toolFinding(tool, te.UserSID)
			addEvidence(f, te.Evidence)
			continue
		}
		approved := a.cat.IsSanctioned(te.ToolID, nil) || a.cat.IsSanctioned(tool.ID, nil)
		name := te.ToolName
		if name == "" {
			name = tool.Name
		}
		f, _ := a.genericFinding(te.ToolID, name, tool.Category, te.UserSID, approved)
		f.Vendor = tool.Vendor
		addEvidence(f, te.Evidence)
	}
}

// --------------------------------------------------------------- environment

func (a *acc) environment() {
	for _, it := range a.s.EnvItems {
		where := fmt.Sprintf("(%s environment)", it.Scope)
		switch it.Kind {
		case "base-url":
			a.baseURL(it.Var, it.Host, it.UserSID, model.LevelInstalled, where, nil)
		case "api-key":
			id := "api-key:" + strings.ToLower(it.Var)
			f, _ := a.genericFinding(id, "LLM API key configured ("+it.Var+")", "credential", it.UserSID, false)
			addEvidence(f, model.Evidence{Kind: "env", Level: model.LevelInstalled, Confidence: model.ConfidenceLow,
				Detail: fmt.Sprintf("%s is set %s (value not recorded)", it.Var, where)})
		case "tool-env":
			if tool := a.cat.Tool(it.ToolID); tool != nil {
				f, _ := a.toolFinding(tool, it.UserSID)
				addEvidence(f, model.Evidence{Kind: "env", Level: model.LevelInstalled, Confidence: model.ConfidenceMedium,
					Detail: fmt.Sprintf("%s is set %s", it.Var, where)})
			}
		}
	}
}

// -------------------------------------------------------------------- finish

func (a *acc) finish() []model.Finding {
	// Merge machine-wide evidence into the user findings of the same tool.
	byTool := map[string][]string{}
	for _, key := range a.order {
		f := a.findings[key]
		byTool[f.ToolID] = append(byTool[f.ToolID], key)
	}
	for _, keys := range byTool {
		var machine *model.Finding
		var users []*model.Finding
		for _, k := range keys {
			if f := a.findings[k]; f.UserSID == "" {
				machine = f
			} else {
				users = append(users, f)
			}
		}
		if machine == nil || len(users) == 0 {
			continue
		}
		for _, u := range users {
			for _, e := range machine.Evidence {
				addEvidence(u, e)
			}
			if machine.Approved {
				u.Approved = true
			}
		}
		delete(a.findings, findingKey(machine.ToolID, ""))
	}

	names := map[string]string{}
	for _, p := range a.s.Profiles {
		names[strings.ToLower(p.SID)] = p.User
	}
	var out []model.Finding
	for _, key := range a.order {
		f, ok := a.findings[key]
		if !ok || len(f.Evidence) == 0 {
			continue
		}
		capConf := model.ConfidenceHigh
		baseID, _, _ := strings.Cut(f.ToolID, ":")
		if t := a.cat.Tool(baseID); t != nil {
			capConf = t.ConfidenceCap()
		}
		f.Level, f.Confidence = model.LevelUnknown, model.ConfidenceUnknown
		for _, e := range f.Evidence {
			if e.Level > f.Level {
				f.Level = e.Level
			}
			if e.Confidence > f.Confidence {
				f.Confidence = e.Confidence
			}
		}
		if f.Confidence > capConf {
			f.Confidence = capConf
		}
		sort.SliceStable(f.Evidence, func(i, j int) bool {
			if f.Evidence[i].Level != f.Evidence[j].Level {
				return f.Evidence[i].Level > f.Evidence[j].Level
			}
			return f.Evidence[i].Confidence > f.Evidence[j].Confidence
		})
		if len(f.Evidence) > maxEvidencePerFinding {
			f.Evidence = f.Evidence[:maxEvidencePerFinding]
		}
		if f.UserSID != "" {
			f.User = names[strings.ToLower(f.UserSID)]
			if f.User == "" {
				f.User = winapi.AccountNameFromString(f.UserSID)
			}
		}
		out = append(out, *f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Level != out[j].Level {
			return out[i].Level > out[j].Level
		}
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].ToolName < out[j].ToolName
	})
	return out
}

// ------------------------------------------------------------------- helpers

const maxCmdlineBytes = 300

// currentConfidence is the strongest confidence of the evidence gathered so
// far: evidence attached through a process tree inherits it, so that it never
// makes a circumstantial finding look stronger than it is.
func currentConfidence(f *model.Finding) model.Confidence {
	c := model.ConfidenceLow
	for _, e := range f.Evidence {
		if e.Confidence > c {
			c = e.Confidence
		}
	}
	return c
}

func cmdline(p *scan.Process) string { return redact.CommandLine(p.Cmdline, maxCmdlineBytes) }

func sortedPIDs(m map[uint32]*scan.Process) []uint32 {
	out := make([]uint32, 0, len(m))
	for pid := range m {
		out = append(out, pid)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func slug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' {
			b.WriteRune(r)
			dash = false
			continue
		}
		if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.TrimSuffix(b.String(), "-")
}

func toolNames(tools []*catalog.Tool) string {
	names := make([]string, len(tools))
	for i, t := range tools {
		names[i] = t.Name
	}
	return strings.Join(names, " or ")
}

func limit(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return append(append([]string(nil), in[:n]...), fmt.Sprintf("+%d more", len(in)-n))
}

func appendUnique(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}
