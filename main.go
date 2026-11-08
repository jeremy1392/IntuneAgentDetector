// Command detectoragent scans a Windows laptop for AI agents (known tools and
// unknown agents talking to LLM endpoints), reports them as JSON and to the
// Windows Event Log, and asks the user to accept the AI usage disclaimer at
// every scan for as long as agents are detected. It never blocks or modifies
// anything: it only writes its report and its Event Log entries.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"detectoragent/internal/catalog"
	"detectoragent/internal/correlate"
	"detectoragent/internal/disclaimer"
	"detectoragent/internal/model"
	"detectoragent/internal/report"
	"detectoragent/internal/scan"
	"detectoragent/internal/winapi"
	"detectoragent/rules"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "0.1.0-dev"

const (
	productName  = "detectorAgent"
	exitClean    = 0
	exitDetected = 1
	exitError    = 2
	exitDeclined = 3
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	cmd := "scan"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "scan":
		return cmdScan(args)
	case "disclaimer":
		return cmdDisclaimer(args)
	case "check-branding":
		return cmdCheckBranding(args)
	case "version":
		fmt.Println(productName, version)
		return exitClean
	case "help", "-h", "--help", "/?":
		usage(os.Stdout)
		return exitClean
	}
	fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
	usage(os.Stderr)
	return exitError
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `%s %s - detects AI agents on this computer (detection only, nothing is blocked)

Usage:
  detectoragent scan [options]         scan, report, and show the disclaimer if needed
  detectoragent disclaimer --preview   show the disclaimer with sample tools (nothing recorded)
  detectoragent disclaimer --selftest  show the disclaimer and accept it automatically (nothing recorded)
  detectoragent check-branding [FILE]  validate a branding file without showing anything
  detectoragent version

Scan options:
  --format json|text   report format (default json)
  --out FILE           write the report to FILE instead of stdout
  --rules FILE         use FILE instead of the embedded catalog
  --branding FILE      disclaimer branding (default: branding\branding.yaml next to the executable)
  --days N             execution traces newer than N days count as recent use (default 30)
  --no-disclaimer      never show the disclaimer
  --no-eventlog        do not write to the Windows Event Log
  --timeout DURATION   maximum scan duration (default 60s)

Disclaimer options:
  --branding FILE      check a branding file before deploying it (with --preview)

Exit codes: 0 nothing to report, 1 unapproved AI tool detected,
            2 error or incomplete scan with nothing detected.
`, productName, version)
}

func loadCatalog(path string) (*catalog.Catalog, error) {
	if path == "" {
		return catalog.Load(rules.Default)
	}
	return catalog.LoadFile(path)
}

// brandingPath returns the branding file to use: the given path, or
// branding\branding.yaml next to the executable when it exists.
func brandingPath(given string) string {
	if given != "" {
		if abs, err := filepath.Abs(given); err == nil {
			return abs
		}
		return given
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	p := filepath.Join(filepath.Dir(exe), "branding", "branding.yaml")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// applyBranding merges a branding file into the catalog's disclaimer. On
// error the catalog keeps its default texts.
func applyBranding(cat *catalog.Catalog, path string) error {
	if path == "" {
		return nil
	}
	b, err := catalog.LoadBrandingFile(path)
	if err != nil {
		return err
	}
	return cat.Disclaimer.ApplyBranding(b, filepath.Dir(path))
}

// ---------------------------------------------------------------------- scan

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	format := fs.String("format", "json", "report format: json or text")
	out := fs.String("out", "", "write the report to this file instead of stdout")
	rulesPath := fs.String("rules", "", "catalog file to use instead of the embedded one")
	brandingFlag := fs.String("branding", "", "disclaimer branding file")
	days := fs.Int("days", 30, "execution traces newer than this many days count as recent use")
	noDisclaimer := fs.Bool("no-disclaimer", false, "never show the disclaimer")
	noEventLog := fs.Bool("no-eventlog", false, "do not write to the Windows Event Log")
	timeout := fs.Duration("timeout", 60*time.Second, "maximum scan duration")
	fs.Usage = func() { usage(os.Stderr) }
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if *format != "json" && *format != "text" {
		fmt.Fprintln(os.Stderr, "--format must be json or text")
		return exitError
	}
	if *rulesPath != "" {
		if abs, err := filepath.Abs(*rulesPath); err == nil {
			*rulesPath = abs
		}
	}
	cat, err := loadCatalog(*rulesPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "catalog:", err)
		return exitError
	}
	branding := brandingPath(*brandingFlag)
	brandingErr := applyBranding(cat, branding)
	if brandingErr != nil {
		fmt.Fprintln(os.Stderr, "branding (default texts used):", brandingErr)
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	snap := scan.Run(ctx, cat, scan.Options{RecentDays: *days, Now: start})
	findings := correlate.Build(cat, snap)

	host, _ := os.Hostname()
	rep := &model.Report{
		Product:        productName,
		Version:        version,
		CatalogVersion: cat.Version,
		Host:           host,
		RunAs:          snap.RunAs,
		Elevated:       snap.Elevated || snap.IsSystem,
		StartedAt:      start,
		RecentDays:     *days,
		Coverage:       snap.Coverage,
		Findings:       findings,
		Errors:         snap.Errors,
	}
	if rep.Findings == nil {
		rep.Findings = []model.Finding{}
	}
	rep.Summary = model.Summarize(findings)
	rep.DurationMs = time.Since(start).Milliseconds()
	report.Sanitize(rep)

	if err := writeReport(rep, *format, *out); err != nil {
		fmt.Fprintln(os.Stderr, "report:", err)
		return exitError
	}

	var evlog *report.EventLog
	if !*noEventLog {
		evlog, err = report.OpenEventLog()
		if err != nil {
			fmt.Fprintln(os.Stderr, "event log:", err)
		} else {
			defer evlog.Close()
			writeEvents(evlog, rep)
			if brandingErr != nil {
				_ = evlog.Error(rep.Host, "branding file "+branding+" ignored, default texts used: "+brandingErr.Error())
			}
		}
	}

	if !*noDisclaimer {
		showDisclaimers(cat, rep, snap, evlog, *rulesPath, branding)
	}

	switch {
	case rep.Summary.Actionable > 0:
		return exitDetected
	case len(rep.Errors) > 0:
		return exitError // incomplete scan: "nothing found" would be misleading
	}
	return exitClean
}

func writeReport(rep *model.Report, format, out string) error {
	w := io.Writer(os.Stdout)
	if out != "" {
		f, err := os.Create(out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	if format == "text" {
		return report.WriteText(w, rep)
	}
	return report.WriteJSON(w, rep)
}

// writeEvents writes the summary and one event per meaningful finding.
// Residues and low-confidence findings stay in the summary only.
func writeEvents(evlog *report.EventLog, rep *model.Report) {
	check := func(err error) {
		if err != nil {
			fmt.Fprintln(os.Stderr, "event log:", err)
		}
	}
	check(evlog.Summary(rep))
	for _, f := range rep.Findings {
		if f.Level >= model.LevelInstalled && f.Confidence >= model.ConfidenceMedium {
			check(evlog.Finding(rep.Host, f))
		}
	}
	for _, e := range rep.Errors {
		check(evlog.Error(rep.Host, e))
	}
}

// showDisclaimers opens the disclaimer for every user who has pending tools.
// As LocalSystem it starts a disclaimer process in each active session; run
// by an interactive user it shows the dialog directly.
func showDisclaimers(cat *catalog.Catalog, rep *model.Report, snap *scan.Snapshot, evlog *report.EventLog,
	rulesPath, brandingFile string) {
	logErr := func(format string, a ...any) {
		msg := fmt.Sprintf(format, a...)
		fmt.Fprintln(os.Stderr, "disclaimer:", msg)
		if evlog != nil {
			_ = evlog.Error(rep.Host, "disclaimer: "+msg)
		}
	}
	exe, err := os.Executable()
	if err != nil {
		logErr("cannot locate the executable: %v", err)
		return
	}

	if snap.IsSystem {
		sessions, err := disclaimer.ActiveSessions()
		if err != nil {
			logErr("cannot list sessions: %v", err)
			return
		}
		for i := range sessions {
			ses := &sessions[i]
			func() {
				defer ses.Close()
				tools := disclaimer.Pending(cat, rep.Findings, ses.SID)
				if len(tools) == 0 || disclaimer.RunningInSession(snap.Processes, exe, ses.ID) {
					return
				}
				enc, err := disclaimer.Payload{Version: cat.Disclaimer.Version, Tools: tools, Rules: rulesPath,
					Branding: brandingFile}.Encode()
				if err != nil {
					logErr("encode payload: %v", err)
					return
				}
				if err := ses.LaunchInSession(exe, []string{"disclaimer", "--payload", enc}); err != nil {
					logErr("cannot start the disclaimer in session %d: %v", ses.ID, err)
					return
				}
				if evlog != nil {
					_ = evlog.DisclaimerShown(rep.Host, ses.SID, ses.User, ses.ID, cat.Disclaimer.Version, disclaimer.ToolIDs(tools))
				}
			}()
		}
		return
	}

	if snap.SessionID == 0 {
		return // service account without an interactive desktop
	}
	tools := disclaimer.Pending(cat, rep.Findings, snap.RunAsSID)
	if len(tools) == 0 {
		return
	}
	if evlog != nil {
		_ = evlog.DisclaimerShown(rep.Host, snap.RunAsSID, snap.RunAs, snap.SessionID, cat.Disclaimer.Version, disclaimer.ToolIDs(tools))
	}
	if code := presentAndLog(cat, tools, cat.Disclaimer.Version, evlog, rep.Host, presentOptions{}); code != exitClean {
		logErr("the disclaimer was not accepted (exit code %d)", code)
	}
}

// ---------------------------------------------------------------- disclaimer

func cmdDisclaimer(args []string) int {
	fs := flag.NewFlagSet("disclaimer", flag.ContinueOnError)
	payloadArg := fs.String("payload", "", "encoded list of tools (set by the scan)")
	rulesPath := fs.String("rules", "", "catalog file holding the disclaimer text")
	brandingFlag := fs.String("branding", "", "disclaimer branding file")
	preview := fs.Bool("preview", false, "show the dialog with sample tools; nothing is recorded")
	selftest := fs.Bool("selftest", false, "show the dialog and accept it automatically; nothing is recorded")
	noEventLog := fs.Bool("no-eventlog", false, "do not write to the Windows Event Log")
	fs.Usage = func() { usage(os.Stderr) }
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	dryRun := *preview || *selftest

	var p disclaimer.Payload
	if dryRun {
		p = samplePayload()
	} else {
		var err error
		if p, err = disclaimer.DecodePayload(*payloadArg); err != nil {
			fmt.Fprintln(os.Stderr, "payload:", err)
			return exitError
		}
	}
	rulesFile := *rulesPath
	if rulesFile == "" {
		rulesFile = p.Rules
	}
	cat, err := loadCatalog(rulesFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "catalog:", err)
		return exitError
	}

	givenBranding := *brandingFlag
	if givenBranding == "" {
		givenBranding = p.Branding
	}
	branding := brandingPath(givenBranding)
	brandingErr := applyBranding(cat, branding)
	if dryRun {
		// An administrator checks a branding file: report problems and stop.
		if brandingErr != nil {
			fmt.Fprintf(os.Stderr, "branding file %s is invalid:\n%v\n", branding, brandingErr)
			return exitError
		}
		if branding == "" {
			fmt.Println("branding: none found, built-in default texts")
		} else {
			fmt.Println("branding:", branding)
		}
		p.Version = cat.Disclaimer.Version
	}

	if !dryRun {
		name, _ := windows.UTF16PtrFromString(`Local\DetectorAgentDisclaimer`)
		h, err := windows.CreateMutex(nil, false, name)
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return exitClean // a disclaimer is already open in this session
		}
		if err == nil {
			defer windows.CloseHandle(h)
		}
	}

	var evlog *report.EventLog
	if !*noEventLog && !dryRun {
		if evlog, err = report.OpenEventLog(); err == nil {
			defer evlog.Close()
		}
	}
	host, _ := os.Hostname()
	if brandingErr != nil && evlog != nil {
		_ = evlog.Error(host, "branding file "+branding+" ignored, default texts used: "+brandingErr.Error())
	}
	opt := presentOptions{dryRun: dryRun, allowClose: *preview}
	if *selftest {
		opt.autoAccept = 2 * time.Second
	}
	return presentAndLog(cat, p.Tools, p.Version, evlog, host, opt)
}

// cmdCheckBranding validates a branding file (default: the one next to the
// executable) and prints the resulting settings. Used by install.ps1.
func cmdCheckBranding(args []string) int {
	given := ""
	if len(args) > 0 {
		given = args[0]
	}
	path := brandingPath(given)
	cat, err := loadCatalog("")
	if err != nil {
		fmt.Fprintln(os.Stderr, "catalog:", err)
		return exitError
	}
	if path == "" {
		fmt.Println("no branding file found: the built-in default texts are used")
		fmt.Printf("  version: %d\n", cat.Disclaimer.Version)
		return exitClean
	}
	if err := applyBranding(cat, path); err != nil {
		fmt.Fprintf(os.Stderr, "branding file %s is invalid:\n%v\n", path, err)
		return exitError
	}
	d := &cat.Disclaimer
	orNone := func(s string) string {
		if s == "" {
			return "(none)"
		}
		return s
	}
	fmt.Printf("branding file %s is valid\n", path)
	fmt.Printf("  version: %d\n  company: %s\n  logo:    %s\n  policy:  %s\n  email:   %s\n  title:   %s\n",
		d.Version, orNone(d.Company), orNone(d.Logo), orNone(d.Policy), orNone(d.Email), d.Expand(d.Title))
	return exitClean
}

type presentOptions struct {
	dryRun     bool          // preview or self-test: nothing is logged
	autoAccept time.Duration // self-test only
	allowClose bool          // preview: the administrator may close the window
}

// presentAndLog shows the window and, unless it is a dry run, logs the
// acceptance (event 410). The acceptance is not stored on the machine: the
// next scan shows the window again if agents are still detected.
func presentAndLog(cat *catalog.Catalog, tools []disclaimer.Tool, version int, evlog *report.EventLog,
	host string, opt presentOptions) int {
	content := disclaimer.BuildContent(&cat.Disclaimer, tools)
	res, err := disclaimer.Show(content, disclaimer.ShowOptions{AutoAccept: opt.autoAccept, AllowClose: opt.allowClose})
	for _, w := range res.Warnings {
		fmt.Fprintln(os.Stderr, "disclaimer:", w)
		if evlog != nil {
			_ = evlog.Error(host, "disclaimer: "+w)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "disclaimer:", err)
		if evlog != nil {
			_ = evlog.Error(host, "disclaimer dialog: "+err.Error())
		}
		return exitError
	}
	if !res.Accepted {
		if opt.dryRun {
			fmt.Println("closed without accepting (dry run: nothing recorded)")
		}
		return exitDeclined
	}
	if opt.dryRun {
		mode := "disclaimer window"
		if res.Fallback {
			mode = "fallback message box"
		}
		fmt.Printf("accepted via %s (dry run: nothing recorded)\n", mode)
		return exitClean
	}
	if evlog != nil {
		_ = evlog.DisclaimerAccepted(host, winapi.Current().Account, version, disclaimer.ToolIDs(tools), time.Now())
	}
	return exitClean
}

func samplePayload() disclaimer.Payload {
	return disclaimer.Payload{Tools: []disclaimer.Tool{
		{ID: "claude-code", Name: "Claude Code", Category: "cli-agent"},
		{ID: "probable-agent:python.exe", Name: "Probable custom AI agent (python.exe)", Category: "custom-agent"},
		{ID: "github-copilot", Name: "GitHub Copilot (IDE)", Category: "ide-assistant", Approved: true},
	}}
}
