package correlate

import (
	"net"
	"strings"
	"testing"
	"time"

	"detectoragent/internal/catalog"
	"detectoragent/internal/model"
	"detectoragent/internal/scan"
	"detectoragent/rules"
)

const userSID = "S-1-5-21-1000-1000-1000-1001"

func proc(pid, ppid uint32, image, path, cmd string) *scan.Process {
	return &scan.Process{PID: pid, PPID: ppid, Image: image, Path: path, Cmdline: cmd, UserSID: userSID,
		SessionID: 1, Created: time.Unix(1_700_000_000+int64(pid), 0)}
}

func syntheticSnapshot() *scan.Snapshot {
	claudePath := `C:\Users\u\.vscode\extensions\anthropic.claude-code-2.1.319-win32-x64\resources\native-binary\claude.exe`
	procs := map[uint32]*scan.Process{
		100: proc(100, 1, "Code.exe", `C:\Users\u\AppData\Local\Programs\Microsoft VS Code\Code.exe`, "Code.exe"),
		200: proc(200, 100, "claude.exe", claudePath, claudePath+" --output-format stream-json"),
		201: proc(201, 200, "cmd.exe", `C:\Windows\System32\cmd.exe`, "cmd.exe /c dir"),
		300: proc(300, 1, "python.exe", `C:\Python312\python.exe`, `python.exe agent.py --api-key sk-proj-AAAAAAAAAAAAAAAAAAAAAAAA`),
		301: proc(301, 300, "powershell.exe", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "powershell -c ls"),
		400: proc(400, 300, "chrome.exe", `C:\Program Files\Google\Chrome\Application\chrome.exe`, `chrome.exe --remote-debugging-port=9222`),
		500: proc(500, 200, "node.exe", `C:\Program Files\nodejs\node.exe`, `node.exe npx-cli.js -y @modelcontextprotocol/server-filesystem C:\work`),
		600: proc(600, 1, "ollama.exe", `C:\Users\u\AppData\Local\Programs\Ollama\ollama.exe`, "ollama.exe serve"),
		700: proc(700, 1, "python.exe", `C:\Python312\python.exe`, "python.exe chat.py"),
		800: proc(800, 1, "msedge.exe", `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`, "msedge.exe"),
	}
	procs[300].Env = []scan.EnvVar{{Name: "OPENAI_BASE_URL", Value: "relay.example.net"}, {Name: "OPENAI_API_KEY"}}
	s := &scan.Snapshot{
		RunAsSID:  "S-1-5-18",
		IsSystem:  true,
		Profiles:  []scan.Profile{{SID: userSID, User: `PC\u`}},
		Processes: procs,
		Conns: []scan.Conn{
			{PID: 200, RemoteIP: net.ParseIP("160.79.104.10"), RemotePort: 443},
			{PID: 300, RemoteIP: net.ParseIP("104.18.32.47"), RemotePort: 443},
			{PID: 700, RemoteIP: net.ParseIP("127.0.0.1"), RemotePort: 11434},
			{PID: 800, RemoteIP: net.ParseIP("104.18.32.47"), RemotePort: 443},
		},
		Listeners: []scan.Listener{{PID: 600, Port: 11434, IP: net.ParseIP("127.0.0.1")}},
		IPToHosts: map[string][]string{"104.18.32.47": {"openrouter.ai"}},
		Traces: []scan.Trace{{Source: "bam", UserSID: userSID, Time: time.Now(),
			Path: `C:\Users\u\AppData\Local\OpenAI\Codex\bin\abc\codex.exe`}},
		Inventory: []scan.ToolEvidence{
			{ToolID: "claude-desktop", Evidence: model.Evidence{Kind: "service", Detail: "Windows service CoworkVMService",
				Level: model.LevelInstalled, Confidence: model.ConfidenceHigh}},
			{ToolID: "claude-desktop", UserSID: userSID, Evidence: model.Evidence{Kind: "residue", Detail: "tool data",
				Level: model.LevelResidue, Confidence: model.ConfidenceMedium}},
			{ToolID: "cursor", UserSID: userSID, Evidence: model.Evidence{Kind: "residue", Detail: "tool data",
				Level: model.LevelResidue, Confidence: model.ConfidenceMedium}},
		},
		EnvItems: []scan.EnvItem{
			{Kind: "api-key", Var: "ANTHROPIC_API_KEY", UserSID: userSID, Scope: "user"},
			{Kind: "base-url", Var: "ANTHROPIC_BASE_URL", Host: "openrouter.ai", Scope: "machine"},
		},
	}
	s.Children = map[uint32][]uint32{100: {200}, 200: {201, 500}, 300: {301, 400}}
	return s
}

func build(t *testing.T) (map[string]model.Finding, []model.Finding) {
	t.Helper()
	cat, err := catalog.Load(rules.Default)
	if err != nil {
		t.Fatal(err)
	}
	findings := Build(cat, syntheticSnapshot())
	byID := map[string]model.Finding{}
	for _, f := range findings {
		byID[f.ToolID] = f
	}
	return byID, findings
}

func hasEvidence(f model.Finding, kind, contains string) bool {
	for _, e := range f.Evidence {
		if e.Kind == kind && strings.Contains(e.Detail, contains) {
			return true
		}
	}
	return false
}

func TestKnownAgentProcess(t *testing.T) {
	byID, _ := build(t)
	f, ok := byID["claude-code"]
	if !ok {
		t.Fatal("claude-code not found")
	}
	if f.Level != model.LevelActive || f.Confidence != model.ConfidenceHigh || f.UserSID != userSID {
		t.Errorf("unexpected claude-code finding: %s/%s user %q", f.Level, f.Confidence, f.UserSID)
	}
	for _, want := range []struct{ kind, text string }{
		{"process", "claude.exe"},
		{"network", "Anthropic API"},
		{"behavior", "cmd.exe"},
		{"mcp-server", "@modelcontextprotocol"},
	} {
		if !hasEvidence(f, want.kind, want.text) {
			t.Errorf("claude-code lacks %s evidence %q: %+v", want.kind, want.text, f.Evidence)
		}
	}
}

func TestUnknownAgentIsDetectedGenerically(t *testing.T) {
	byID, _ := build(t)
	api, ok := byID["llm-api:openrouter:python.exe"]
	if !ok {
		t.Fatalf("generic OpenRouter client not found; got %v", keys(byID))
	}
	if api.Category != "aggregator" || api.Confidence != model.ConfidenceMedium {
		t.Errorf("llm-api finding: category %q confidence %s (API key in process env should raise it)", api.Category, api.Confidence)
	}
	agent, ok := byID["probable-agent:python.exe"]
	if !ok {
		t.Fatal("probable agent not found")
	}
	if agent.Confidence != model.ConfidenceMedium || agent.Level != model.LevelActive {
		t.Errorf("probable agent: %s/%s", agent.Level, agent.Confidence)
	}
	if !hasEvidence(agent, "behavior", "powershell.exe") || !hasEvidence(agent, "browser-automation", "remote-debugging-port") {
		t.Errorf("probable agent evidence incomplete: %+v", agent.Evidence)
	}
	if strings.Contains(agent.Evidence[0].Cmdline, "AAAAAAAAAAAA") {
		t.Errorf("secret leaked in command line: %s", agent.Evidence[0].Cmdline)
	}
	relay, ok := byID["relay-candidate:relay.example.net"]
	if !ok || relay.Level != model.LevelActive || relay.Category != "relay" {
		t.Errorf("relay candidate missing or wrong: %+v", relay)
	}
}

func TestBrowsersAreNotAttributed(t *testing.T) {
	byID, _ := build(t)
	for id := range byID {
		if strings.HasSuffix(id, ":msedge.exe") {
			t.Errorf("browser traffic must be left to the web proxy, got %s", id)
		}
	}
}

func TestLocalLLM(t *testing.T) {
	byID, _ := build(t)
	if f := byID["ollama"]; !hasEvidence(f, "listener", "11434") {
		t.Errorf("ollama listener evidence missing: %+v", f.Evidence)
	}
	if f, ok := byID["local-llm-client:python.exe"]; !ok || f.Confidence != model.ConfidenceLow {
		t.Errorf("local LLM client should be reported with low confidence: %+v", f)
	}
}

func TestTracesInventoryAndEnvironment(t *testing.T) {
	byID, findings := build(t)
	if f := byID["openai-codex"]; f.Level != model.LevelRecent || !hasEvidence(f, "execution-trace", "codex.exe") {
		t.Errorf("codex BAM trace not attributed: %+v", f)
	}
	cd := byID["claude-desktop"]
	if cd.UserSID != userSID || cd.Level != model.LevelInstalled || !hasEvidence(cd, "service", "CoworkVMService") {
		t.Errorf("machine-wide evidence not merged into the user finding: %+v", cd)
	}
	for _, f := range findings {
		if f.ToolID == "claude-desktop" && f.UserSID == "" {
			t.Error("machine-wide claude-desktop finding should have been merged")
		}
	}
	if f := byID["cursor"]; f.Level != model.LevelResidue || f.Actionable() {
		t.Errorf("residue must not be actionable: %+v", f)
	}
	if f := byID["api-key:anthropic_api_key"]; f.Confidence != model.ConfidenceLow {
		t.Errorf("API key presence must stay low confidence: %+v", f)
	}
	if f, ok := byID["llm-config:openrouter"]; !ok || f.Level != model.LevelInstalled {
		t.Errorf("base URL to a catalog aggregator not reported: %+v", f)
	}
}

func TestSanctionedEndpoint(t *testing.T) {
	data := strings.Replace(string(rules.Default), "sanctioned: []", "sanctioned: [openrouter.ai, claude-code]", 1)
	cat, err := catalog.Load([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]model.Finding{}
	for _, f := range Build(cat, syntheticSnapshot()) {
		byID[f.ToolID] = f
	}
	if !byID["claude-code"].Approved || !byID["llm-api:openrouter:python.exe"].Approved {
		t.Error("sanctioned tool or endpoint not approved")
	}
	if byID["relay-candidate:relay.example.net"].Approved {
		t.Error("unknown relay must not be approved")
	}
}

func TestBumpProcessCount(t *testing.T) {
	d := "running a.exe (pid 1, matched by path)"
	d = bumpProcessCount(d)
	if !strings.HasSuffix(d, ", 2 processes)") {
		t.Fatalf("got %q", d)
	}
	if d = bumpProcessCount(d); !strings.HasSuffix(d, ", 3 processes)") {
		t.Fatalf("got %q", d)
	}
}

func keys(m map[string]model.Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
