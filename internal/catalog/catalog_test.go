package catalog

import (
	"net"
	"testing"

	"detectoragent/internal/model"
	"detectoragent/rules"
)

func loadDefault(t *testing.T) *Catalog {
	t.Helper()
	c, err := Load(rules.Default)
	if err != nil {
		t.Fatalf("default catalog does not load: %v", err)
	}
	return c
}

func TestDefaultCatalogLoads(t *testing.T) {
	c := loadDefault(t)
	if len(c.Tools) < 20 {
		t.Errorf("expected at least 20 tools, got %d", len(c.Tools))
	}
	if len(c.Endpoints) < 100 {
		t.Errorf("expected at least 100 endpoints, got %d", len(c.Endpoints))
	}
	if c.Disclaimer.Button != "I accept" {
		t.Errorf("unexpected button label %q", c.Disclaimer.Button)
	}
}

func TestMatchHost(t *testing.T) {
	c := loadDefault(t)
	cases := []struct {
		host     string
		provider string
	}{
		{"api.openai.com", "OpenAI API"},
		{"API.OpenAI.com.", "OpenAI API"},
		{"openrouter.ai", "OpenRouter"},
		{"router.requesty.ai:443", "Requesty"},
		{"proxy.individual.githubcopilot.com", "GitHub Copilot (personal plan)"},
		{"api.business.githubcopilot.com", "GitHub Copilot Business"},
		{"api.githubcopilot.com", "GitHub Copilot"},
		{"myres.openai.azure.com", "Azure OpenAI"},
		{"us-central1-aiplatform.googleapis.com", "Google Vertex AI (regional)"},
		{"bedrock-runtime.eu-west-3.amazonaws.com", "AWS Bedrock"},
		{"api2.cursor.sh", "Cursor"},
		{"mcp.example.org", "Remote MCP server"},
	}
	for _, tc := range cases {
		e := c.MatchHost(tc.host)
		if e == nil {
			t.Errorf("%s: no match", tc.host)
			continue
		}
		if e.Provider != tc.provider {
			t.Errorf("%s: got provider %q, want %q", tc.host, e.Provider, tc.provider)
		}
	}
	for _, host := range []string{"example.com", "openai.com", "s3.amazonaws.com", "notcursor.sh"} {
		if e := c.MatchHost(host); e != nil {
			t.Errorf("%s: unexpected match %q", host, e.Provider)
		}
	}
}

func TestMatchIP(t *testing.T) {
	c := loadDefault(t)
	if e := c.MatchIP(net.ParseIP("160.79.104.10")); e == nil || e.Category != "model-provider" {
		t.Errorf("Anthropic range not matched: %+v", e)
	}
	if e := c.MatchIP(net.ParseIP("104.18.32.47")); e != nil {
		t.Errorf("Cloudflare address must not match a dedicated range: %+v", e)
	}
}

func TestToolMatchers(t *testing.T) {
	c := loadDefault(t)
	cc := c.Tool("claude-code")
	if cc == nil {
		t.Fatal("claude-code missing")
	}
	if !cc.MatchPath(`C:\Users\a\.vscode\extensions\anthropic.claude-code-2.1.319-win32-x64\resources\native-binary\claude.exe`) {
		t.Error("claude-code extension binary path not matched")
	}
	if !cc.MatchCmdline(`"C:\Program Files\nodejs\node.exe" C:\Users\a\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\cli.js`) {
		t.Error("claude-code npm command line not matched")
	}
	if cc.MatchCmdline(`"C:\Program Files\nodejs\node.exe" server.js`) {
		t.Error("plain node command line must not match")
	}
	if !cc.MatchSigner("Anthropic, PBC") || cc.MatchSigner("OpenAI OpCo, LLC") {
		t.Error("signer matching is wrong")
	}
	cx := c.Tool("openai-codex")
	if !cx.MatchPackage("OpenAI.Codex_2p2nqsd0c76g0") || !cx.MatchPackage("OpenAI.CodexPrimaryRuntime.v26-1104-2876-0_3k8sg7r9htsxt") {
		t.Error("codex package families not matched")
	}
	if !cx.MatchService("CodexSandboxService.OpenAI.Codex") {
		t.Error("codex service not matched")
	}
	if !c.Tool("cline").MatchVSCodeExtension("SaoudRizwan.Claude-Dev") {
		t.Error("extension ids must be case-insensitive")
	}
	if !c.Tool("aider").MatchPIP("Aider_Chat") {
		t.Error("pip names must be PEP 503 normalized")
	}
	if c.Tool("agent-frameworks").ConfidenceCap() != model.ConfidenceLow {
		t.Error("framework confidence cap not applied")
	}
}

func TestGeneric(t *testing.T) {
	c := loadDefault(t)
	g := &c.Generic
	if g.AutomationFlag(`chrome.exe --remote-debugging-port=9222 --user-data-dir=x`) == "" {
		t.Error("automation flag not detected")
	}
	if g.MCPMatch(`npx -y @modelcontextprotocol/server-filesystem C:\work`) == "" {
		t.Error("MCP command line not detected")
	}
	if !g.InferenceModule("ggml-cuda.dll") || g.InferenceModule("kernel32.dll") {
		t.Error("inference module matching is wrong")
	}
	if !g.TokenizerModule("_tiktoken.cp312-win_amd64.pyd") {
		t.Error("tokenizer module not detected")
	}
	if !g.IsBaseURLVar("OPENAI_BASE_URL") || !g.IsBaseURLVar("ANTHROPIC_BASE_URL") || g.IsBaseURLVar("NEXT_PUBLIC_API_BASE_URL") {
		t.Error("base URL variable matching is wrong")
	}
	if !g.IsAPIKeyVar("OPENROUTER_API_KEY") || g.IsAPIKeyVar("GITHUB_TOKEN") {
		t.Error("API key variable matching is wrong")
	}
}

func TestDisclaimerTriggers(t *testing.T) {
	c := loadDefault(t)
	d := &c.Disclaimer
	if !d.Triggers(model.LevelActive, model.ConfidenceMedium) {
		t.Error("active/medium must trigger")
	}
	if d.Triggers(model.LevelResidue, model.ConfidenceHigh) {
		t.Error("residue must never trigger")
	}
	if d.Triggers(model.LevelInstalled, model.ConfidenceLow) {
		t.Error("low confidence must not trigger")
	}
}

func TestSanctioned(t *testing.T) {
	c, err := Load([]byte(`
sanctioned: [github-copilot, .business.githubcopilot.com, corp.openai.azure.com]
endpoints:
  - { suffix: .business.githubcopilot.com, provider: Copilot Business, category: dev-tool }
  - { suffix: .openai.azure.com, provider: Azure OpenAI, category: model-provider }
`))
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsSanctioned("github-copilot", nil) {
		t.Error("tool id not sanctioned")
	}
	if !c.IsSanctioned("", c.MatchHost("api.business.githubcopilot.com")) {
		t.Error("suffix endpoint not sanctioned")
	}
	if !c.IsSanctionedHost("corp.openai.azure.com") || c.IsSanctionedHost("other.openai.azure.com") {
		t.Error("exact host sanctioning is wrong")
	}
}

func TestInvalidCatalog(t *testing.T) {
	if _, err := Load([]byte("tools:\n  - id: x\n    process:\n      paths: ['(']\n")); err == nil {
		t.Error("invalid regex must fail")
	}
	if _, err := Load([]byte("endpoints:\n  - { host: a.com, suffix: .b.com, provider: x }\n")); err == nil {
		t.Error("endpoint with two keys must fail")
	}
}
