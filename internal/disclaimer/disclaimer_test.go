package disclaimer

import (
	"strings"
	"testing"

	"detectoragent/internal/catalog"
	"detectoragent/internal/model"
	"detectoragent/rules"
)

const sid = "S-1-5-21-1-2-3-1001"

func finding(id string, level model.Level, conf model.Confidence, user string) model.Finding {
	return model.Finding{ToolID: id, ToolName: id, Level: level, Confidence: conf, UserSID: user}
}

func TestPending(t *testing.T) {
	cat, err := catalog.Load(rules.Default)
	if err != nil {
		t.Fatal(err)
	}
	findings := []model.Finding{
		finding("claude-code", model.LevelActive, model.ConfidenceHigh, sid),
		finding("cursor", model.LevelResidue, model.ConfidenceMedium, sid),                   // residue: never shown
		finding("api-key:openai_api_key", model.LevelInstalled, model.ConfidenceLow, sid),    // low: never shown
		finding("claude-desktop", model.LevelInstalled, model.ConfidenceHigh, ""),            // machine-wide: shown
		finding("openai-codex", model.LevelRecent, model.ConfidenceHigh, "S-1-5-21-9-9-9-9"), // other user
		finding("probable-agent:python.exe", model.LevelActive, model.ConfidenceMedium, sid),
		finding("relay-candidate:relay.example.net", model.LevelActive, model.ConfidenceMedium, sid),
		finding("claude-code", model.LevelInstalled, model.ConfidenceHigh, sid), // duplicate id: listed once
	}
	want := "claude-code,claude-desktop,probable-agent:python.exe,relay-candidate:relay.example.net"

	// The same findings at the next scan give the same list: an acceptance
	// never silences the disclaimer while the agents are still detected.
	for scan := 1; scan <= 3; scan++ {
		got := ToolIDs(Pending(cat, findings, sid))
		if strings.Join(sortCopy(got), ",") != want {
			t.Errorf("scan %d: pending = %v, want %s", scan, got, want)
		}
	}

	// Nothing detected any more: nothing to show.
	if got := Pending(cat, findings[1:2], sid); len(got) != 0 {
		t.Errorf("only a residue left, pending = %v", got)
	}
}

func TestPayloadRoundTrip(t *testing.T) {
	p := Payload{Version: 3, Rules: `C:\rules.yaml`, Tools: []Tool{{ID: "claude-code", Name: "Claude Code", Approved: false}}}
	enc, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(enc, ` "&|<>^`) {
		t.Errorf("payload is not command-line safe: %s", enc)
	}
	back, err := DecodePayload(enc)
	if err != nil || back.Version != 3 || back.Tools[0].ID != "claude-code" || back.Rules != p.Rules {
		t.Errorf("round trip failed: %+v %v", back, err)
	}
	if _, err := DecodePayload("not base64!"); err == nil {
		t.Error("garbage payload must fail")
	}
}

func TestBuildContent(t *testing.T) {
	cat, err := catalog.Load(rules.Default)
	if err != nil {
		t.Fatal(err)
	}
	cat.Disclaimer.Company = "Acme"
	c := BuildContent(&cat.Disclaimer, []Tool{
		{ID: "a", Name: "Evil <a href=x>tool</a>"},
		{ID: "b", Name: "GitHub Copilot", Approved: true},
	})
	if strings.Contains(c.Text, "<a") {
		t.Errorf("tool names must not inject markup: %s", c.Text)
	}
	if !strings.Contains(c.Text, "GitHub Copilot: approved") || !strings.Contains(c.Text, ": not approved") {
		t.Errorf("statuses missing: %s", c.Text)
	}
	if !strings.Contains(c.Text, "AI policy of Acme") || strings.Contains(c.Text, "{company}") {
		t.Errorf("{company} not replaced: %s", c.Text)
	}
	if c.PolicyTarget != "https://intranet.example.com/ai-policy" || c.Email != "security@example.com" {
		t.Errorf("policy or e-mail missing: %+v", c)
	}
	markup, plain := c.FooterMarkup()
	if markup != `<a id="policy">Read the AI policy</a>     Questions? Contact <a id="email">security@example.com</a>.` {
		t.Errorf("footer markup = %s", markup)
	}
	if strings.Contains(plain, "<a") || !strings.Contains(plain, "security@example.com") {
		t.Errorf("footer plain text = %s", plain)
	}
	if strings.Contains(markup, "https://") || strings.Contains(markup, "mailto:") {
		t.Error("links must carry ids, never addresses")
	}
}

func TestFooterWithoutContact(t *testing.T) {
	c := Content{PolicyTarget: `C:\Policy.pdf`, PolicyLabel: "Policy"}
	if markup, _ := c.FooterMarkup(); markup != `<a id="policy">Policy</a>` {
		t.Errorf("markup = %s", markup)
	}
	if markup, plain := (Content{}).FooterMarkup(); markup != "" || plain != "" {
		t.Error("no policy and no e-mail: no footer")
	}
}

func sortCopy(in []string) []string {
	out := append([]string(nil), in...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestAnyUnapproved(t *testing.T) {
	if AnyUnapproved(nil) {
		t.Error("no tool: nothing to show")
	}
	if AnyUnapproved([]Tool{{ID: "github-copilot", Approved: true}}) {
		t.Error("approved tools only: the notice must not open")
	}
	if !AnyUnapproved([]Tool{{ID: "github-copilot", Approved: true}, {ID: "claude-code"}}) {
		t.Error("one unapproved tool: the notice must open")
	}
}
