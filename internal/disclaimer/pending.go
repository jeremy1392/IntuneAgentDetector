// Package disclaimer shows the AI usage disclaimer to users in whose session
// an AI agent was detected. The dialog comes back at every scan for as long
// as agents are detected; each acceptance is logged (event 410) but never
// silences the next scan.
package disclaimer

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"detectoragent/internal/catalog"
	"detectoragent/internal/model"
)

// MaxToolsPerDialog bounds the list shown to the user and the payload size.
const MaxToolsPerDialog = 40

// Tool is one entry of the disclaimer list.
type Tool struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category,omitempty"`
	Approved bool   `json:"approved"`
}

// Payload is passed, base64-encoded, to the disclaimer process.
type Payload struct {
	Version  int    `json:"v"`
	Tools    []Tool `json:"tools"`
	Rules    string `json:"rules,omitempty"`
	Branding string `json:"branding,omitempty"`
}

// Encode serializes the payload for the command line.
func (p Payload) Encode() (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DecodePayload parses a payload produced by Encode.
func DecodePayload(s string) (Payload, error) {
	var p Payload
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, err
	}
	if len(p.Tools) == 0 {
		return p, errors.New("payload lists no tool")
	}
	if len(p.Tools) > MaxToolsPerDialog {
		p.Tools = p.Tools[:MaxToolsPerDialog]
	}
	return p, nil
}

// AnyUnapproved reports whether at least one tool is not approved. The notice
// is opened only in that case; approved tools are then listed alongside, so
// that a user of approved tools only is never interrupted.
func AnyUnapproved(tools []Tool) bool {
	for _, t := range tools {
		if !t.Approved {
			return true
		}
	}
	return false
}

// Pending returns the tools that must be shown to the user with this SID:
// findings of that user or machine-wide that match the trigger rules. Past
// acceptances are deliberately ignored: as long as an agent is still
// detected, the disclaimer is shown again at every scan.
func Pending(cat *catalog.Catalog, findings []model.Finding, sid string) []Tool {
	seen := map[string]bool{}
	var out []Tool
	for _, f := range findings {
		if f.UserSID != "" && !strings.EqualFold(f.UserSID, sid) {
			continue
		}
		if !cat.Disclaimer.Triggers(f.Level, f.Confidence) || seen[f.ToolID] {
			continue
		}
		seen[f.ToolID] = true
		out = append(out, Tool{ID: f.ToolID, Name: f.ToolName, Category: f.Category, Approved: f.Approved})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Approved != out[j].Approved {
			return !out[i].Approved // not approved first
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > MaxToolsPerDialog {
		out = out[:MaxToolsPerDialog]
	}
	return out
}

// Content is everything the disclaimer window displays.
type Content struct {
	Title    string
	Heading  string
	Text     string // detected tools followed by the disclaimer text
	Checkbox string
	Button   string
	LogoPath string

	PolicyTarget string // https address or document path; empty for no link
	PolicyLabel  string

	Email         string // empty for no contact line
	MailtoURL     string
	ContactBefore string // contact sentence before the e-mail link
	ContactAfter  string // and after it
}

// BuildContent assembles the window content from the disclaimer settings
// (catalog defaults merged with the branding file) and the tool list.
func BuildContent(d *catalog.Disclaimer, tools []Tool) Content {
	br := &d.Branding
	var b strings.Builder
	b.WriteString("Detected tools:\n")
	for _, t := range tools {
		status := "not approved"
		if t.Approved {
			status = "approved"
		}
		b.WriteString("• " + clean(t.Name) + ": " + status + "\n")
	}
	if text := strings.TrimSpace(br.Expand(br.Text)); text != "" {
		b.WriteString("\n" + text)
	}

	c := Content{
		Title:        br.Expand(br.Title),
		Heading:      br.Expand(br.Heading),
		Text:         b.String(),
		Checkbox:     br.Expand(br.Checkbox),
		Button:       br.Expand(br.Button),
		LogoPath:     br.Logo,
		PolicyTarget: br.Policy,
		PolicyLabel:  clean(br.Expand(br.PolicyLabel)),
	}
	if br.Email != "" {
		before, after, _ := strings.Cut(br.ContactText, "{email}")
		c.Email = br.Email
		c.MailtoURL = br.MailtoURL()
		c.ContactBefore = clean(br.Expand(before))
		c.ContactAfter = clean(br.Expand(after))
	}
	return c
}

// clean removes characters that the window's link control would interpret
// as markup.
func clean(s string) string {
	return strings.NewReplacer("<", "", ">", "", `"`, "'").Replace(s)
}

// FooterMarkup returns the text of the link control: the policy link and the
// contact sentence. Links carry ids, never addresses: the window maps the id
// back to the configured target, so a text cannot inject another link.
func (c Content) FooterMarkup() (markup, plain string) {
	var m, p []string
	if c.PolicyTarget != "" {
		m = append(m, `<a id="policy">`+c.PolicyLabel+`</a>`)
		p = append(p, c.PolicyLabel)
	}
	if c.Email != "" {
		m = append(m, c.ContactBefore+`<a id="email">`+clean(c.Email)+`</a>`+c.ContactAfter)
		p = append(p, c.ContactBefore+c.Email+c.ContactAfter)
	}
	return strings.Join(m, "     "), strings.Join(p, "     ")
}

// ToolIDs lists the ids of the tools.
func ToolIDs(tools []Tool) []string {
	out := make([]string, len(tools))
	for i, t := range tools {
		out[i] = t.ID
	}
	return out
}
