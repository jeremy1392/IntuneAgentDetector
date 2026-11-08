package catalog

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"detectoragent/rules"
)

func brandingDir(t *testing.T, yaml string) string {
	t.Helper()
	dir := t.TempDir()
	img := image.NewNRGBA(image.Rect(0, 0, 40, 10))
	img.Set(1, 1, color.NRGBA{R: 200, A: 255})
	f, err := os.Create(filepath.Join(dir, "logo.png"))
	if err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := os.WriteFile(filepath.Join(dir, "AI-Policy.pdf"), []byte("%PDF-1.4"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "branding.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func apply(t *testing.T, yaml string) (*Disclaimer, string, error) {
	t.Helper()
	cat, err := Load(rules.Default)
	if err != nil {
		t.Fatal(err)
	}
	dir := brandingDir(t, yaml)
	b, err := LoadBrandingFile(filepath.Join(dir, "branding.yaml"))
	if err != nil {
		return &cat.Disclaimer, dir, err
	}
	return &cat.Disclaimer, dir, cat.Disclaimer.ApplyBranding(b, dir)
}

func TestBrandingOverrides(t *testing.T) {
	d, dir, err := apply(t, `
version: 3
company: "Acme Corp"
logo: logo.png
title: "{company}: AI notice"
text: |
  Read the {company} policy.
  Write to {email}.
policy: AI-Policy.pdf
email: secu@acme.example
email_subject: "AI question & more"
`)
	if err != nil {
		t.Fatal(err)
	}
	if d.Version != 3 || d.Company != "Acme Corp" {
		t.Errorf("version/company not applied: %+v", d.Branding)
	}
	if d.Logo != filepath.Join(dir, "logo.png") || d.Policy != filepath.Join(dir, "AI-Policy.pdf") {
		t.Errorf("relative paths not resolved: logo %q policy %q", d.Logo, d.Policy)
	}
	if got := d.Expand(d.Title); got != "Acme Corp: AI notice" {
		t.Errorf("title = %q", got)
	}
	if got := d.Expand(d.Text); !strings.Contains(got, "the Acme Corp policy") || !strings.Contains(got, "secu@acme.example") {
		t.Errorf("text placeholders: %q", got)
	}
	if d.Button != "I accept" || d.Heading == "" {
		t.Error("fields absent from the branding file must keep their default")
	}
	if got := d.MailtoURL(); got != "mailto:secu@acme.example?subject=AI%20question%20%26%20more" {
		t.Errorf("mailto = %q", got)
	}
	if !d.PolicyIsFile() {
		t.Error("policy should be a local document")
	}
}

func TestBrandingNoneAndEmpty(t *testing.T) {
	d, _, err := apply(t, "email: none\npolicy: none\n")
	if err != nil {
		t.Fatal(err)
	}
	if d.Email != "" || d.Policy != "" || d.MailtoURL() != "" {
		t.Errorf("none must remove the element: %+v", d.Branding)
	}
	if _, _, err := apply(t, ""); err != nil {
		t.Errorf("an empty branding file must be accepted: %v", err)
	}
}

func TestBrandingValidation(t *testing.T) {
	cases := map[string]string{
		"unknown key":          "compagny: Acme\n",
		"bad email":            "email: not-an-address\n",
		"missing logo":         "logo: missing.png\n",
		"logo type":            "logo: AI-Policy.pdf\n",
		"policy type":          "policy: run.exe\n",
		"policy url":           "policy: https://\n",
		"contact without link": "email: a@b.example\ncontact_text: Write to us.\n",
		"title too long":       "title: " + strings.Repeat("x", 201) + "\n",
	}
	for name, yaml := range cases {
		d, _, err := apply(t, yaml)
		if err == nil {
			t.Errorf("%s: expected an error", name)
		}
		if d.Email != "security@example.com" {
			t.Errorf("%s: a rejected branding file must leave the defaults unchanged", name)
		}
	}
}
