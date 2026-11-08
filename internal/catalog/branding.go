package catalog

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// Branding is what users see in the disclaimer window. The catalog holds the
// defaults; a branding file (branding.yaml) overrides any non-empty field.
//
// Text fields accept the placeholders {company} and {email}.
type Branding struct {
	// Version identifies the text in events 400 and 410.
	Version int `yaml:"version"`
	// Company replaces {company} in the texts.
	Company string `yaml:"company"`
	// Logo is a PNG or JPEG file shown at the top of the window.
	Logo     string `yaml:"logo"`
	Title    string `yaml:"title"`
	Heading  string `yaml:"heading"`
	Text     string `yaml:"text"`
	Checkbox string `yaml:"checkbox"`
	Button   string `yaml:"button"`
	// Policy is an http(s) address or a document file (PDF, DOCX, HTML...).
	Policy      string `yaml:"policy"`
	PolicyLabel string `yaml:"policy_label"`
	// Email is shown as a mailto link; EmailSubject pre-fills the subject.
	Email        string `yaml:"email"`
	EmailSubject string `yaml:"email_subject"`
	// ContactText is the sentence holding the e-mail link, with {email}.
	ContactText string `yaml:"contact_text"`
}

// Limits keep the window readable and the payloads small.
var brandingLimits = map[string]int{
	"company": 100, "title": 200, "heading": 300, "text": 10000, "checkbox": 300,
	"button": 40, "policy_label": 100, "email_subject": 150, "contact_text": 300,
}

var (
	emailPattern       = regexp.MustCompile(`^[^@\s<>"'()\[\],;:\\]+@[^@\s<>"'()\[\],;:\\]+\.[A-Za-z]{2,}$`)
	logoExtensions     = map[string]bool{".png": true, ".jpg": true, ".jpeg": true}
	documentExtensions = map[string]bool{".pdf": true, ".docx": true, ".doc": true, ".html": true, ".htm": true,
		".txt": true, ".md": true, ".rtf": true, ".pptx": true, ".odt": true, ".xlsx": true}
)

const maxLogoBytes = 5 << 20

func (b *Branding) setDefaults() {
	def := func(p *string, v string) {
		if strings.TrimSpace(*p) == "" {
			*p = v
		}
	}
	if b.Version <= 0 {
		b.Version = 1
	}
	def(&b.Title, "AI agent usage: mandatory notice")
	def(&b.Heading, "An AI agent was detected on your computer.")
	def(&b.Checkbox, "I have read and understood the AI acceptable use policy.")
	def(&b.Button, "I accept")
	def(&b.PolicyLabel, "Read the AI policy")
	def(&b.ContactText, "Questions? Contact {email}.")
}

// LoadBrandingFile reads a branding file. Unknown keys are rejected so that
// a typo does not silently keep the default text.
func LoadBrandingFile(path string) (*Branding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Branding
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&b); err != nil && !errors.Is(err, io.EOF) { // io.EOF: empty file
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return &b, nil
}

// ApplyBranding overrides the disclaimer with the non-empty fields of b.
// Relative logo and policy paths are resolved against baseDir. Every value
// is validated; on error the disclaimer is left unchanged.
func (d *Disclaimer) ApplyBranding(b *Branding, baseDir string) error {
	merged := d.Branding
	set := func(dst *string, v string) {
		if strings.TrimSpace(v) != "" {
			*dst = strings.TrimSpace(v)
		}
	}
	if b.Version > 0 {
		merged.Version = b.Version
	}
	set(&merged.Company, b.Company)
	set(&merged.Title, b.Title)
	set(&merged.Heading, b.Heading)
	if strings.TrimSpace(b.Text) != "" {
		merged.Text = strings.TrimRight(b.Text, "\r\n ")
	}
	set(&merged.Checkbox, b.Checkbox)
	set(&merged.Button, b.Button)
	set(&merged.PolicyLabel, b.PolicyLabel)
	set(&merged.Email, b.Email)
	set(&merged.EmailSubject, b.EmailSubject)
	set(&merged.ContactText, b.ContactText)
	if strings.TrimSpace(b.Logo) != "" {
		merged.Logo = resolvePath(strings.TrimSpace(b.Logo), baseDir)
	}
	if strings.TrimSpace(b.Policy) != "" {
		p := strings.TrimSpace(b.Policy)
		if !isWebURL(p) {
			p = resolvePath(p, baseDir)
		}
		merged.Policy = p
	}
	// "none" removes an element that the defaults would otherwise show.
	for _, f := range []struct {
		value string
		dst   *string
	}{{b.Logo, &merged.Logo}, {b.Policy, &merged.Policy}, {b.Email, &merged.Email}} {
		if strings.EqualFold(strings.TrimSpace(f.value), "none") {
			*f.dst = ""
		}
	}
	if err := merged.Validate(); err != nil {
		return err
	}
	d.Branding = merged
	return nil
}

// Validate checks every branding value.
func (b *Branding) Validate() error {
	var errs []error
	fields := map[string]string{
		"company": b.Company, "title": b.Title, "heading": b.Heading, "text": b.Text,
		"checkbox": b.Checkbox, "button": b.Button, "policy_label": b.PolicyLabel,
		"email_subject": b.EmailSubject, "contact_text": b.ContactText,
	}
	for name, v := range fields {
		if n := utf8.RuneCountInString(v); n > brandingLimits[name] {
			errs = append(errs, fmt.Errorf("%s: %d characters, at most %d", name, n, brandingLimits[name]))
		}
		if strings.ContainsRune(v, 0) {
			errs = append(errs, fmt.Errorf("%s: contains a NUL character", name))
		}
	}
	if b.Email != "" && !emailPattern.MatchString(b.Email) {
		errs = append(errs, fmt.Errorf("email: %q is not a valid address", b.Email))
	}
	if b.Email != "" && !strings.Contains(b.ContactText, "{email}") {
		errs = append(errs, errors.New("contact_text: must contain {email}"))
	}
	if b.Logo != "" {
		if err := checkFile(b.Logo, logoExtensions, maxLogoBytes); err != nil {
			errs = append(errs, fmt.Errorf("logo: %w", err))
		}
	}
	if b.Policy != "" {
		if isWebURL(b.Policy) {
			if u, err := url.Parse(b.Policy); err != nil || u.Host == "" {
				errs = append(errs, fmt.Errorf("policy: %q is not a valid address", b.Policy))
			}
		} else if err := checkFile(b.Policy, documentExtensions, 0); err != nil {
			errs = append(errs, fmt.Errorf("policy: %w", err))
		}
	}
	return errors.Join(errs...)
}

// Expand replaces {company} and {email} in a text.
func (b *Branding) Expand(s string) string {
	company := b.Company
	if company == "" {
		company = "the company"
	}
	return strings.NewReplacer("{company}", company, "{email}", b.Email).Replace(s)
}

// MailtoURL returns the mailto link of the contact address, or "".
func (b *Branding) MailtoURL() string {
	if b.Email == "" {
		return ""
	}
	u := "mailto:" + b.Email
	if b.EmailSubject != "" {
		u += "?subject=" + strings.ReplaceAll(url.QueryEscape(b.Expand(b.EmailSubject)), "+", "%20")
	}
	return u
}

// PolicyIsFile reports whether the policy is a local document.
func (b *Branding) PolicyIsFile() bool { return b.Policy != "" && !isWebURL(b.Policy) }

func isWebURL(s string) bool {
	l := strings.ToLower(s)
	return strings.HasPrefix(l, "https://") || strings.HasPrefix(l, "http://")
}

func resolvePath(p, baseDir string) string {
	p = os.ExpandEnv(p)
	if !filepath.IsAbs(p) && baseDir != "" {
		p = filepath.Join(baseDir, p)
	}
	return filepath.Clean(p)
}

func checkFile(path string, allowed map[string]bool, maxBytes int64) error {
	ext := strings.ToLower(filepath.Ext(path))
	if !allowed[ext] {
		return fmt.Errorf("%s: unsupported file type %q", path, ext)
	}
	st, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s: file not found", path)
	}
	if err != nil {
		return fmt.Errorf("%s: %v", path, err)
	}
	if st.IsDir() {
		return fmt.Errorf("%s: is a directory", path)
	}
	if maxBytes > 0 && st.Size() > maxBytes {
		return fmt.Errorf("%s: %d bytes, at most %d", path, st.Size(), maxBytes)
	}
	return nil
}
