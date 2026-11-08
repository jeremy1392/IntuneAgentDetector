// Package catalog loads the detection catalog (known AI tools, LLM endpoints,
// generic agent patterns and the disclaimer text) and provides matchers.
package catalog

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"detectoragent/internal/model"
)

// Catalog is the root of the YAML catalog.
type Catalog struct {
	Version    string      `yaml:"version"`
	Disclaimer Disclaimer  `yaml:"disclaimer"`
	Sanctioned []string    `yaml:"sanctioned"`
	Generic    Generic     `yaml:"generic"`
	Tools      []*Tool     `yaml:"tools"`
	Endpoints  []*Endpoint `yaml:"endpoints"`

	toolByID   map[string]*Tool
	hosts      map[string]*Endpoint
	suffixes   []*Endpoint // sorted longest first
	patterns   []*Endpoint
	cidrs      []*Endpoint
	sanctioned map[string]bool
	imageTools map[string][]*Tool
}

// Disclaimer holds the text, branding and trigger rules of the user
// disclaimer. The catalog provides the defaults; a branding file can
// override every text and branding field (see branding.go).
type Disclaimer struct {
	Branding      `yaml:",inline"`
	TriggerLevels []string `yaml:"trigger_levels"`
	MinConfidence string   `yaml:"min_confidence"`

	levels        map[model.Level]bool
	minConfidence model.Confidence
}

// Generic holds the signature-less patterns used to spot unknown agents.
type Generic struct {
	Shells                 []string `yaml:"shells"`
	Interpreters           []string `yaml:"interpreters"`
	Browsers               []string `yaml:"browsers"`
	BrowserAutomationFlags []string `yaml:"browser_automation_flags"`
	MCPCmdline             []string `yaml:"mcp_cmdline"`
	InferenceModules       []string `yaml:"inference_modules"`
	TokenizerModules       []string `yaml:"tokenizer_modules"`
	BaseURLVars            []string `yaml:"base_url_vars"`
	APIKeyVars             []string `yaml:"api_key_vars"`
	VSCodeExtensionDirs    []string `yaml:"vscode_extension_dirs"`
	JetBrainsPluginDirs    []string `yaml:"jetbrains_plugin_dirs"`
	BrowserProfileDirs     []string `yaml:"browser_profile_dirs"`
	NPMGlobalDirs          []string `yaml:"npm_global_dirs"`
	PIPSiteDirs            []string `yaml:"pip_site_dirs"`
	PIPToolDirs            []string `yaml:"pip_tool_dirs"`

	shells, interpreters, browsers map[string]bool
	reAutomation, reMCP            []*regexp.Regexp
	reInference, reTokenizer       []*regexp.Regexp
	reBaseURL, reAPIKey            []*regexp.Regexp
}

// Tool describes one known AI tool and how to recognize it.
type Tool struct {
	ID                string       `yaml:"id"`
	Name              string       `yaml:"name"`
	Vendor            string       `yaml:"vendor"`
	Category          string       `yaml:"category"`
	Confidence        string       `yaml:"confidence"`
	Process           ProcessMatch `yaml:"process"`
	Packages          []string     `yaml:"packages"`
	Services          []string     `yaml:"services"`
	Uninstall         []string     `yaml:"uninstall"`
	VSCodeExtensions  []string     `yaml:"vscode_extensions"`
	JetBrainsPlugins  []string     `yaml:"jetbrains_plugins"`
	BrowserExtensions []string     `yaml:"browser_extensions"`
	NPM               []string     `yaml:"npm"`
	PIP               []string     `yaml:"pip"`
	Installed         []string     `yaml:"installed"`
	Residue           []string     `yaml:"residue"`
	History           []string     `yaml:"history"`
	Models            []string     `yaml:"models"`
	MCPConfigs        []string     `yaml:"mcp_configs"`
	Ports             []int        `yaml:"ports"`
	Env               []string     `yaml:"env"`

	confidenceCap model.Confidence
	images        map[string]bool
	products      map[string]bool
	signers       []string
	rePaths       []*regexp.Regexp
	reCmdline     []*regexp.Regexp
	rePackages    []*regexp.Regexp
	reServices    []*regexp.Regexp
	reUninstall   []*regexp.Regexp
	reJetBrains   []*regexp.Regexp
	reBrowserExt  []*regexp.Regexp
	vscodeExt     map[string]bool
	npm           map[string]bool
	pip           map[string]bool
	env           map[string]bool
	ports         map[int]bool
}

// ProcessMatch describes how to recognize a running process of a tool.
type ProcessMatch struct {
	Images   []string `yaml:"images"`
	Products []string `yaml:"products"`
	Signers  []string `yaml:"signers"`
	Paths    []string `yaml:"paths"`
	Cmdline  []string `yaml:"cmdline"`
}

// Endpoint describes an LLM-related network destination.
type Endpoint struct {
	Host       string `yaml:"host"`
	Suffix     string `yaml:"suffix"`
	CIDR       string `yaml:"cidr"`
	Pattern    string `yaml:"pattern"`
	Provider   string `yaml:"provider"`
	Category   string `yaml:"category"`
	Shared     bool   `yaml:"shared"`
	Unverified bool   `yaml:"unverified"`

	ipnet *net.IPNet
	re    *regexp.Regexp
}

// Key returns the host, suffix or CIDR that identifies the endpoint.
func (e *Endpoint) Key() string {
	switch {
	case e.Host != "":
		return e.Host
	case e.Suffix != "":
		return "*" + e.Suffix
	case e.Pattern != "":
		return e.Pattern
	default:
		return e.CIDR
	}
}

// LoadFile reads and compiles a catalog from disk.
func LoadFile(path string) (*Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Load(data)
}

// Load parses and compiles a catalog.
func Load(data []byte) (*Catalog, error) {
	var c Catalog
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse catalog: %w", err)
	}
	if err := c.compile(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Catalog) compile() error {
	var errs []error
	add := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	add(c.Disclaimer.compile())
	add(c.Generic.compile())

	c.toolByID = make(map[string]*Tool)
	c.imageTools = make(map[string][]*Tool)
	for i, t := range c.Tools {
		if t == nil || t.ID == "" {
			add(fmt.Errorf("tool #%d: missing id", i))
			continue
		}
		if _, dup := c.toolByID[t.ID]; dup {
			add(fmt.Errorf("tool %q: duplicate id", t.ID))
			continue
		}
		if t.Name == "" {
			t.Name = t.ID
		}
		if err := t.compile(); err != nil {
			add(fmt.Errorf("tool %q: %w", t.ID, err))
			continue
		}
		c.toolByID[t.ID] = t
		for img := range t.images {
			c.imageTools[img] = append(c.imageTools[img], t)
		}
	}

	c.hosts = make(map[string]*Endpoint)
	for i, e := range c.Endpoints {
		if e == nil {
			continue
		}
		set := 0
		for _, v := range []string{e.Host, e.Suffix, e.CIDR, e.Pattern} {
			if v != "" {
				set++
			}
		}
		if set != 1 {
			add(fmt.Errorf("endpoint #%d: exactly one of host, suffix, pattern or cidr is required", i))
			continue
		}
		if e.Provider == "" {
			add(fmt.Errorf("endpoint %q: missing provider", e.Key()))
			continue
		}
		switch {
		case e.Host != "":
			e.Host = NormalizeHost(e.Host)
			if _, dup := c.hosts[e.Host]; dup {
				add(fmt.Errorf("endpoint %q: duplicate host", e.Host))
				continue
			}
			c.hosts[e.Host] = e
		case e.Suffix != "":
			s := NormalizeHost(e.Suffix)
			if !strings.HasPrefix(s, ".") {
				s = "." + s
			}
			e.Suffix = s
			for _, other := range c.suffixes {
				if other.Suffix == s {
					add(fmt.Errorf("endpoint %q: duplicate suffix", s))
				}
			}
			c.suffixes = append(c.suffixes, e)
		case e.Pattern != "":
			re, err := regexp.Compile(e.Pattern)
			if err != nil {
				add(fmt.Errorf("endpoint %q: %w", e.Pattern, err))
				continue
			}
			e.re = re
			c.patterns = append(c.patterns, e)
		default:
			_, n, err := net.ParseCIDR(e.CIDR)
			if err != nil {
				add(fmt.Errorf("endpoint %q: %w", e.CIDR, err))
				continue
			}
			e.ipnet = n
			c.cidrs = append(c.cidrs, e)
		}
	}
	sort.SliceStable(c.suffixes, func(i, j int) bool {
		return len(c.suffixes[i].Suffix) > len(c.suffixes[j].Suffix)
	})

	c.sanctioned = make(map[string]bool)
	for _, s := range c.Sanctioned {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			c.sanctioned[s] = true
		}
	}
	return errors.Join(errs...)
}

func (d *Disclaimer) compile() error {
	d.Branding.setDefaults()
	if err := d.Branding.Validate(); err != nil {
		return fmt.Errorf("disclaimer: %w", err)
	}
	if len(d.TriggerLevels) == 0 {
		d.TriggerLevels = []string{"active", "recent", "installed"}
	}
	d.levels = make(map[model.Level]bool)
	for _, s := range d.TriggerLevels {
		l, err := model.ParseLevel(s)
		if err != nil {
			return fmt.Errorf("disclaimer.trigger_levels: %w", err)
		}
		d.levels[l] = true
	}
	if d.MinConfidence == "" {
		d.MinConfidence = "medium"
	}
	mc, err := model.ParseConfidence(d.MinConfidence)
	if err != nil {
		return fmt.Errorf("disclaimer.min_confidence: %w", err)
	}
	d.minConfidence = mc
	return nil
}

// Triggers reports whether a finding with this level and confidence must be
// shown in the disclaimer.
func (d *Disclaimer) Triggers(l model.Level, c model.Confidence) bool {
	return d.levels[l] && c >= d.minConfidence
}

func (g *Generic) compile() error {
	var err error
	g.shells = lowerSet(g.Shells)
	g.interpreters = lowerSet(g.Interpreters)
	g.browsers = lowerSet(g.Browsers)
	compile := func(name string, src []string) []*regexp.Regexp {
		res, e := compileAll(src)
		if e != nil && err == nil {
			err = fmt.Errorf("generic.%s: %w", name, e)
		}
		return res
	}
	g.reAutomation = compile("browser_automation_flags", quoteLiterals(g.BrowserAutomationFlags))
	g.reMCP = compile("mcp_cmdline", g.MCPCmdline)
	g.reInference = compile("inference_modules", g.InferenceModules)
	g.reTokenizer = compile("tokenizer_modules", g.TokenizerModules)
	g.reBaseURL = compile("base_url_vars", g.BaseURLVars)
	g.reAPIKey = compile("api_key_vars", g.APIKeyVars)
	return err
}

func (t *Tool) compile() error {
	var err error
	compile := func(name string, src []string) []*regexp.Regexp {
		res, e := compileAll(src)
		if e != nil && err == nil {
			err = fmt.Errorf("%s: %w", name, e)
		}
		return res
	}
	t.confidenceCap = model.ConfidenceHigh
	if t.Confidence != "" {
		c, e := model.ParseConfidence(t.Confidence)
		if e != nil {
			return e
		}
		t.confidenceCap = c
	}
	t.images = lowerSet(t.Process.Images)
	t.products = lowerSet(t.Process.Products)
	for _, s := range t.Process.Signers {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			t.signers = append(t.signers, s)
		}
	}
	t.rePaths = compile("process.paths", t.Process.Paths)
	t.reCmdline = compile("process.cmdline", t.Process.Cmdline)
	t.rePackages = compile("packages", t.Packages)
	t.reServices = compile("services", t.Services)
	t.reUninstall = compile("uninstall", t.Uninstall)
	t.reJetBrains = compile("jetbrains_plugins", t.JetBrainsPlugins)
	t.reBrowserExt = compile("browser_extensions", t.BrowserExtensions)
	t.vscodeExt = lowerSet(t.VSCodeExtensions)
	t.npm = lowerSet(t.NPM)
	t.pip = make(map[string]bool)
	for _, p := range t.PIP {
		t.pip[NormalizePipName(p)] = true
	}
	t.env = make(map[string]bool)
	for _, e := range t.Env {
		t.env[strings.ToUpper(strings.TrimSpace(e))] = true
	}
	t.ports = make(map[int]bool)
	for _, p := range t.Ports {
		t.ports[p] = true
	}
	return err
}

// Tool returns the tool with the given id, or nil.
func (c *Catalog) Tool(id string) *Tool { return c.toolByID[id] }

// ToolsForImage returns the tools that list this executable name.
func (c *Catalog) ToolsForImage(image string) []*Tool {
	return c.imageTools[strings.ToLower(image)]
}

// MatchHost returns the endpoint matching a host name, exact names first and
// then the longest suffix.
func (c *Catalog) MatchHost(host string) *Endpoint {
	h := NormalizeHost(host)
	if h == "" {
		return nil
	}
	if e, ok := c.hosts[h]; ok {
		return e
	}
	for _, e := range c.suffixes {
		if strings.HasSuffix(h, e.Suffix) || h == strings.TrimPrefix(e.Suffix, ".") {
			return e
		}
	}
	for _, e := range c.patterns {
		if e.re.MatchString(h) {
			return e
		}
	}
	return nil
}

// MatchIP returns the endpoint whose CIDR contains the address, or nil.
func (c *Catalog) MatchIP(ip net.IP) *Endpoint {
	for _, e := range c.cidrs {
		if e.ipnet.Contains(ip) {
			return e
		}
	}
	return nil
}

// ExactHosts returns every exact host of the catalog.
func (c *Catalog) ExactHosts() []string {
	out := make([]string, 0, len(c.hosts))
	for h := range c.hosts {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// IsSanctioned reports whether a tool id or an endpoint is approved.
func (c *Catalog) IsSanctioned(toolID string, ep *Endpoint) bool {
	if toolID != "" && c.sanctioned[strings.ToLower(toolID)] {
		return true
	}
	if ep != nil {
		if ep.Host != "" && c.sanctioned[ep.Host] {
			return true
		}
		if ep.Suffix != "" && (c.sanctioned[ep.Suffix] || c.sanctioned["*"+ep.Suffix] ||
			c.sanctioned[strings.TrimPrefix(ep.Suffix, ".")]) {
			return true
		}
	}
	return false
}

// IsSanctionedHost reports whether a raw host name is approved.
func (c *Catalog) IsSanctionedHost(host string) bool {
	h := NormalizeHost(host)
	if c.sanctioned[h] {
		return true
	}
	return c.IsSanctioned("", c.MatchHost(h))
}

// ConfidenceCap returns the maximum confidence allowed for the tool.
func (t *Tool) ConfidenceCap() model.Confidence { return t.confidenceCap }

// HasImage reports whether the tool lists this executable name.
func (t *Tool) HasImage(image string) bool { return t.images[strings.ToLower(image)] }

// HasProduct reports whether the version-info product name belongs to the tool.
func (t *Tool) HasProduct(product string) bool {
	return product != "" && t.products[strings.ToLower(strings.TrimSpace(product))]
}

// HasSigners reports whether the tool declares expected signers.
func (t *Tool) HasSigners() bool { return len(t.signers) > 0 }

// MatchSigner reports whether the signer subject contains an expected name.
func (t *Tool) MatchSigner(signer string) bool {
	s := strings.ToLower(signer)
	if s == "" {
		return false
	}
	for _, want := range t.signers {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}

// MatchPath reports whether a full image path matches the tool.
func (t *Tool) MatchPath(path string) bool { return anyMatch(t.rePaths, path) }

// MatchCmdline reports whether a command line matches the tool.
func (t *Tool) MatchCmdline(cmd string) bool { return anyMatch(t.reCmdline, cmd) }

// MatchPackage reports whether an MSIX package family name matches the tool.
func (t *Tool) MatchPackage(pfn string) bool { return pfn != "" && anyMatch(t.rePackages, pfn) }

// MatchService reports whether a service name matches the tool.
func (t *Tool) MatchService(name string) bool { return anyMatch(t.reServices, name) }

// MatchUninstall reports whether an uninstall DisplayName matches the tool.
func (t *Tool) MatchUninstall(displayName string) bool {
	return displayName != "" && anyMatch(t.reUninstall, displayName)
}

// MatchVSCodeExtension reports whether an extension id belongs to the tool.
func (t *Tool) MatchVSCodeExtension(id string) bool { return t.vscodeExt[strings.ToLower(id)] }

// MatchJetBrainsPlugin reports whether a plugin directory name matches.
func (t *Tool) MatchJetBrainsPlugin(dir string) bool { return anyMatch(t.reJetBrains, dir) }

// MatchBrowserExtension reports whether a browser extension name matches.
func (t *Tool) MatchBrowserExtension(name string) bool {
	return name != "" && anyMatch(t.reBrowserExt, name)
}

// MatchNPM reports whether a global npm package belongs to the tool.
func (t *Tool) MatchNPM(pkg string) bool { return t.npm[strings.ToLower(pkg)] }

// MatchPIP reports whether a Python distribution belongs to the tool.
func (t *Tool) MatchPIP(dist string) bool { return t.pip[NormalizePipName(dist)] }

// MatchEnv reports whether an environment variable name belongs to the tool.
func (t *Tool) MatchEnv(name string) bool { return t.env[strings.ToUpper(name)] }

// HasPort reports whether the tool listens on this local port.
func (t *Tool) HasPort(port int) bool { return t.ports[port] }

// IsShell reports whether an executable name is a shell or interpreter that
// agents use to run commands.
func (g *Generic) IsShell(image string) bool { return g.shells[strings.ToLower(image)] }

// IsInterpreter reports whether a process deserves module/environment inspection.
func (g *Generic) IsInterpreter(image string) bool { return g.interpreters[strings.ToLower(image)] }

// IsBrowser reports whether an executable name is a web browser.
func (g *Generic) IsBrowser(image string) bool { return g.browsers[strings.ToLower(image)] }

// AutomationFlag returns the first browser automation flag found in a command line.
func (g *Generic) AutomationFlag(cmd string) string { return firstMatch(g.reAutomation, cmd) }

// MCPMatch returns the MCP pattern found in a command line.
func (g *Generic) MCPMatch(cmd string) string { return firstMatch(g.reMCP, cmd) }

// InferenceModule reports whether a loaded module name is an inference runtime.
func (g *Generic) InferenceModule(name string) bool { return anyMatch(g.reInference, name) }

// TokenizerModule reports whether a loaded module name is an LLM tokenizer.
func (g *Generic) TokenizerModule(name string) bool { return anyMatch(g.reTokenizer, name) }

// IsBaseURLVar reports whether an environment variable configures an LLM API base.
func (g *Generic) IsBaseURLVar(name string) bool { return anyMatch(g.reBaseURL, name) }

// IsAPIKeyVar reports whether an environment variable holds an LLM API key.
func (g *Generic) IsAPIKeyVar(name string) bool { return anyMatch(g.reAPIKey, name) }

// NormalizeHost lowercases a host name and strips a trailing dot and port.
func NormalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.Trim(h, "[]")
}

// NormalizePipName applies PEP 503 normalization to a distribution name.
func NormalizePipName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastSep := false
	for _, r := range s {
		if r == '-' || r == '_' || r == '.' {
			if !lastSep {
				b.WriteByte('-')
			}
			lastSep = true
			continue
		}
		b.WriteRune(r)
		lastSep = false
	}
	return b.String()
}

func lowerSet(in []string) map[string]bool {
	m := make(map[string]bool, len(in))
	for _, s := range in {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			m[s] = true
		}
	}
	return m
}

func compileAll(src []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(src))
	for _, s := range src {
		re, err := regexp.Compile(s)
		if err != nil {
			return nil, fmt.Errorf("invalid pattern %q: %w", s, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// quoteLiterals turns plain substrings into case-insensitive literal patterns.
func quoteLiterals(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, "(?i)"+regexp.QuoteMeta(s))
	}
	return out
}

func anyMatch(res []*regexp.Regexp, s string) bool {
	if s == "" {
		return false
	}
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func firstMatch(res []*regexp.Regexp, s string) string {
	if s == "" {
		return ""
	}
	for _, re := range res {
		if m := re.FindString(s); m != "" {
			return m
		}
	}
	return ""
}
