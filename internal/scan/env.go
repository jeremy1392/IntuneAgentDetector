package scan

import (
	"net/url"
	"strings"

	"golang.org/x/sys/windows/registry"

	"detectoragent/internal/catalog"
)

const machineEnvironmentKey = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`

// environment inspects the persistent machine and user environment variables
// for LLM base URLs, API keys (presence only) and tool-specific variables.
func environment(cat *catalog.Catalog, profiles []Profile, currentSID string) []EnvItem {
	var out []EnvItem
	inspect := func(k registry.Key, sid, scope string) {
		names, _ := k.ReadValueNames(-1)
		for _, name := range names {
			out = append(out, classifyEnv(cat, k, name, sid, scope)...)
		}
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, machineEnvironmentKey, registry.QUERY_VALUE); err == nil {
		inspect(k, "", "machine")
		k.Close()
	}
	for i := range profiles {
		p := &profiles[i]
		if k, ok := userKey(p, currentSID, "Environment", registry.QUERY_VALUE); ok {
			inspect(k, p.SID, "user")
			k.Close()
		}
	}
	return out
}

func classifyEnv(cat *catalog.Catalog, k registry.Key, name, sid, scope string) []EnvItem {
	var out []EnvItem
	g := &cat.Generic
	switch {
	case g.IsBaseURLVar(name):
		value, _, err := k.GetStringValue(name)
		if err == nil {
			if host := hostOf(value); host != "" {
				out = append(out, EnvItem{Kind: "base-url", Var: name, Host: host, UserSID: sid, Scope: scope})
			}
		}
	case g.IsAPIKeyVar(name):
		out = append(out, EnvItem{Kind: "api-key", Var: name, UserSID: sid, Scope: scope})
	}
	for _, t := range cat.Tools {
		if t.MatchEnv(name) {
			out = append(out, EnvItem{Kind: "tool-env", Var: name, ToolID: t.ID, UserSID: sid, Scope: scope})
		}
	}
	return out
}

// hostOf extracts the host name of a URL or host:port value.
func hostOf(value string) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return ""
	}
	if !strings.Contains(v, "://") {
		v = "http://" + v
	}
	u, err := url.Parse(v)
	if err != nil {
		return ""
	}
	return catalog.NormalizeHost(u.Hostname())
}

// envKeeper returns the filter used when reading a process environment:
// base URLs keep only their host, API keys and tool variables only their name.
func envKeeper(cat *catalog.Catalog) func(name, value string) (string, bool) {
	return func(name, value string) (string, bool) {
		g := &cat.Generic
		if g.IsBaseURLVar(name) {
			if h := hostOf(value); h != "" {
				return h, true
			}
			return "", false
		}
		if g.IsAPIKeyVar(name) {
			return "", true
		}
		for _, t := range cat.Tools {
			if t.MatchEnv(name) {
				return "", true
			}
		}
		return "", false
	}
}
