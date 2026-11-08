package scan

import (
	"os"
	"path/filepath"
	"strings"
)

var profilePlaceholders = []string{"%USERPROFILE%", "%APPDATA%", "%LOCALAPPDATA%"}

// isProfilePattern reports whether a path pattern depends on a user profile.
func isProfilePattern(pattern string) bool {
	up := strings.ToUpper(pattern)
	for _, p := range profilePlaceholders {
		if strings.Contains(up, p) {
			return true
		}
	}
	return false
}

// machineDirs maps machine-wide placeholders to their values.
func machineDirs() map[string]string {
	get := func(name, def string) string {
		if v := os.Getenv(name); v != "" {
			return v
		}
		return def
	}
	return map[string]string{
		"%PROGRAMFILES%":      get("ProgramW6432", get("ProgramFiles", `C:\Program Files`)),
		"%PROGRAMFILES(X86)%": get("ProgramFiles(x86)", `C:\Program Files (x86)`),
		"%PROGRAMDATA%":       get("ProgramData", `C:\ProgramData`),
		"%SYSTEMROOT%":        get("SystemRoot", `C:\Windows`),
	}
}

// expand replaces placeholders in a pattern. Profile placeholders need a
// profile; ok is false when one is missing.
func expand(pattern string, p *Profile) (string, bool) {
	out := pattern
	replace := func(placeholder, value string) {
		for {
			i := strings.Index(strings.ToUpper(out), placeholder)
			if i < 0 {
				return
			}
			out = out[:i] + value + out[i+len(placeholder):]
		}
	}
	if isProfilePattern(pattern) {
		if p == nil {
			return "", false
		}
		replace("%USERPROFILE%", p.Home)
		replace("%LOCALAPPDATA%", p.Local)
		replace("%APPDATA%", p.Roaming)
	}
	for k, v := range machineDirs() {
		replace(k, v)
	}
	return out, true
}

// glob expands wildcards, or checks existence for plain paths.
func glob(pattern string) []string {
	if !strings.ContainsAny(pattern, "*?[") {
		if _, err := os.Lstat(pattern); err == nil {
			return []string{pattern}
		}
		return nil
	}
	m, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	return m
}

// expandGlob expands placeholders and wildcards for one profile, or for the
// machine when p is nil and the pattern is machine-wide.
func expandGlob(pattern string, p *Profile) []string {
	x, ok := expand(pattern, p)
	if !ok {
		return nil
	}
	return glob(x)
}

// subdirs lists the names of the sub-directories of dir.
func subdirs(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}
