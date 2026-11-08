// Package redact masks secrets (API keys, tokens, passwords) in strings that
// leave the machine: reports, event log messages and command lines.
package redact

import (
	"regexp"
	"unicode/utf8"
)

type rule struct {
	re   *regexp.Regexp
	repl string
}

var rules = []rule{
	{regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{8,}`), "sk-ant-***"},
	{regexp.MustCompile(`sk-(?:proj-|svcacct-|or-v1-)?[A-Za-z0-9_\-]{16,}`), "sk-***"},
	{regexp.MustCompile(`AIza[0-9A-Za-z_\-]{20,}`), "AIza***"},
	{regexp.MustCompile(`\b(gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}`), "${1}_***"},
	{regexp.MustCompile(`\bxai-[A-Za-z0-9]{20,}`), "xai-***"},
	{regexp.MustCompile(`\bhf_[A-Za-z0-9]{20,}`), "hf_***"},
	{regexp.MustCompile(`\bgsk_[A-Za-z0-9]{20,}`), "gsk_***"},
	{regexp.MustCompile(`\br8_[A-Za-z0-9]{20,}`), "r8_***"},
	{regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=\-]{8,}`), "${1}***"},
	{regexp.MustCompile(`(?i)(--?(?:api[-_]?key|token|access[-_]?token|password|passwd|secret|auth)(?:=|\s+))("[^"]*"|'[^']*'|\S+)`), "${1}***"},
	{regexp.MustCompile(`(?i)\b([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD)[A-Z0-9_]*\s*=\s*)("[^"]*"|\S+)`), "${1}***"},
	{regexp.MustCompile(`(://[^/\s:@]+:)[^@\s/]+@`), "${1}***@"},
}

// String masks every secret pattern found in s.
func String(s string) string {
	if s == "" {
		return s
	}
	for _, r := range rules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}

// CommandLine masks secrets and truncates a command line to max bytes,
// without splitting a UTF-8 character.
func CommandLine(s string, max int) string {
	s = String(s)
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
