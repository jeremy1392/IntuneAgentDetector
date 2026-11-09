package scan

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func TestParseExtensionID(t *testing.T) {
	cases := map[string]string{
		"anthropic.claude-code-2.1.319-win32-x64": "anthropic.claude-code",
		"github.copilot-chat-0.30.1":              "github.copilot-chat",
		"ms-python.python-2024.2.1":               "ms-python.python",
		"SaoudRizwan.claude-dev-3.20.0":           "saoudrizwan.claude-dev",
		".obsolete":                               "",
		"extensions.json":                         "",
	}
	for in, want := range cases {
		if got := parseExtensionID(in); got != want {
			t.Errorf("parseExtensionID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFamilyFromFullName(t *testing.T) {
	cases := map[string]string{
		"Claude_3.1623.1.0_x64__pzs8sxrjxfjjc":                                       "Claude_pzs8sxrjxfjjc",
		"OpenAI.Codex_26.1103.3517.0_x64__2p2nqsd0c76g0":                             "OpenAI.Codex_2p2nqsd0c76g0",
		"OpenAI.CodexPrimaryRuntime.v26-1030-493-0_26.1030.493.0_x64__3k8sg7r9htsxt": "OpenAI.CodexPrimaryRuntime.v26-1030-493-0_3k8sg7r9htsxt",
		"garbage": "",
	}
	for in, want := range cases {
		if got := familyFromFullName(in); got != want {
			t.Errorf("familyFromFullName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPrefetchExecutable(t *testing.T) {
	if got := prefetchExecutable("CLAUDE.EXE-1A2B3C4D.pf"); got != "claude.exe" {
		t.Errorf("got %q", got)
	}
	if got := prefetchExecutable("CODEX-COMPUTER-USE-SWIFT.EXE-00AA11BB.pf"); got != "codex-computer-use-swift.exe" {
		t.Errorf("got %q", got)
	}
}

func TestParseEnvironmentBlock(t *testing.T) {
	block := utf16.Encode([]rune("=C:=C:\\work\x00OPENAI_BASE_URL=https://relay.example.net/v1\x00OPENAI_API_KEY=sk-secret\x00PATH=C:\\x\x00\x00"))
	keep := func(name, value string) (string, bool) {
		switch name {
		case "OPENAI_BASE_URL":
			return hostOf(value), true
		case "OPENAI_API_KEY":
			return "", true
		}
		return "", false
	}
	got := parseEnvironmentBlock(block, keep)
	if len(got) != 2 || got[0].Value != "relay.example.net" || got[1].Name != "OPENAI_API_KEY" || got[1].Value != "" {
		t.Errorf("unexpected environment: %+v", got)
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"https://openrouter.ai/api/v1": "openrouter.ai",
		"http://127.0.0.1:11434":       "127.0.0.1",
		"localhost:4000":               "localhost",
		"  https://API.Example.COM  ":  "api.example.com",
		"":                             "",
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCountMCPServers(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	claude := write("claude.json", `{"oauthAccount":{"email":"x"},"mcpServers":{"a":{},"b":{}},"projects":{"C:/p":{"mcpServers":{"c":{}}}}}`)
	vscode := write("mcp.json", "\ufeff"+`{"servers":{"github":{"type":"http"}}}`)
	empty := write("empty.json", `{"projects":{}}`)
	if n := countMCPServers(claude); n != 3 {
		t.Errorf("claude config: %d servers, want 3", n)
	}
	if n := countMCPServers(vscode); n != 1 {
		t.Errorf("vscode config with BOM: %d servers, want 1", n)
	}
	if n := countMCPServers(empty); n != 0 {
		t.Errorf("empty config: %d servers", n)
	}
}

func TestExpand(t *testing.T) {
	p := &Profile{Home: `C:\Users\u`, Roaming: `C:\Users\u\AppData\Roaming`, Local: `C:\Users\u\AppData\Local`}
	got, ok := expand(`%LocalAppData%\Programs\cursor\Cursor.exe`, p)
	if !ok || got != `C:\Users\u\AppData\Local\Programs\cursor\Cursor.exe` {
		t.Errorf("got %q %v", got, ok)
	}
	if _, ok := expand(`%APPDATA%\x`, nil); ok {
		t.Error("profile pattern without profile must fail")
	}
	if !isProfilePattern(`%userprofile%\.claude`) || isProfilePattern(`%PROGRAMFILES%\nodejs`) {
		t.Error("isProfilePattern is wrong")
	}
}

func TestPort(t *testing.T) {
	// 443 in network byte order, as stored in the low 16 bits of a DWORD.
	if got := port(0xBB01); got != 443 {
		t.Errorf("port = %d", got)
	}
}

func TestDNSRecordIPv4Mapped(t *testing.T) {
	// getaddrinfo with AF_UNSPEC caches IPv4 answers as IPv4-mapped AAAA
	// records: they must match the IPv4 connection table.
	mapped := windows.DNSRecord{Type: windows.DNS_TYPE_AAAA}
	copy(mapped.Data[:], net.ParseIP("::ffff:104.18.2.115").To16())
	v6 := windows.DNSRecord{Type: windows.DNS_TYPE_AAAA}
	copy(v6.Data[:], net.ParseIP("2607:6bc0::10").To16())
	a := windows.DNSRecord{Type: windows.DNS_TYPE_A}
	copy(a.Data[:], net.ParseIP("160.79.104.10").To4())
	cname := windows.DNSRecord{Type: windows.DNS_TYPE_CNAME}

	if ip := recordIP(&mapped); len(ip) != 4 || ip.String() != "104.18.2.115" {
		t.Errorf("mapped AAAA: got %v (len %d)", ip, len(ip))
	}
	if ip := recordIP(&v6); ip.String() != "2607:6bc0::10" {
		t.Errorf("AAAA: got %v", ip)
	}
	if ip := recordIP(&a); ip.String() != "160.79.104.10" {
		t.Errorf("A: got %v", ip)
	}
	if ip := recordIP(&cname); ip != nil {
		t.Errorf("CNAME: got %v, want nil", ip)
	}

	ips := appendIPs(nil, []net.IP{recordIP(&a), recordIP(&mapped)})
	ips = appendIPs(ips, []net.IP{net.ParseIP("160.79.104.10")})
	if len(ips) != 2 {
		t.Errorf("appendIPs kept duplicates: %v", ips)
	}
	inv := invertDNS(map[string][]net.IP{"openrouter.ai": {recordIP(&mapped)}})
	if got := inv["104.18.2.115"]; len(got) != 1 || got[0] != "openrouter.ai" {
		t.Errorf("invertDNS: got %v", inv)
	}
}
