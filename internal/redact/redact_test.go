package redact

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	cases := []struct{ in, mustNotContain string }{
		{`agent.py --api-key sk-proj-abcdefghijklmnopqrstuvwxyz123456`, "abcdefghijklmnop"},
		{`claude --token=sk-ant-api03-SECRETSECRETSECRET`, "SECRETSECRET"},
		{`set ANTHROPIC_API_KEY=sk-ant-xyzxyzxyzxyz && claude`, "xyzxyzxyz"},
		{`OPENAI_API_KEY="abc123def456ghi789" python run.py`, "abc123def456"},
		{`curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig" https://x`, "eyJhbGci"},
		{`gemini --key AIzaSyA-1234567890abcdefghijklmnop`, "1234567890abcdef"},
		{`git clone https://user:hunter2secret@github.com/org/repo`, "hunter2secret"},
		{`--password "my secret value"`, "my secret value"},
		{`export GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345`, "ABCDEFGHIJKLMNOP"},
		{`HF_TOKEN=hf_abcdefghijklmnopqrstuvwxyz`, "abcdefghijklmnopq"},
	}
	for _, c := range cases {
		out := String(c.in)
		if strings.Contains(out, c.mustNotContain) {
			t.Errorf("secret leaked:\n in: %s\nout: %s", c.in, out)
		}
	}
	plain := `"C:\Program Files\nodejs\node.exe" C:\Users\a\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\cli.js --model sonnet`
	if String(plain) != plain {
		t.Errorf("benign command line changed: %s", String(plain))
	}
}

func TestCommandLineTruncates(t *testing.T) {
	long := strings.Repeat("é", 400)
	out := CommandLine(long, 101)
	if len(out) > 104 || !strings.HasSuffix(out, "…") {
		t.Errorf("unexpected truncation: %d bytes", len(out))
	}
}
