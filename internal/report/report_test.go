package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"detectoragent/internal/model"
)

func sampleReport() *model.Report {
	return &model.Report{
		Product: "detectorAgent", Version: "test", Host: "PC1", RunAs: `NT AUTHORITY\SYSTEM`,
		StartedAt: time.Unix(1_700_000_000, 0).UTC(),
		Findings: []model.Finding{{
			ToolID: "probable-agent:python.exe", ToolName: "Probable custom AI agent (python.exe)",
			Category: "custom-agent", Level: model.LevelActive, Confidence: model.ConfidenceMedium,
			Evidence: []model.Evidence{{Kind: "behavior", Detail: "python.exe runs cmd.exe",
				Cmdline: `python.exe agent.py --api-key sk-proj-ZZZZZZZZZZZZZZZZZZZZZZZZ`,
				Level:   model.LevelActive, Confidence: model.ConfidenceMedium}},
		}},
		Errors: []string{"network: token=abcdefgh12345678"},
	}
}

func TestSanitizeAndJSON(t *testing.T) {
	r := sampleReport()
	r.Summary = model.Summarize(r.Findings)
	Sanitize(r)
	var buf bytes.Buffer
	if err := WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "ZZZZZZZZZZZZ") || strings.Contains(out, "abcdefgh12345678") {
		t.Errorf("secret leaked in JSON:\n%s", out)
	}
	var back model.Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("JSON does not round-trip: %v", err)
	}
	if back.Findings[0].Level != model.LevelActive || back.Findings[0].Confidence != model.ConfidenceMedium {
		t.Errorf("levels lost in round trip: %+v", back.Findings[0])
	}
	if back.Summary.Actionable != 1 {
		t.Errorf("summary not encoded: %+v", back.Summary)
	}
}

func TestWriteText(t *testing.T) {
	r := sampleReport()
	r.Summary = model.Summarize(r.Findings)
	var buf bytes.Buffer
	if err := WriteText(&buf, r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"LEVEL", "Probable custom AI agent (python.exe)", "behavior: python.exe runs cmd.exe", "(machine)"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("text output lacks %q:\n%s", want, buf.String())
		}
	}
}
