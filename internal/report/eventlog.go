package report

import (
	"encoding/json"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/eventlog"

	"detectoragent/internal/model"
	"detectoragent/internal/redact"
)

// Event Log source and event ids (EventCreate.exe message file: ids 1-1000).
const (
	Source                  = "DetectorAgent"
	EventScanSummary        = 100
	EventFinding            = 300
	EventDisclaimerShown    = 400
	EventDisclaimerAccepted = 410
	EventError              = 900

	maxEventMessage = 30000
)

// EventLog writes JSON messages to the Application log.
type EventLog struct {
	l *eventlog.Log
}

// OpenEventLog opens the Application log with the DetectorAgent source. If
// the source is not registered, Windows still records the message.
func OpenEventLog() (*EventLog, error) {
	l, err := eventlog.Open(Source)
	if err != nil {
		return nil, err
	}
	return &EventLog{l: l}, nil
}

// Close releases the log handle.
func (e *EventLog) Close() {
	if e != nil && e.l != nil {
		_ = e.l.Close()
	}
}

type findingRef struct {
	ToolID     string           `json:"tool_id"`
	ToolName   string           `json:"tool_name"`
	Category   string           `json:"category"`
	Level      model.Level      `json:"level"`
	Confidence model.Confidence `json:"confidence"`
	Approved   bool             `json:"approved"`
	User       string           `json:"user,omitempty"`
}

// Summary writes event 100 with the counters and a compact list of findings.
func (e *EventLog) Summary(r *model.Report) error {
	refs := make([]findingRef, 0, len(r.Findings))
	for _, f := range r.Findings {
		refs = append(refs, findingRef{f.ToolID, f.ToolName, f.Category, f.Level, f.Confidence, f.Approved, f.User})
	}
	msg := map[string]any{
		"event":           "scan_summary",
		"product":         r.Product,
		"version":         r.Version,
		"catalog_version": r.CatalogVersion,
		"host":            r.Host,
		"run_as":          r.RunAs,
		"elevated":        r.Elevated,
		"started_at":      r.StartedAt,
		"duration_ms":     r.DurationMs,
		"summary":         r.Summary,
		"findings":        refs,
		"coverage_notes":  r.Coverage,
		"errors":          r.Errors,
	}
	return e.write(EventScanSummary, r.Summary.Actionable > 0, msg)
}

// Finding writes event 300 for one finding.
func (e *EventLog) Finding(host string, f model.Finding) error {
	msg := map[string]any{"event": "finding", "host": host, "finding": f}
	return e.write(EventFinding, f.Actionable(), msg)
}

// DisclaimerShown writes event 400.
func (e *EventLog) DisclaimerShown(host, userSID, user string, session uint32, version int, tools []string) error {
	msg := map[string]any{"event": "disclaimer_shown", "host": host, "user_sid": userSID, "user": user,
		"session_id": session, "disclaimer_version": version, "tools": tools}
	return e.write(EventDisclaimerShown, false, msg)
}

// DisclaimerAccepted writes event 410. It runs under the user's identity, so
// Windows records the user's SID in the event itself.
func (e *EventLog) DisclaimerAccepted(host, user string, version int, tools []string, at time.Time) error {
	msg := map[string]any{"event": "disclaimer_accepted", "host": host, "user": user,
		"disclaimer_version": version, "tools": tools, "accepted_at": at}
	return e.write(EventDisclaimerAccepted, false, msg)
}

// Error writes event 900.
func (e *EventLog) Error(host, message string) error {
	return e.writeRaw(EventError, "error", map[string]any{"event": "error", "host": host, "message": redact.String(message)})
}

func (e *EventLog) write(id uint32, warning bool, msg map[string]any) error {
	level := "info"
	if warning {
		level = "warning"
	}
	return e.writeRaw(id, level, msg)
}

func (e *EventLog) writeRaw(id uint32, level string, msg map[string]any) error {
	if e == nil || e.l == nil {
		return nil
	}
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	s := redact.String(string(b))
	if len(s) > maxEventMessage {
		s = s[:maxEventMessage] + `…"truncated"`
	}
	etype := uint16(windows.EVENTLOG_INFORMATION_TYPE)
	switch level {
	case "error":
		etype = windows.EVENTLOG_ERROR_TYPE
	case "warning":
		etype = windows.EVENTLOG_WARNING_TYPE
	}
	s16, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return err
	}
	strs := []*uint16{s16}
	// Record the SID of the account that writes the event: SYSTEM for the
	// scan, the user for the disclaimer acceptance (event 410).
	var sid uintptr
	if tu, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil {
		sid = uintptr(unsafe.Pointer(tu.User.Sid))
		defer runtime.KeepAlive(tu)
	}
	return windows.ReportEvent(e.l.Handle, etype, 0, id, sid, 1, 0, &strs[0], nil)
}
