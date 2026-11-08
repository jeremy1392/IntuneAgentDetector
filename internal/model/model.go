// Package model defines the data types shared by the scanner, the correlator
// and the reporters.
package model

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Level ranks how strongly a finding indicates actual use of a tool.
type Level int

// Levels, from weakest to strongest.
const (
	LevelUnknown Level = iota
	LevelResidue
	LevelInstalled
	LevelRecent
	LevelActive
)

var levelNames = map[Level]string{
	LevelUnknown:   "unknown",
	LevelResidue:   "residue",
	LevelInstalled: "installed",
	LevelRecent:    "recent",
	LevelActive:    "active",
}

func (l Level) String() string {
	if s, ok := levelNames[l]; ok {
		return s
	}
	return "unknown"
}

// ParseLevel converts a level name ("active", "recent", ...) to a Level.
func ParseLevel(s string) (Level, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	for l, name := range levelNames {
		if name == s && l != LevelUnknown {
			return l, nil
		}
	}
	return LevelUnknown, fmt.Errorf("unknown level %q", s)
}

// MarshalJSON encodes the level as its name.
func (l Level) MarshalJSON() ([]byte, error) { return json.Marshal(l.String()) }

// UnmarshalJSON decodes a level name.
func (l *Level) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseLevel(s)
	if err != nil {
		return err
	}
	*l = v
	return nil
}

// Confidence ranks how sure the scanner is that the evidence is genuine.
type Confidence int

// Confidence values, from weakest to strongest.
const (
	ConfidenceUnknown Confidence = iota
	ConfidenceLow
	ConfidenceMedium
	ConfidenceHigh
)

var confidenceNames = map[Confidence]string{
	ConfidenceUnknown: "unknown",
	ConfidenceLow:     "low",
	ConfidenceMedium:  "medium",
	ConfidenceHigh:    "high",
}

func (c Confidence) String() string {
	if s, ok := confidenceNames[c]; ok {
		return s
	}
	return "unknown"
}

// ParseConfidence converts a confidence name ("low", "medium", "high").
func ParseConfidence(s string) (Confidence, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	for c, name := range confidenceNames {
		if name == s && c != ConfidenceUnknown {
			return c, nil
		}
	}
	return ConfidenceUnknown, fmt.Errorf("unknown confidence %q", s)
}

// MarshalJSON encodes the confidence as its name.
func (c Confidence) MarshalJSON() ([]byte, error) { return json.Marshal(c.String()) }

// UnmarshalJSON decodes a confidence name.
func (c *Confidence) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseConfidence(s)
	if err != nil {
		return err
	}
	*c = v
	return nil
}

// Evidence is one observed fact supporting a finding.
type Evidence struct {
	Kind       string     `json:"kind"`
	Detail     string     `json:"detail"`
	Path       string     `json:"path,omitempty"`
	PID        uint32     `json:"pid,omitempty"`
	Cmdline    string     `json:"cmdline,omitempty"` // masked and truncated
	Time       *time.Time `json:"time,omitempty"`
	Level      Level      `json:"level"`
	Confidence Confidence `json:"confidence"`
}

// Finding groups the evidence about one tool for one user.
// An empty UserSID means the evidence is machine-wide.
type Finding struct {
	ToolID     string     `json:"tool_id"`
	ToolName   string     `json:"tool_name"`
	Vendor     string     `json:"vendor,omitempty"`
	Category   string     `json:"category"`
	Level      Level      `json:"level"`
	Confidence Confidence `json:"confidence"`
	Approved   bool       `json:"approved"`
	UserSID    string     `json:"user_sid,omitempty"`
	User       string     `json:"user,omitempty"`
	Evidence   []Evidence `json:"evidence"`
}

// Actionable reports whether the finding is an unapproved tool that is at
// least installed and detected with at least medium confidence.
func (f Finding) Actionable() bool {
	return !f.Approved && f.Level >= LevelInstalled && f.Confidence >= ConfidenceMedium
}

// Summary holds counters over the findings of a report.
type Summary struct {
	Findings    int `json:"findings"`
	NotApproved int `json:"not_approved"`
	Actionable  int `json:"actionable"`
	Active      int `json:"active"`
	Recent      int `json:"recent"`
	Installed   int `json:"installed"`
	Residue     int `json:"residue"`
}

// Report is the complete result of one scan.
type Report struct {
	Product        string    `json:"product"`
	Version        string    `json:"version"`
	CatalogVersion string    `json:"catalog_version"`
	Host           string    `json:"host"`
	RunAs          string    `json:"run_as"`
	Elevated       bool      `json:"elevated"`
	StartedAt      time.Time `json:"started_at"`
	DurationMs     int64     `json:"duration_ms"`
	RecentDays     int       `json:"recent_days"`
	Coverage       []string  `json:"coverage_notes,omitempty"`
	Summary        Summary   `json:"summary"`
	Findings       []Finding `json:"findings"`
	Errors         []string  `json:"errors,omitempty"`
}

// Summarize computes the summary counters from the findings.
func Summarize(findings []Finding) Summary {
	var s Summary
	s.Findings = len(findings)
	for _, f := range findings {
		if !f.Approved {
			s.NotApproved++
		}
		if f.Actionable() {
			s.Actionable++
		}
		switch f.Level {
		case LevelActive:
			s.Active++
		case LevelRecent:
			s.Recent++
		case LevelInstalled:
			s.Installed++
		case LevelResidue:
			s.Residue++
		}
	}
	return s
}
