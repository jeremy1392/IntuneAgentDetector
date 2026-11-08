// Package scan collects raw facts about AI tools on the machine: processes,
// network connections, DNS cache, execution traces, installed software and
// configuration. It never modifies the machine.
package scan

import (
	"net"
	"time"

	"detectoragent/internal/model"
)

// Profile is a local user profile.
type Profile struct {
	SID        string
	User       string
	Home       string
	Roaming    string
	Local      string
	HiveLoaded bool
}

// EnvVar is an environment variable kept by the scanner. Value is empty for
// secrets: only the presence of an API key is recorded.
type EnvVar struct {
	Name  string
	Value string
}

// Process is a running process.
type Process struct {
	PID             uint32
	PPID            uint32
	Image           string
	Path            string
	Cmdline         string
	UserSID         string
	SessionID       uint32
	PackageFullName string
	PackageFamily   string
	Created         time.Time
	Denied          bool

	// Filled only for candidate processes.
	Product   string
	Company   string
	Signer    string
	Modules   []string
	Env       []EnvVar
	Inspected bool
}

// Conn is an established TCP connection.
type Conn struct {
	PID        uint32
	RemoteIP   net.IP
	RemotePort uint16
	LocalPort  uint16
}

// Listener is a listening TCP socket.
type Listener struct {
	PID  uint32
	Port uint16
	IP   net.IP
}

// Trace is an execution trace kept by Windows (BAM or Prefetch).
type Trace struct {
	Source  string // "bam" or "prefetch"
	UserSID string
	Path    string // full path for BAM, executable name for Prefetch
	Package string // package family name for BAM entries of packaged apps
	Time    time.Time
}

// ToolEvidence is evidence already attributed to a catalog tool.
type ToolEvidence struct {
	ToolID   string
	ToolName string // optional override of the tool name (browser extensions)
	UserSID  string // empty for machine-wide evidence
	Evidence model.Evidence
}

// EnvItem is an LLM-related environment variable found outside a process.
type EnvItem struct {
	Kind    string // "base-url", "api-key" or "tool-env"
	Var     string
	Host    string // host part of a base URL
	ToolID  string // for "tool-env"
	UserSID string // empty for machine-wide variables
	Scope   string // "machine" or "user"
}

// Snapshot is everything the scanner collected.
type Snapshot struct {
	StartedAt  time.Time
	RunAsSID   string
	RunAs      string
	Elevated   bool
	IsSystem   bool
	SessionID  uint32
	Profiles   []Profile
	Processes  map[uint32]*Process
	Children   map[uint32][]uint32
	Conns      []Conn
	Listeners  []Listener
	DNS        map[string][]net.IP // catalog-relevant host -> addresses
	IPToHosts  map[string][]string // address -> catalog-relevant hosts
	Traces     []Trace
	Inventory  []ToolEvidence
	EnvItems   []EnvItem
	Coverage   []string
	Errors     []string
	RecentDays int
}

// ProfileBySID returns the profile with this SID, or nil.
func (s *Snapshot) ProfileBySID(sid string) *Profile {
	for i := range s.Profiles {
		if s.Profiles[i].SID == sid {
			return &s.Profiles[i]
		}
	}
	return nil
}
