// Package winapi holds small helpers about the current process identity.
package winapi

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetProcessMemoryInfo = windows.NewLazySystemDLL("kernel32.dll").NewProc("K32GetProcessMemoryInfo")

// processMemoryCounters mirrors PROCESS_MEMORY_COUNTERS.
type processMemoryCounters struct {
	cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

// ProcessStats returns the CPU time (user + kernel) used so far by the
// current process and its peak working set in bytes. Zero values mean the
// information is unavailable.
func ProcessStats() (cpu time.Duration, peakWorkingSet uint64) {
	h := windows.CurrentProcess()
	var creation, exit, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &creation, &exit, &kernel, &user) == nil {
		ticks := func(ft windows.Filetime) int64 { return int64(ft.HighDateTime)<<32 | int64(ft.LowDateTime) }
		cpu = time.Duration((ticks(kernel) + ticks(user)) * 100)
	}
	var pmc processMemoryCounters
	pmc.cb = uint32(unsafe.Sizeof(pmc))
	if r, _, _ := procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&pmc)), uintptr(pmc.cb)); r != 0 {
		peakWorkingSet = uint64(pmc.PeakWorkingSetSize)
	}
	return cpu, peakWorkingSet
}

// SystemSID is the well-known SID of the LocalSystem account.
const SystemSID = "S-1-5-18"

// Identity describes the account and session the scanner runs in.
type Identity struct {
	SID       string
	Account   string
	Elevated  bool
	SessionID uint32
}

// IsSystem reports whether the process runs as LocalSystem.
func (i Identity) IsSystem() bool { return i.SID == SystemSID }

// Current returns the identity of the running process.
func Current() Identity {
	var id Identity
	tok := windows.GetCurrentProcessToken()
	id.Elevated = tok.IsElevated()
	if tu, err := tok.GetTokenUser(); err == nil {
		id.SID = tu.User.Sid.String()
		id.Account = AccountName(tu.User.Sid)
	}
	_ = windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &id.SessionID)
	return id
}

// AccountName resolves a SID to DOMAIN\user, or returns "" if unknown.
func AccountName(sid *windows.SID) string {
	if sid == nil {
		return ""
	}
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return ""
	}
	if domain == "" {
		return account
	}
	return domain + `\` + account
}

// AccountNameFromString resolves a SID string to DOMAIN\user.
func AccountNameFromString(s string) string {
	sid, err := windows.StringToSid(s)
	if err != nil {
		return ""
	}
	return AccountName(sid)
}
