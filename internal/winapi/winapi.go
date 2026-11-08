// Package winapi holds small helpers about the current process identity.
package winapi

import (
	"golang.org/x/sys/windows"
)

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
