package disclaimer

import (
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"detectoragent/internal/scan"
	"detectoragent/internal/winapi"
)

const wtsActive = 0

// Session is an active interactive session and its user token. Call Close
// when done.
type Session struct {
	ID    uint32
	SID   string
	User  string
	token windows.Token
}

// Close releases the user token.
func (s *Session) Close() { _ = s.token.Close() }

// ActiveSessions lists the active interactive sessions. It requires the
// SeTcbPrivilege, held by LocalSystem.
func ActiveSessions() ([]Session, error) {
	var infos *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &infos, &count); err != nil {
		return nil, err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(infos)))
	var out []Session
	for _, si := range unsafe.Slice(infos, count) {
		if si.State != wtsActive {
			continue
		}
		var tok windows.Token
		if err := windows.WTSQueryUserToken(si.SessionID, &tok); err != nil {
			continue
		}
		tu, err := tok.GetTokenUser()
		if err != nil {
			tok.Close()
			continue
		}
		out = append(out, Session{ID: si.SessionID, SID: tu.User.Sid.String(),
			User: winapi.AccountName(tu.User.Sid), token: tok})
	}
	return out, nil
}

// RunningInSession reports whether a disclaimer process of this executable
// is already running in the session.
func RunningInSession(procs map[uint32]*scan.Process, exePath string, session uint32) bool {
	exe := strings.ToLower(filepath.Base(exePath))
	for _, p := range procs {
		if p.SessionID != session || strings.ToLower(p.Image) != exe {
			continue
		}
		if strings.Contains(strings.ToLower(p.Cmdline), " disclaimer") {
			return true
		}
	}
	return false
}

// LaunchInSession starts exe with args on the user's interactive desktop,
// under the user's identity, without a console window.
func (s *Session) LaunchInSession(exe string, args []string) error {
	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, s.token, false); err != nil {
		return err
	}
	defer windows.DestroyEnvironmentBlock(env)

	cmd := windows.ComposeCommandLine(append([]string{exe}, args...))
	cmd16, err := windows.UTF16PtrFromString(cmd)
	if err != nil {
		return err
	}
	exe16, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	dir16, err := windows.UTF16PtrFromString(filepath.Dir(exe))
	if err != nil {
		return err
	}
	desktop, err := windows.UTF16PtrFromString(`winsta0\default`)
	if err != nil {
		return err
	}
	si := windows.StartupInfo{Desktop: desktop}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	err = windows.CreateProcessAsUser(s.token, exe16, cmd16, nil, nil, false,
		windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW, env, dir16, &si, &pi)
	if err != nil {
		return err
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	return nil
}
