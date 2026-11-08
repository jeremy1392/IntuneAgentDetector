package scan

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"

	"detectoragent/internal/winapi"
)

const profileListKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

// listProfiles returns the real user profiles of the machine. Without
// elevation only the current user's profile is readable.
func listProfiles(elevated bool, currentSID string) ([]Profile, []string) {
	var notes []string
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, profileListKey, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return currentProfileOnly(currentSID), []string{"profile list unreadable: scanning the current profile only"}
	}
	defer k.Close()
	sids, _ := k.ReadSubKeyNames(-1)

	var out []Profile
	for _, sid := range sids {
		if !isUserSID(sid) {
			continue
		}
		if !elevated && !strings.EqualFold(sid, currentSID) {
			continue
		}
		sk, err := registry.OpenKey(k, sid, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		home, _, err := sk.GetStringValue("ProfileImagePath")
		sk.Close()
		if err != nil || home == "" {
			continue
		}
		home, _ = registry.ExpandString(home)
		if st, err := os.Stat(home); err != nil || !st.IsDir() {
			continue
		}
		out = append(out, newProfile(sid, home))
	}
	if !elevated {
		notes = append(notes, "not elevated: only the current user profile is scanned")
	}
	if len(out) == 0 {
		out = currentProfileOnly(currentSID)
	}
	return out, notes
}

func newProfile(sid, home string) Profile {
	p := Profile{
		SID:     sid,
		Home:    home,
		Roaming: filepath.Join(home, "AppData", "Roaming"),
		Local:   filepath.Join(home, "AppData", "Local"),
		User:    winapi.AccountNameFromString(sid),
	}
	if hk, err := registry.OpenKey(registry.USERS, sid, registry.QUERY_VALUE); err == nil {
		p.HiveLoaded = true
		hk.Close()
	}
	return p
}

func currentProfileOnly(sid string) []Profile {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}
	p := newProfile(sid, home)
	if v := os.Getenv("APPDATA"); v != "" {
		p.Roaming = v
	}
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		p.Local = v
	}
	return []Profile{p}
}

// isUserSID keeps local, domain (S-1-5-21-) and Entra ID (S-1-12-1-) accounts.
func isUserSID(sid string) bool {
	return strings.HasPrefix(sid, "S-1-5-21-") || strings.HasPrefix(sid, "S-1-12-1-")
}

// userKey opens a key under the user's hive: HKU\<sid> when the hive is loaded,
// or HKCU when the profile is the current user's.
func userKey(p *Profile, currentSID, path string, access uint32) (registry.Key, bool) {
	if p.HiveLoaded {
		if k, err := registry.OpenKey(registry.USERS, p.SID+`\`+path, access); err == nil {
			return k, true
		}
	}
	if strings.EqualFold(p.SID, currentSID) {
		if k, err := registry.OpenKey(registry.CURRENT_USER, path, access); err == nil {
			return k, true
		}
	}
	return 0, false
}
