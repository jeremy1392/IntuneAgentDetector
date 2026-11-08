package scan

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var bamRoots = []string{
	`SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`,
	`SYSTEM\CurrentControlSet\Services\bam\UserSettings`,
}

// executionTraces reads the Background Activity Moderator (last execution per
// executable and user) and the Prefetch folder. Both need administrator rights.
func executionTraces(since time.Time) ([]Trace, []string) {
	var out []Trace
	var notes []string

	bam, err := readBAM(since)
	if err != nil {
		notes = append(notes, "BAM execution traces unreadable (needs SYSTEM or administrator)")
	}
	out = append(out, bam...)

	pf, err := readPrefetch(since)
	if err != nil {
		notes = append(notes, "Prefetch unreadable (needs administrator) or disabled")
	}
	out = append(out, pf...)
	return out, notes
}

func readBAM(since time.Time) ([]Trace, error) {
	devices := dosDevices()
	var out []Trace
	var lastErr error
	opened := false
	for _, root := range bamRoots {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, root, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			lastErr = err
			continue
		}
		opened = true
		sids, _ := k.ReadSubKeyNames(-1)
		for _, sid := range sids {
			sk, err := registry.OpenKey(k, sid, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			names, _ := sk.ReadValueNames(-1)
			for _, name := range names {
				data, _, err := sk.GetBinaryValue(name)
				if err != nil || len(data) < 8 {
					continue
				}
				ft := windows.Filetime{
					LowDateTime:  binary.LittleEndian.Uint32(data[0:4]),
					HighDateTime: binary.LittleEndian.Uint32(data[4:8]),
				}
				t := time.Unix(0, ft.Nanoseconds())
				if t.Before(since) {
					continue
				}
				tr := Trace{Source: "bam", UserSID: sid, Time: t}
				if strings.Contains(name, `\`) {
					tr.Path = devicePathToDOS(name, devices)
				} else {
					tr.Package = name
				}
				out = append(out, tr)
			}
			sk.Close()
		}
		k.Close()
	}
	if !opened {
		return nil, lastErr
	}
	return out, nil
}

// dosDevices maps \Device\HarddiskVolumeN to drive letters.
func dosDevices() map[string]string {
	out := make(map[string]string)
	buf := make([]uint16, 1024)
	for c := 'A'; c <= 'Z'; c++ {
		drive := string(c) + ":"
		d16, _ := windows.UTF16PtrFromString(drive)
		n, err := windows.QueryDosDevice(d16, &buf[0], uint32(len(buf)))
		if err != nil || n == 0 {
			continue
		}
		target := windows.UTF16ToString(buf[:n])
		out[strings.ToLower(target)] = drive
	}
	return out
}

func devicePathToDOS(p string, devices map[string]string) string {
	lower := strings.ToLower(p)
	for dev, drive := range devices {
		if strings.HasPrefix(lower, dev+`\`) {
			return drive + p[len(dev):]
		}
	}
	return p
}

func readPrefetch(since time.Time) ([]Trace, error) {
	dir := filepath.Join(os.Getenv("SystemRoot"), "Prefetch")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Trace
	for _, e := range entries {
		name := e.Name()
		if !strings.EqualFold(filepath.Ext(name), ".pf") {
			continue
		}
		exe := prefetchExecutable(name)
		if exe == "" {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().Before(since) {
			continue
		}
		out = append(out, Trace{Source: "prefetch", Path: exe, Time: info.ModTime()})
	}
	return out, nil
}

// prefetchExecutable extracts "CLAUDE.EXE" from "CLAUDE.EXE-1A2B3C4D.pf".
func prefetchExecutable(file string) string {
	base := strings.TrimSuffix(file, filepath.Ext(file))
	i := strings.LastIndexByte(base, '-')
	if i <= 0 {
		return ""
	}
	return strings.ToLower(base[:i])
}
