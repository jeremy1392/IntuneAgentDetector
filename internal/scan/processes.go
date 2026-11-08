package scan

import (
	"errors"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procGetPackageFullName    = modKernel32.NewProc("GetPackageFullName")
	errNoPackage              = errors.New("process is not packaged")
	statusInfoLengthMismatch  = windows.NTStatus(0xC0000004)
	statusBufferTooSmall      = windows.NTStatus(0xC0000023)
	maxCommandLineBufferBytes = uint32(1 << 20)
)

// listProcesses snapshots the running processes and reads their path,
// command line, owner, session and package identity.
func listProcesses() (map[uint32]*Process, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	procs := make(map[uint32]*Process)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		p := &Process{
			PID:   pe.ProcessID,
			PPID:  pe.ParentProcessID,
			Image: windows.UTF16ToString(pe.ExeFile[:]),
		}
		procs[p.PID] = p
	}

	work := make(chan *Process)
	var wg sync.WaitGroup
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range work {
				fillProcess(p)
			}
		}()
	}
	for _, p := range procs {
		work <- p
	}
	close(work)
	wg.Wait()
	return procs, nil
}

func fillProcess(p *Process) {
	if p.PID == 0 || p.PID == 4 {
		return
	}
	_ = windows.ProcessIdToSessionId(p.PID, &p.SessionID)
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, p.PID)
	if err != nil {
		p.Denied = true
		return
	}
	defer windows.CloseHandle(h)

	p.Path = imagePath(h)
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &created, &exited, &kernel, &user) == nil {
		p.Created = time.Unix(0, created.Nanoseconds())
	}
	p.Cmdline = commandLine(h)
	var tok windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok) == nil {
		if tu, err := tok.GetTokenUser(); err == nil {
			p.UserSID = tu.User.Sid.String()
		}
		tok.Close()
	}
	if full, err := packageFullName(h); err == nil {
		p.PackageFullName = full
		p.PackageFamily = familyFromFullName(full)
	}
}

func imagePath(h windows.Handle) string {
	buf := make([]uint16, windows.MAX_PATH)
	for i := 0; i < 3; i++ {
		n := uint32(len(buf))
		err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n)
		if err == nil {
			return windows.UTF16ToString(buf[:n])
		}
		if err != windows.ERROR_INSUFFICIENT_BUFFER {
			return ""
		}
		buf = make([]uint16, len(buf)*4)
	}
	return ""
}

// commandLine reads the command line of a process opened with
// PROCESS_QUERY_LIMITED_INFORMATION (Windows 8.1 and later).
func commandLine(h windows.Handle) string {
	size := uint32(1024)
	for i := 0; i < 4; i++ {
		buf := make([]uint64, (size+7)/8) // 8-byte aligned for NTUnicodeString
		var ret uint32
		err := windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation,
			unsafe.Pointer(&buf[0]), uint32(len(buf)*8), &ret)
		if err == nil {
			us := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
			if us.Buffer == nil || us.Length == 0 {
				return ""
			}
			return windows.UTF16ToString(unsafe.Slice(us.Buffer, us.Length/2))
		}
		if (err == statusInfoLengthMismatch || err == statusBufferTooSmall) && ret > size && ret <= maxCommandLineBufferBytes {
			size = ret
			continue
		}
		return ""
	}
	return ""
}

func packageFullName(h windows.Handle) (string, error) {
	if err := procGetPackageFullName.Find(); err != nil {
		return "", err
	}
	n := uint32(256)
	buf := make([]uint16, n)
	r, _, _ := procGetPackageFullName.Call(uintptr(h), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&buf[0])))
	if r != 0 {
		return "", errNoPackage
	}
	return windows.UTF16ToString(buf), nil
}

// familyFromFullName turns Name_Version_Arch_ResourceId_PublisherId into
// the package family name Name_PublisherId.
func familyFromFullName(full string) string {
	parts := strings.Split(full, "_")
	if len(parts) < 5 {
		return ""
	}
	return parts[0] + "_" + parts[len(parts)-1]
}

// listModules returns the lower-cased names of the modules loaded by a process.
func listModules(pid uint32) []string {
	var snap windows.Handle
	var err error
	for i := 0; i < 3; i++ {
		snap, err = windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
		if err != windows.ERROR_BAD_LENGTH {
			break
		}
	}
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))
	var out []string
	for err = windows.Module32First(snap, &me); err == nil && len(out) < 4000; err = windows.Module32Next(snap, &me) {
		out = append(out, strings.ToLower(windows.UTF16ToString(me.Module[:])))
	}
	return out
}

// buildChildren indexes processes by parent PID, ignoring stale parents whose
// creation time is later than the child's (PID reuse).
func buildChildren(procs map[uint32]*Process) map[uint32][]uint32 {
	children := make(map[uint32][]uint32)
	for _, p := range procs {
		parent, ok := procs[p.PPID]
		if !ok || p.PPID == p.PID {
			continue
		}
		if !parent.Created.IsZero() && !p.Created.IsZero() && parent.Created.After(p.Created) {
			continue
		}
		children[p.PPID] = append(children[p.PPID], p.PID)
	}
	return children
}
