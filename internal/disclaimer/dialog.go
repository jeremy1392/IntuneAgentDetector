package disclaimer

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modUser32                         = windows.NewLazySystemDLL("user32.dll")
	modGdi32                          = windows.NewLazySystemDLL("gdi32.dll")
	modKernel32                       = windows.NewLazySystemDLL("kernel32.dll")
	procMessageBox                    = modUser32.NewProc("MessageBoxW")
	procSetProcessDpiAwarenessContext = modUser32.NewProc("SetProcessDpiAwarenessContext")
	procCreateActCtx                  = modKernel32.NewProc("CreateActCtxW")
	procActivateActCtx                = modKernel32.NewProc("ActivateActCtx")
)

const (
	mbOK                     = 0x0000
	mbIconWarning            = 0x0030
	mbSystemModal            = 0x1000
	mbSetForeground          = 0x10000
	mbTopmost                = 0x40000
	idOK                     = 1
	actctxFlagResourceNameOK = 0x008
)

// ShowOptions tune Show.
type ShowOptions struct {
	// AutoAccept ticks the box and clicks the button after this delay. It
	// exists for the self-test only.
	AutoAccept time.Duration
	// AllowClose adds a close button (preview mode for administrators).
	AllowClose bool
}

// Result describes how the window ended.
type Result struct {
	Accepted bool
	Fallback bool     // a plain message box was used instead of the window
	Warnings []string // non-fatal problems, such as an unreadable logo
}

var showMu sync.Mutex

// Show displays the disclaimer window and blocks until the user accepts it.
func Show(c Content, opt ShowOptions) (Result, error) {
	showMu.Lock()
	defer showMu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	_ = windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED|windows.COINIT_DISABLE_OLE1DDE)
	setDPIAware()

	accepted, warnings, err := runWindow(c, opt)
	if err != nil {
		warnings = append(warnings, "disclaimer window unavailable, message box used: "+err.Error())
		ok, ferr := messageBox(c)
		return Result{Accepted: ok, Fallback: true, Warnings: warnings}, ferr
	}
	return Result{Accepted: accepted, Warnings: warnings}, nil
}

// openPolicy opens the AI policy: a web address or a local document.
func openPolicy(target string) {
	switch {
	case target == "":
		return
	case isWeb(target):
		shellOpen(target)
	default:
		if st, err := os.Stat(target); err == nil && !st.IsDir() {
			shellOpen(target)
		}
	}
}

// openMailto opens the default mail client.
func openMailto(u string) {
	if strings.HasPrefix(strings.ToLower(u), "mailto:") {
		shellOpen(u)
	}
}

func isWeb(s string) bool {
	l := strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(l, "https://") || strings.HasPrefix(l, "http://")
}

func shellOpen(target string) {
	verb, _ := windows.UTF16PtrFromString("open")
	file, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return
	}
	_ = windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL)
}

type actCtx struct {
	Size                  uint32
	Flags                 uint32
	Source                *uint16
	ProcessorArchitecture uint16
	LangID                uint16
	AssemblyDirectory     *uint16
	ResourceName          uintptr
	ApplicationName       *uint16
	Module                windows.Handle
}

var commonControlsOnce sync.Once

// activateCommonControlsV6 selects Common Controls v6 (themed controls and
// the SysLink link control). The embedded manifest normally does it; for a
// build without the manifest, the manifest that shell32.dll carries as
// resource 124 is activated instead.
func activateCommonControlsV6() {
	commonControlsOnce.Do(func() {
		if procCreateActCtx.Find() != nil || procActivateActCtx.Find() != nil {
			return
		}
		sys, err := windows.GetSystemDirectory()
		if err != nil {
			return
		}
		src, err := windows.UTF16PtrFromString(filepath.Join(sys, "shell32.dll"))
		if err != nil {
			return
		}
		ctx := actCtx{Flags: actctxFlagResourceNameOK, Source: src, ResourceName: 124}
		ctx.Size = uint32(unsafe.Sizeof(ctx))
		h, _, _ := procCreateActCtx.Call(uintptr(unsafe.Pointer(&ctx)))
		if h == 0 || h == ^uintptr(0) {
			return
		}
		var cookie uintptr
		_, _, _ = procActivateActCtx.Call(h, uintptr(unsafe.Pointer(&cookie)))
	})
}

func setDPIAware() {
	if procSetProcessDpiAwarenessContext.Find() == nil {
		const perMonitorAwareV2 = ^uintptr(3) // (DPI_AWARENESS_CONTEXT)-4
		_, _, _ = procSetProcessDpiAwarenessContext.Call(perMonitorAwareV2)
	}
}

// messageBox is the fallback when the window cannot be created: the user
// confirms with OK, which is logged as acceptance.
func messageBox(c Content) (bool, error) {
	if err := procMessageBox.Find(); err != nil {
		return false, errors.New("no dialog API available")
	}
	var b strings.Builder
	b.WriteString(c.Heading + "\n\n" + c.Text + "\n")
	if c.PolicyTarget != "" {
		b.WriteString("\n" + c.PolicyLabel + ": " + c.PolicyTarget)
	}
	if c.Email != "" {
		b.WriteString("\n" + c.ContactBefore + c.Email + c.ContactAfter)
	}
	b.WriteString("\n\nClick OK to confirm: " + c.Checkbox)
	t16, _ := windows.UTF16PtrFromString(strings.ReplaceAll(b.String(), "\x00", ""))
	c16, _ := windows.UTF16PtrFromString(c.Title)
	r, _, _ := procMessageBox.Call(0, uintptr(unsafe.Pointer(t16)), uintptr(unsafe.Pointer(c16)),
		mbOK|mbIconWarning|mbSystemModal|mbSetForeground|mbTopmost)
	return r == idOK, nil
}
