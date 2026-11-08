package disclaimer

import (
	"errors"
	"fmt"
	"image/color"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procRegisterClassExW             = modUser32.NewProc("RegisterClassExW")
	procCreateWindowExW              = modUser32.NewProc("CreateWindowExW")
	procDefWindowProcW               = modUser32.NewProc("DefWindowProcW")
	procDestroyWindow                = modUser32.NewProc("DestroyWindow")
	procShowWindow                   = modUser32.NewProc("ShowWindow")
	procUpdateWindow                 = modUser32.NewProc("UpdateWindow")
	procSetForegroundWindow          = modUser32.NewProc("SetForegroundWindow")
	procGetMessageW                  = modUser32.NewProc("GetMessageW")
	procTranslateMessage             = modUser32.NewProc("TranslateMessage")
	procDispatchMessageW             = modUser32.NewProc("DispatchMessageW")
	procIsDialogMessageW             = modUser32.NewProc("IsDialogMessageW")
	procPostQuitMessage              = modUser32.NewProc("PostQuitMessage")
	procSendMessageW                 = modUser32.NewProc("SendMessageW")
	procEnableWindow                 = modUser32.NewProc("EnableWindow")
	procSetFocus                     = modUser32.NewProc("SetFocus")
	procLoadCursorW                  = modUser32.NewProc("LoadCursorW")
	procSetTimer                     = modUser32.NewProc("SetTimer")
	procKillTimer                    = modUser32.NewProc("KillTimer")
	procSystemParametersInfoW        = modUser32.NewProc("SystemParametersInfoW")
	procGetDpiForSystem              = modUser32.NewProc("GetDpiForSystem")
	procSetThreadDpiAwarenessContext = modUser32.NewProc("SetThreadDpiAwarenessContext")
	procAdjustWindowRectEx           = modUser32.NewProc("AdjustWindowRectEx")
	procGetDC                        = modUser32.NewProc("GetDC")
	procReleaseDC                    = modUser32.NewProc("ReleaseDC")
	procDrawTextW                    = modUser32.NewProc("DrawTextW")
	procGetSysColor                  = modUser32.NewProc("GetSysColor")
	procGetSysColorBrush             = modUser32.NewProc("GetSysColorBrush")
	procGetSystemMetrics             = modUser32.NewProc("GetSystemMetrics")
	procCreateFontIndirectW          = modGdi32.NewProc("CreateFontIndirectW")
	procDeleteObject                 = modGdi32.NewProc("DeleteObject")
	procSelectObject                 = modGdi32.NewProc("SelectObject")
	procSetTextColor                 = modGdi32.NewProc("SetTextColor")
	procSetBkColor                   = modGdi32.NewProc("SetBkColor")
	procGetModuleHandleW             = modKernel32.NewProc("GetModuleHandleW")
)

// Win32 constants.
const (
	wsPopup        = 0x80000000
	wsCaption      = 0x00C00000
	wsSysMenu      = 0x00080000
	wsClipChildren = 0x02000000
	wsChild        = 0x40000000
	wsVisible      = 0x10000000
	wsDisabled     = 0x08000000
	wsTabStop      = 0x00010000
	wsGroup        = 0x00020000
	wsVScroll      = 0x00200000

	wsExDlgModalFrame = 0x00000001
	wsExTopmost       = 0x00000008
	wsExControlParent = 0x00010000
	wsExAppWindow     = 0x00040000

	ssNoPrefix     = 0x0080
	ssBitmap       = 0x000E
	ssEtchedHorz   = 0x0010
	esMultiline    = 0x0004
	esAutoVScroll  = 0x0040
	esReadOnly     = 0x0800
	bsDefPush      = 0x0001
	bsAutoCheck    = 0x0003
	bsMultiline    = 0x2000
	lwsTransparent = 0x0001

	wmDestroy         = 0x0002
	wmClose           = 0x0010
	wmSetFont         = 0x0030
	wmNotify          = 0x004E
	wmCommand         = 0x0111
	wmTimer           = 0x0113
	wmCtlColorStatic  = 0x0138
	bmGetCheck        = 0x00F0
	bmClick           = 0x00F5
	bstChecked        = 1
	bnClicked         = 0
	stmSetImage       = 0x0172
	imageBitmap       = 0
	dmGetDefID        = 0x0400
	dcHasDefID        = 0x534B
	swShowNormal      = 1
	idcArrow          = 32512
	colorWindow       = 5
	colorWindowText   = 8
	dtWordBreak       = 0x0010
	dtSingleLine      = 0x0020
	dtCalcRect        = 0x0400
	dtNoPrefix        = 0x0800
	dtEditControl     = 0x2000
	spiGetWorkArea    = 0x0030
	spiGetNCMetrics   = 0x0029
	smCxVScroll       = 2
	iccStandard       = 0x4000
	iccLink           = 0x8000
	nmClick           = 0xFFFFFFFE // NM_CLICK (-2)
	nmReturn          = 0xFFFFFFFC // NM_RETURN (-4)
	timerAutoAccept   = 1
	headingColor      = 0x00993300  // COLORREF of RGB(0, 51, 153)
	systemAwareCtx    = ^uintptr(1) // DPI_AWARENESS_CONTEXT_SYSTEM_AWARE (-2)
	windowClassName   = "DetectorAgentDisclaimer"
	contentWidthDIP   = 540
	marginDIP         = 22
	logoMaxHeightDIP  = 80
	textMaxHeightDIP  = 300
	buttonHeightDIP   = 32
	buttonMinWidthDIP = 110
)

// Control ids.
const (
	idLogo = 100 + iota
	idHeading
	idText
	idSeparator
	idCheckbox
	idAccept
	idLink
)

type rect struct{ Left, Top, Right, Bottom int32 }

type point struct{ X, Y int32 }

type msg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
	Private uint32
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

type logFont struct {
	Height         int32
	Width          int32
	Escapement     int32
	Orientation    int32
	Weight         int32
	Italic         byte
	Underline      byte
	StrikeOut      byte
	CharSet        byte
	OutPrecision   byte
	ClipPrecision  byte
	Quality        byte
	PitchAndFamily byte
	FaceName       [32]uint16
}

type nonClientMetrics struct {
	Size            uint32
	BorderWidth     int32
	ScrollWidth     int32
	ScrollHeight    int32
	CaptionWidth    int32
	CaptionHeight   int32
	CaptionFont     logFont
	SmCaptionWidth  int32
	SmCaptionHeight int32
	SmCaptionFont   logFont
	MenuWidth       int32
	MenuHeight      int32
	MenuFont        logFont
	StatusFont      logFont
	MessageFont     logFont
	PaddedBorder    int32
}

type nmhdr struct {
	HwndFrom uintptr
	IDFrom   uintptr
	Code     uint32
}

type litem struct {
	Mask      uint32
	Link      int32
	State     uint32
	StateMask uint32
	ID        [48]uint16
	URL       [2083]uint16
}

type nmLink struct {
	Hdr  nmhdr
	Item litem
}

type initCommonControlsEx struct {
	Size uint32
	ICC  uint32
}

// state of the one window a process shows.
var win struct {
	hwnd, heading, checkbox, accept uintptr
	brush                           uintptr
	checked, accepted, allowClose   bool
	content                         Content
}

var (
	classOnce sync.Once
	classErr  error
)

func call(p *windows.LazyProc, args ...uintptr) uintptr {
	r, _, _ := p.Call(args...)
	return r
}

func u16(s string) *uint16 {
	p, err := windows.UTF16PtrFromString(strings.ReplaceAll(s, "\x00", ""))
	if err != nil {
		p, _ = windows.UTF16PtrFromString("")
	}
	return p
}

func ptr(p *uint16) uintptr { return uintptr(unsafe.Pointer(p)) }

// runWindow creates the disclaimer window and runs its message loop until
// the user accepts. It returns non-fatal warnings (logo problems).
func runWindow(c Content, opt ShowOptions) (bool, []string, error) {
	var warnings []string
	for _, p := range []*windows.LazyProc{procRegisterClassExW, procCreateWindowExW, procIsDialogMessageW, procDrawTextW} {
		if err := p.Find(); err != nil {
			return false, nil, err
		}
	}
	activateCommonControlsV6()
	if err := initControls(); err != nil {
		return false, nil, err
	}
	// System-DPI awareness: Windows rescales the window if it is moved to a
	// monitor with another DPI, so the layout below stays correct.
	if procSetThreadDpiAwarenessContext.Find() == nil {
		call(procSetThreadDpiAwarenessContext, systemAwareCtx)
	}
	dpi := 96
	if procGetDpiForSystem.Find() == nil {
		if d := int(call(procGetDpiForSystem)); d > 0 {
			dpi = d
		}
	}
	s := func(v int) int { return v * dpi / 96 }

	instance := call(procGetModuleHandleW, 0)
	classOnce.Do(func() { classErr = registerClass(instance) })
	if classErr != nil {
		return false, nil, classErr
	}

	bodyFont, headingFont := createFonts(dpi)
	defer call(procDeleteObject, bodyFont)
	defer call(procDeleteObject, headingFont)

	win.content, win.checked, win.accepted, win.allowClose = c, false, false, opt.AllowClose
	win.brush = call(procGetSysColorBrush, colorWindow)

	// ---- layout (client coordinates, pixels)
	margin, width := s(marginDIP), s(contentWidthDIP)
	y := margin

	var logo uintptr
	var logoW, logoH int
	if c.LogoPath != "" {
		bgRef := uint32(call(procGetSysColor, colorWindow))
		bg := color.NRGBA{R: uint8(bgRef), G: uint8(bgRef >> 8), B: uint8(bgRef >> 16), A: 255}
		var err error
		logo, logoW, logoH, err = logoBitmap(c.LogoPath, width, s(logoMaxHeightDIP), float64(dpi)/96, bg)
		if err != nil {
			warnings = append(warnings, err.Error())
			logo = 0
		}
	}
	if logo != 0 {
		defer call(procDeleteObject, logo)
	}
	logoY := y
	if logo != 0 {
		y += logoH + s(14)
	}

	headingH := measure(headingFont, c.Heading, width, false)
	headingY := y
	y += headingH + s(10)

	text := strings.ReplaceAll(strings.ReplaceAll(c.Text, "\r\n", "\n"), "\n", "\r\n")
	scrollW := int(call(procGetSystemMetrics, smCxVScroll))
	textH := measure(bodyFont, text, width-scrollW-s(8), false) + s(6)
	textStyle := uintptr(wsChild | wsVisible | esMultiline | esReadOnly | esAutoVScroll | wsTabStop)
	if textH > s(textMaxHeightDIP) {
		textH = s(textMaxHeightDIP)
		textStyle |= wsVScroll
	}
	textY := y
	y += textH + s(14)

	sepY := y
	y += s(14)

	buttonW := max(measureWidth(bodyFont, c.Button)+s(36), s(buttonMinWidthDIP))
	buttonH := s(buttonHeightDIP)
	checkW := width - buttonW - s(16)
	checkH := max(measure(bodyFont, c.Checkbox, checkW-s(24), false), s(20))
	rowH := max(checkH, buttonH)
	rowY := y
	y += rowH + s(16)

	markup, plain := c.FooterMarkup()
	linkY, linkH := y, 0
	if plain != "" {
		linkH = measure(bodyFont, plain, width, false) + s(4)
		y += linkH + s(4)
	}
	clientW, clientH := width+2*margin, y+margin-s(4)

	// ---- window
	style := uintptr(wsPopup | wsCaption | wsClipChildren)
	if opt.AllowClose {
		style |= wsSysMenu
	}
	exStyle := uintptr(wsExDlgModalFrame | wsExTopmost | wsExControlParent | wsExAppWindow)
	r := rect{0, 0, int32(clientW), int32(clientH)}
	call(procAdjustWindowRectEx, uintptr(unsafe.Pointer(&r)), style, 0, exStyle)
	winW, winH := int(r.Right-r.Left), int(r.Bottom-r.Top)
	var work rect
	call(procSystemParametersInfoW, spiGetWorkArea, 0, uintptr(unsafe.Pointer(&work)), 0)
	x0 := int(work.Left) + (int(work.Right-work.Left)-winW)/2
	y0 := max(int(work.Top)+(int(work.Bottom-work.Top)-winH)/2, int(work.Top))

	hwnd := call(procCreateWindowExW, exStyle, ptr(u16(windowClassName)), ptr(u16(c.Title)), style,
		uintptr(x0), uintptr(y0), uintptr(winW), uintptr(winH), 0, 0, instance, 0)
	if hwnd == 0 {
		return false, warnings, errors.New("CreateWindowEx failed")
	}
	win.hwnd = hwnd

	child := func(class, text string, style uintptr, x, y, w, h, id int, font uintptr) uintptr {
		hc := call(procCreateWindowExW, 0, ptr(u16(class)), ptr(u16(text)), style,
			uintptr(x), uintptr(y), uintptr(w), uintptr(h), hwnd, uintptr(id), instance, 0)
		if hc != 0 && font != 0 {
			call(procSendMessageW, hc, wmSetFont, font, 1)
		}
		return hc
	}
	if logo != 0 {
		lc := child("STATIC", "", wsChild|wsVisible|ssBitmap, margin, logoY, logoW, logoH, idLogo, 0)
		call(procSendMessageW, lc, stmSetImage, imageBitmap, logo)
	}
	win.heading = child("STATIC", c.Heading, wsChild|wsVisible|ssNoPrefix, margin, headingY, width, headingH, idHeading, headingFont)
	child("EDIT", text, textStyle, margin, textY, width, textH, idText, bodyFont)
	child("STATIC", "", wsChild|wsVisible|ssEtchedHorz, margin, sepY, width, 2, idSeparator, 0)
	win.checkbox = child("BUTTON", c.Checkbox, wsChild|wsVisible|wsTabStop|wsGroup|bsAutoCheck|bsMultiline,
		margin, rowY+(rowH-checkH)/2, checkW, checkH, idCheckbox, bodyFont)
	win.accept = child("BUTTON", c.Button, wsChild|wsVisible|wsTabStop|wsDisabled|bsDefPush,
		margin+width-buttonW, rowY+(rowH-buttonH)/2, buttonW, buttonH, idAccept, bodyFont)
	if markup != "" {
		child("SysLink", markup, wsChild|wsVisible|wsTabStop|lwsTransparent, margin, linkY, width, linkH, idLink, bodyFont)
	}

	// The first ShowWindow call of a process takes the show state of its
	// STARTUPINFO, which may be "hidden": spend it, then really show.
	call(procShowWindow, hwnd, swShowNormal)
	call(procShowWindow, hwnd, swShowNormal)
	call(procUpdateWindow, hwnd)
	call(procSetForegroundWindow, hwnd)
	call(procSetFocus, win.checkbox)
	if opt.AutoAccept > 0 {
		call(procSetTimer, hwnd, timerAutoAccept, uintptr(opt.AutoAccept.Milliseconds()), 0)
	}

	var m msg
	for {
		r := int32(call(procGetMessageW, uintptr(unsafe.Pointer(&m)), 0, 0, 0))
		if r == 0 || r == -1 {
			break
		}
		if call(procIsDialogMessageW, hwnd, uintptr(unsafe.Pointer(&m))) != 0 {
			continue
		}
		call(procTranslateMessage, uintptr(unsafe.Pointer(&m)))
		call(procDispatchMessageW, uintptr(unsafe.Pointer(&m)))
	}
	win.hwnd = 0
	return win.accepted, warnings, nil
}

func registerClass(instance uintptr) error {
	wc := wndClassEx{
		WndProc:    syscall.NewCallback(windowProc),
		Instance:   instance,
		Cursor:     call(procLoadCursorW, 0, idcArrow),
		Background: call(procGetSysColorBrush, colorWindow),
		ClassName:  u16(windowClassName),
	}
	wc.Size = uint32(unsafe.Sizeof(wc))
	if r, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return fmt.Errorf("RegisterClassEx: %v", err)
	}
	return nil
}

// initControls loads Common Controls (v6 after activation) for SysLink.
func initControls() error {
	h, err := windows.LoadLibrary("comctl32.dll")
	if err != nil {
		return err
	}
	addr, err := windows.GetProcAddress(h, "InitCommonControlsEx")
	if err != nil {
		return err
	}
	icc := initCommonControlsEx{ICC: iccStandard | iccLink}
	icc.Size = uint32(unsafe.Sizeof(icc))
	if r, _, _ := syscall.SyscallN(addr, uintptr(unsafe.Pointer(&icc))); r == 0 {
		return errors.New("InitCommonControlsEx failed")
	}
	return nil
}

// createFonts returns the system message font and a larger semibold heading font.
func createFonts(dpi int) (body, heading uintptr) {
	var ncm nonClientMetrics
	ncm.Size = uint32(unsafe.Sizeof(ncm))
	lf := logFont{Height: -int32(12 * dpi / 72), Weight: 400}
	copy(lf.FaceName[:], windows.StringToUTF16("Segoe UI"))
	if call(procSystemParametersInfoW, spiGetNCMetrics, uintptr(ncm.Size), uintptr(unsafe.Pointer(&ncm)), 0) != 0 {
		lf = ncm.MessageFont
	}
	body = call(procCreateFontIndirectW, uintptr(unsafe.Pointer(&lf)))
	h := lf
	h.Height = h.Height * 3 / 2
	h.Weight = 600
	heading = call(procCreateFontIndirectW, uintptr(unsafe.Pointer(&h)))
	return body, heading
}

// measure returns the height of a text wrapped at width pixels.
func measure(font uintptr, text string, width int, single bool) int {
	r := measureRect(font, text, width, single)
	return int(r.Bottom - r.Top)
}

// measureWidth returns the width of a single-line text.
func measureWidth(font uintptr, text string) int {
	r := measureRect(font, text, 0, true)
	return int(r.Right - r.Left)
}

func measureRect(font uintptr, text string, width int, single bool) rect {
	hdc := call(procGetDC, 0)
	defer call(procReleaseDC, 0, hdc)
	old := call(procSelectObject, hdc, font)
	defer call(procSelectObject, hdc, old)
	r := rect{0, 0, int32(width), 0}
	flags := uintptr(dtCalcRect | dtNoPrefix)
	if single {
		flags |= dtSingleLine
	} else {
		flags |= dtWordBreak | dtEditControl
	}
	if text == "" {
		text = " "
	}
	call(procDrawTextW, hdc, ptr(u16(text)), ^uintptr(0), uintptr(unsafe.Pointer(&r)), flags)
	return r
}

func windowProc(hwnd, message, wParam, lParam uintptr) uintptr {
	switch message {
	case wmCommand:
		id, code := wParam&0xFFFF, (wParam>>16)&0xFFFF
		if code == bnClicked {
			switch id {
			case idCheckbox:
				win.checked = call(procSendMessageW, win.checkbox, bmGetCheck, 0, 0) == bstChecked
				enable := uintptr(0)
				if win.checked {
					enable = 1
				}
				call(procEnableWindow, win.accept, enable)
			case idAccept:
				if win.checked {
					win.accepted = true
					call(procDestroyWindow, hwnd)
				}
			}
		}
		return 0
	case wmNotify:
		link := (*nmLink)(ptrFrom(lParam))
		if link.Hdr.IDFrom == idLink && (link.Hdr.Code == nmClick || link.Hdr.Code == nmReturn) {
			switch windows.UTF16ToString(link.Item.ID[:]) {
			case "policy":
				openPolicy(win.content.PolicyTarget)
			case "email":
				openMailto(win.content.MailtoURL)
			}
		}
		return 0
	case wmCtlColorStatic:
		call(procSetBkColor, wParam, call(procGetSysColor, colorWindow))
		if lParam == win.heading {
			call(procSetTextColor, wParam, headingColor)
		} else {
			call(procSetTextColor, wParam, call(procGetSysColor, colorWindowText))
		}
		return win.brush
	case dmGetDefID:
		if win.checked {
			return dcHasDefID<<16 | idAccept
		}
		return 0
	case wmTimer:
		if wParam == timerAutoAccept {
			call(procKillTimer, hwnd, timerAutoAccept)
			call(procSendMessageW, win.checkbox, bmClick, 0, 0)
			call(procSendMessageW, win.accept, bmClick, 0, 0)
		}
		return 0
	case wmClose:
		if win.allowClose {
			call(procDestroyWindow, hwnd)
		}
		return 0 // otherwise the window only closes through the accept button
	case wmDestroy:
		call(procPostQuitMessage, 0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, message, wParam, lParam)
	return r
}
