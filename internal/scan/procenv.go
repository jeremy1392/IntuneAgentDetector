package scan

import (
	"errors"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Offsets in the 64-bit PEB and RTL_USER_PROCESS_PARAMETERS structures.
const (
	pebProcessParametersOffset = 0x20
	paramsEnvironmentOffset    = 0x80
	paramsEnvironmentSize      = 0x3F0
	maxEnvironmentBytes        = 256 << 10
)

var errWow64 = errors.New("32-bit process: environment not read")

// readEnvironment reads the environment block of a 64-bit process and keeps
// only the variables accepted by keep. keep returns the value to store
// (empty to record presence only) and whether to keep the variable.
func readEnvironment(pid uint32, keep func(name, value string) (string, bool)) ([]EnvVar, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)

	var processMachine, nativeMachine uint16
	if windows.IsWow64Process2(h, &processMachine, &nativeMachine) == nil && processMachine != 0 {
		return nil, errWow64
	}

	var pbi windows.PROCESS_BASIC_INFORMATION
	if err := windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation,
		unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), nil); err != nil {
		return nil, err
	}
	peb := uintptr(unsafe.Pointer(pbi.PebBaseAddress))
	if peb == 0 {
		return nil, errors.New("no PEB")
	}
	params, err := readPointer(h, peb+pebProcessParametersOffset)
	if err != nil || params == 0 {
		return nil, errors.New("no process parameters")
	}
	envAddr, err := readPointer(h, params+paramsEnvironmentOffset)
	if err != nil || envAddr == 0 {
		return nil, errors.New("no environment")
	}
	size, err := readPointer(h, params+paramsEnvironmentSize)
	if err != nil || size == 0 || size > maxEnvironmentBytes {
		size = 32 << 10
	}

	buf := make([]uint16, size/2)
	var read uintptr
	err = windows.ReadProcessMemory(h, envAddr, (*byte)(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2), &read)
	if err != nil && read == 0 {
		return nil, err
	}
	return parseEnvironmentBlock(buf[:read/2], keep), nil
}

func readPointer(h windows.Handle, addr uintptr) (uintptr, error) {
	var v uintptr
	var n uintptr
	err := windows.ReadProcessMemory(h, addr, (*byte)(unsafe.Pointer(&v)), unsafe.Sizeof(v), &n)
	if err != nil || n != unsafe.Sizeof(v) {
		return 0, errors.New("read failed")
	}
	return v, nil
}

// parseEnvironmentBlock splits a NAME=VALUE\0...\0\0 block.
func parseEnvironmentBlock(block []uint16, keep func(name, value string) (string, bool)) []EnvVar {
	var out []EnvVar
	start := 0
	for i := 0; i < len(block); i++ {
		if block[i] != 0 {
			continue
		}
		if i == start {
			break // empty string: end of block
		}
		entry := windows.UTF16ToString(block[start:i])
		start = i + 1
		eq := strings.IndexByte(entry[1:], '=') // names may start with '='
		if eq < 0 {
			continue
		}
		name, value := entry[:eq+1], entry[eq+2:]
		if v, ok := keep(name, value); ok {
			out = append(out, EnvVar{Name: name, Value: v})
		}
	}
	return out
}
