package scan

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	tcpTableOwnerPIDAll = 5
	tcpStateListen      = 2
	tcpStateEstablished = 5
	afInet              = 2
	afInet6             = 23
	errInsufficientBuf  = 122
)

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type mibTCP6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPID     uint32
}

// tcpTable returns established connections and listening sockets with their
// owning process, for IPv4 and IPv6.
func tcpTable() ([]Conn, []Listener, error) {
	var conns []Conn
	var listeners []Listener

	b4, err := extendedTCPTable(afInet)
	if err != nil {
		return nil, nil, err
	}
	for _, r := range rows[mibTCPRowOwnerPID](b4) {
		local := ipv4(r.LocalAddr)
		switch r.State {
		case tcpStateEstablished:
			conns = append(conns, Conn{PID: r.OwningPID, RemoteIP: ipv4(r.RemoteAddr),
				RemotePort: port(r.RemotePort), LocalPort: port(r.LocalPort)})
		case tcpStateListen:
			listeners = append(listeners, Listener{PID: r.OwningPID, Port: port(r.LocalPort), IP: local})
		}
	}

	if b6, err := extendedTCPTable(afInet6); err == nil {
		for _, r := range rows[mibTCP6RowOwnerPID](b6) {
			switch r.State {
			case tcpStateEstablished:
				conns = append(conns, Conn{PID: r.OwningPID, RemoteIP: net.IP(append([]byte(nil), r.RemoteAddr[:]...)),
					RemotePort: port(r.RemotePort), LocalPort: port(r.LocalPort)})
			case tcpStateListen:
				listeners = append(listeners, Listener{PID: r.OwningPID, Port: port(r.LocalPort),
					IP: net.IP(append([]byte(nil), r.LocalAddr[:]...))})
			}
		}
	}
	return conns, listeners, nil
}

func extendedTCPTable(family uintptr) ([]byte, error) {
	if err := procGetExtendedTcpTable.Find(); err != nil {
		return nil, err
	}
	size := uint32(16 << 10)
	for i := 0; i < 5; i++ {
		buf := make([]byte, size)
		r, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)), 0, family, tcpTableOwnerPIDAll, 0)
		switch r {
		case 0:
			return buf[:size], nil
		case errInsufficientBuf:
			size += 4096
			continue
		default:
			return nil, windows.Errno(r)
		}
	}
	return nil, windows.ERROR_INSUFFICIENT_BUFFER
}

// rows decodes a MIB table: a DWORD count followed by fixed-size rows.
func rows[T any](buf []byte) []T {
	if len(buf) < 4 {
		return nil
	}
	n := int(*(*uint32)(unsafe.Pointer(&buf[0])))
	var zero T
	rowSize := int(unsafe.Sizeof(zero))
	if n <= 0 || 4+n*rowSize > len(buf) {
		return nil
	}
	out := make([]T, n)
	for i := 0; i < n; i++ {
		out[i] = *(*T)(unsafe.Pointer(&buf[4+i*rowSize]))
	}
	return out
}

func ipv4(a uint32) net.IP {
	return net.IPv4(byte(a), byte(a>>8), byte(a>>16), byte(a>>24)).To4()
}

func port(p uint32) uint16 {
	return uint16(p&0xff)<<8 | uint16(p>>8&0xff)
}

// isLoopback reports whether an address is a loopback address.
func isLoopback(ip net.IP) bool { return ip != nil && ip.IsLoopback() }
