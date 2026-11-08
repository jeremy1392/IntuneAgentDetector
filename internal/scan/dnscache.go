package scan

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"

	"detectoragent/internal/catalog"
)

var (
	modDnsapi                 = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsGetCacheDataTable  = modDnsapi.NewProc("DnsGetCacheDataTable")
	dnsQueryNoWireQuery       = uint32(0x10)
	dnsFreeRecordList         = uint32(1)
	maxCacheEntriesToConsider = 20000
)

// dnsCacheEntry mirrors the undocumented DNS_CACHE_ENTRY structure.
type dnsCacheEntry struct {
	Next       *dnsCacheEntry
	Name       *uint16
	Type       uint16
	DataLength uint16
	Flags      uint32
}

// dnsCache reads the Windows DNS client cache, without any network query,
// and keeps the names that match the catalog.
func dnsCache(cat *catalog.Catalog) (map[string][]net.IP, error) {
	names := map[string]bool{}
	for _, h := range cat.ExactHosts() {
		names[h] = true
	}
	tableErr := cachedNames(func(name string) {
		if cat.MatchHost(name) != nil {
			names[catalog.NormalizeHost(name)] = true
		}
	})

	out := make(map[string][]net.IP)
	for name := range names {
		var ips []net.IP
		for _, qtype := range []uint16{windows.DNS_TYPE_A, windows.DNS_TYPE_AAAA} {
			ips = append(ips, cacheLookup(name, qtype)...)
		}
		if len(ips) > 0 {
			out[name] = ips
		}
	}
	return out, tableErr
}

// cachedNames walks the names currently held in the DNS client cache.
func cachedNames(fn func(string)) error {
	if err := procDnsGetCacheDataTable.Find(); err != nil {
		return err
	}
	var head *dnsCacheEntry
	r, _, err := procDnsGetCacheDataTable.Call(uintptr(unsafe.Pointer(&head)))
	if r == 0 {
		return err
	}
	// The list is allocated by dnsapi and not freed: the scanner is a
	// short-lived process.
	count := 0
	for e := head; e != nil && count < maxCacheEntriesToConsider; e = e.Next {
		count++
		if e.Name != nil {
			fn(windows.UTF16PtrToString(e.Name))
		}
	}
	return nil
}

// cacheLookup returns the cached addresses of a name without querying the network.
func cacheLookup(name string, qtype uint16) []net.IP {
	var rec *windows.DNSRecord
	if err := windows.DnsQuery(name, qtype, dnsQueryNoWireQuery, nil, &rec, nil); err != nil || rec == nil {
		return nil
	}
	defer windows.DnsRecordListFree(rec, dnsFreeRecordList)
	var out []net.IP
	for r := rec; r != nil; r = r.Next {
		switch r.Type {
		case windows.DNS_TYPE_A:
			ip := make(net.IP, 4)
			copy(ip, r.Data[:4])
			out = append(out, ip)
		case windows.DNS_TYPE_AAAA:
			ip := make(net.IP, 16)
			copy(ip, r.Data[:16])
			out = append(out, ip)
		}
	}
	return out
}

// invertDNS builds the address -> host names index.
func invertDNS(dns map[string][]net.IP) map[string][]string {
	out := make(map[string][]string)
	for host, ips := range dns {
		for _, ip := range ips {
			k := ip.String()
			out[k] = appendUnique(out[k], host)
		}
	}
	return out
}

func appendUnique(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}
