package scan

import (
	"errors"
	"net"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"detectoragent/internal/catalog"
)

var (
	modDnsapi                 = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsGetCacheDataTable  = modDnsapi.NewProc("DnsGetCacheDataTable")
	maxCacheEntriesToConsider = 20000
)

const (
	dnsQueryNoWireQuery = uint32(0x10)
	dnsQueryAddrConfig  = uint32(0x2000)
	dnsQueryDualAddr    = uint32(0x4000)
	dnsFreeRecordList   = uint32(1)
	dnsLookupWorkers    = 4
)

// cacheKeys are the (record type, options) pairs under which the DNS client
// caches a name. The cache keys an entry by name, type and query options, and
// a cache-only lookup sees only the entries stored under its own key.
// getaddrinfo with AF_UNSPEC, which Python, Node.js and .NET use by default,
// stores one AAAA entry queried with ADDRCONFIG and DUAL_ADDR, whose IPv4
// answers are IPv4-mapped AAAA records; with AF_INET it stores a plain A entry.
var cacheKeys = []struct {
	qtype uint16
	opts  uint32
}{
	{windows.DNS_TYPE_A, dnsQueryNoWireQuery},
	{windows.DNS_TYPE_AAAA, dnsQueryNoWireQuery},
	{windows.DNS_TYPE_AAAA, dnsQueryNoWireQuery | dnsQueryAddrConfig | dnsQueryDualAddr},
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

	jobs := make(chan string)
	out := make(map[string][]net.IP)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < dnsLookupWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range jobs {
				var ips []net.IP
				for _, k := range cacheKeys {
					ips = appendIPs(ips, cacheLookup(name, k.qtype, k.opts))
				}
				if len(ips) > 0 {
					mu.Lock()
					out[name] = ips
					mu.Unlock()
				}
			}
		}()
	}
	for name := range names {
		jobs <- name
	}
	close(jobs)
	wg.Wait()
	return out, tableErr
}

// cachedNames walks the names currently held in the DNS client cache.
// DnsGetCacheDataTable is undocumented; some Windows builds no longer
// return the table, and the scan then relies on cache-only lookups.
func cachedNames(fn func(string)) error {
	if err := procDnsGetCacheDataTable.Find(); err != nil {
		return err
	}
	var head *dnsCacheEntry
	r, _, err := procDnsGetCacheDataTable.Call(uintptr(unsafe.Pointer(&head)))
	if r == 0 {
		if errors.Is(err, windows.ERROR_SUCCESS) {
			return errors.New("DnsGetCacheDataTable returned no table")
		}
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

// dnsCacheEntry mirrors the undocumented DNS_CACHE_ENTRY structure.
type dnsCacheEntry struct {
	Next       *dnsCacheEntry
	Name       *uint16
	Type       uint16
	DataLength uint16
	Flags      uint32
}

// cacheLookup returns the cached addresses of a name without querying the
// network. IPv4-mapped IPv6 answers are returned as IPv4 addresses.
func cacheLookup(name string, qtype uint16, opts uint32) []net.IP {
	var rec *windows.DNSRecord
	if err := windows.DnsQuery(name, qtype, opts, nil, &rec, nil); err != nil || rec == nil {
		return nil
	}
	defer windows.DnsRecordListFree(rec, dnsFreeRecordList)
	var out []net.IP
	for r := rec; r != nil; r = r.Next {
		if ip := recordIP(r); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

// recordIP returns the address of an A or AAAA record, or nil. An
// IPv4-mapped IPv6 address is returned as an IPv4 address, so that it
// matches the IPv4 connection table.
func recordIP(r *windows.DNSRecord) net.IP {
	switch r.Type {
	case windows.DNS_TYPE_A:
		ip := make(net.IP, 4)
		copy(ip, r.Data[:4])
		return ip
	case windows.DNS_TYPE_AAAA:
		ip := make(net.IP, 16)
		copy(ip, r.Data[:16])
		if v4 := ip.To4(); v4 != nil {
			return v4
		}
		return ip
	}
	return nil
}

// appendIPs appends the addresses that are not already in the list.
func appendIPs(list, add []net.IP) []net.IP {
	for _, ip := range add {
		dup := false
		for _, v := range list {
			if v.Equal(ip) {
				dup = true
				break
			}
		}
		if !dup {
			list = append(list, ip)
		}
	}
	return list
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
