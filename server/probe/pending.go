package probe

import (
	"net"
	"slices"
	"strings"

	"zjdns/internal/pending"
)

// probeKey identifies a unique in-flight latency probe.
type probeKey struct {
	qname string
	qtype uint16
}

// nsPending deduplicates concurrent ProbeNSAddrs calls by sorted IP set.
var nsPending = pending.NewGroup[string]()

// buildNSProbeKey returns a deterministic string key from a sorted IP list.
func buildNSProbeKey(ips []net.IP) string {
	strs := make([]string, len(ips))
	for i, ip := range ips {
		strs[i] = ip.String()
	}
	slices.Sort(strs)
	return strings.Join(strs, ",")
}
