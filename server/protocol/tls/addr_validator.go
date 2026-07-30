package tls

import (
	"net"
	"time"
	"zjdns/internal/lrumap"
)

// makeAddrValidator returns a VerifySourceAddress callback backed by an LRU
// cache of recently-seen client IPs. If the client IP is found in the cache,
// address validation (QUIC Retry) is skipped, avoiding connectivity issues
// caused by NAT/firewall dropping Retry packets.
//
// The cache is bounded per RFC 9000 (128 entries). LRU eviction ensures the
// most recently active clients remain cached while inactive entries are
// naturally aged out.
func makeAddrValidator(cache *lrumap.Map[string, time.Time]) func(net.Addr) bool {
	return func(addr net.Addr) bool {
		if cache == nil {
			return true
		}
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			return true
		}
		key := udpAddr.IP.String()
		if _, exists := cache.Get(key); exists {
			return false
		}
		cache.Set(key, time.Now())
		return true
	}
}
