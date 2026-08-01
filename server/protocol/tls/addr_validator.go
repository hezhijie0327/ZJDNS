package tls

import (
	"net"
	"time"
	"zjdns/internal/lrumap"
)

// addrCacheTTL bounds how long a source address stays whitelisted. Entries
// are inserted on first sight (before the client proves address ownership),
// so a spoofed datagram can whitelist a victim IP for at most this long.
const addrCacheTTL = 5 * time.Minute

// makeAddrValidator returns a VerifySourceAddress callback backed by an LRU
// cache of recently-seen client IPs. If the client IP is found in the cache,
// address validation (QUIC Retry) is skipped, avoiding connectivity issues
// caused by NAT/firewall dropping Retry packets.
//
// The cache is bounded per RFC 9000 (128 entries), and entries expire after
// addrCacheTTL so a single spoofed datagram cannot whitelist a victim IP
// indefinitely.
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
		if seenAt, exists := cache.Get(key); exists && time.Since(seenAt) < addrCacheTTL {
			// quic-go's VerifySourceAddress contract: true = the source is
			// verified and the handshake proceeds WITHOUT a Retry.
			return true
		}
		// Unknown (or expired) address: insert it and request a Retry —
		// returning false makes quic-go send one, which proves the client
		// can receive packets at this address (RFC 9000 §8.1).
		cache.Set(key, time.Now())
		return false
	}
}
