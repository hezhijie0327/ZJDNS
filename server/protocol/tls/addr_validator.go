package tls

import (
	"net"
	"time"
	"zjdns/internal/lrumap"
)

// addrCacheTTL bounds how long a verified source address skips the QUIC
// Retry (RFC 9000 §8.1.1: an address validated once needs no re-validation
// within a short window).
const addrCacheTTL = 5 * time.Minute

// makeAddrValidator returns a quic-go VerifySourceAddress callback backed by
// an LRU cache of addresses that have demonstrably completed a handshake
// (marked via markAddrVerified — never on first sight, or a spoofed Initial
// would validate its own spoofed source address).
//
// quic-go's contract is the OPPOSITE of what the name suggests: returning
// true makes the server send a Retry (RFC 9000 §8.1 source-address
// validation), returning false proceeds with the handshake. A verified
// address therefore returns false; anything else returns true.
func makeAddrValidator(cache *lrumap.Map[string, time.Time]) func(net.Addr) bool {
	return func(addr net.Addr) bool {
		if cache == nil {
			return true
		}
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			return true
		}
		if seenAt, exists := cache.Get(udpAddr.IP.String()); exists && time.Since(seenAt) < addrCacheTTL {
			return false // proven address — skip the Retry
		}
		return true // unknown or expired — prove address ownership first
	}
}

// markAddrVerified whitelists an address after the client has demonstrably
// completed a handshake (DoQ Accept) or served a request (DoH3), so its
// next connection skips the Retry.
func markAddrVerified(cache *lrumap.Map[string, time.Time], ip net.IP) {
	if cache == nil || ip == nil {
		return
	}
	cache.Set(ip.String(), time.Now())
}
