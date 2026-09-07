package tls

import (
	"net"
	"testing"
	"time"
	"zjdns/internal/lrumap"
)

// TestAddrValidatorPolarity pins the quic-go VerifySourceAddress contract:
// true makes the server send a Retry (RFC 9000 §8.1), false proceeds. The
// previous implementation had this inverted — returning clients were asked
// to Retry while unknown sources skipped validation entirely.
func TestAddrValidatorPolarity(t *testing.T) {
	cache := lrumap.New[string, time.Time](8)
	validate := makeAddrValidator(cache)

	udp := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 4433}
	if !validate(udp) {
		t.Error("unknown address must require a Retry (true)")
	}
	if !validate(udp) {
		t.Error("still-unverified address must keep requiring a Retry")
	}

	// Verified only AFTER the handshake completes (markAddrVerified), never
	// on first sight — a spoofed Initial must not validate its own source.
	markAddrVerified(cache, udp.IP)
	if validate(udp) {
		t.Error("verified address must skip the Retry (false)")
	}

	// Expiry re-arms validation.
	cache.Set("192.0.2.10", time.Now().Add(-addrCacheTTL-time.Second))
	if !validate(udp) {
		t.Error("expired entry must require a Retry again")
	}

	// Non-UDP addresses and a nil cache stay conservative.
	if !validate(&net.TCPAddr{IP: net.ParseIP("192.0.2.10")}) {
		t.Error("non-UDP address must require a Retry")
	}
	if !makeAddrValidator(nil)(udp) {
		t.Error("nil cache must require a Retry for everything")
	}
	markAddrVerified(nil, udp.IP) // must be a no-op, not a panic
}
