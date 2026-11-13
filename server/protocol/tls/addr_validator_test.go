package tls

import (
	"net"
	"testing"
	"time"
	"zjdns/config"
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

// TestPerShardAddrCacheIndependent pins the shared-port multi-shard contract
// (Round 6 audit P1): each UDP dispatch shard owns its Retry-whitelist cache,
// the mark sites (handleDOQConnections / handleHTTP3Connections) write the
// shard-local cache they received as a parameter, and one shard's marks never
// leak into (or get overwritten by) another's.  The pre-fix routing through a
// single server field was last-wins: 3 of 4 shards validated against a cache
// another shard populated, so their clients paid a Retry round trip forever.
func TestPerShardAddrCacheIndependent(t *testing.T) {
	newShard := func() (*lrumap.Map[string, time.Time], func(net.Addr) bool) {
		cache := lrumap.New[string, time.Time](config.DefaultQUICAddrCacheSize)
		return cache, makeAddrValidator(cache)
	}
	cache0, validate0 := newShard()
	cache1, validate1 := newShard()

	shard0Client := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1000}
	shard1Client := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 2000}

	// Before any handshake completes, both shards must Retry every client.
	if !validate0(shard0Client) || !validate1(shard1Client) {
		t.Fatal("fresh shard caches must require a Retry for every address")
	}

	// Shard 0's accept loop marks ITS parameter cache — only shard 0's
	// validator may see the verified address.
	markAddrVerified(cache0, shard0Client.IP)
	if validate0(shard0Client) {
		t.Error("shard 0 client must skip the Retry after its own shard marked it")
	}
	if !validate1(shard0Client) {
		t.Error("a mark on shard 0's cache must not whitelist the address on shard 1")
	}

	// Shard 1 marks independently — both shards now serve their own client
	// without a Retry, and the marks did not clobber each other.
	markAddrVerified(cache1, shard1Client.IP)
	if validate1(shard1Client) {
		t.Error("shard 1 client must skip the Retry after its own shard marked it")
	}
	if validate0(shard0Client) {
		t.Error("shard 0's earlier mark must survive shard 1 marking (last-wins regression)")
	}
}
