package tlcp

import (
	"context"
	"errors"
	"testing"
	"time"
	"zjdns/config"
	zpool "zjdns/server/upstream/pool"
	socks5 "zjdns/server/upstream/socks5"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// TestTLCPPoolShutdownFailsFast pins the pool-saturation gate: a shut-down
// pool must fail the query with ErrPoolShutdown immediately instead of
// falling through to a per-query dial + full TLCP/DTLCP handshake that
// bypasses the pool's dial caps (same gate as the plain TCP path).
func TestTLCPPoolShutdownFailsFast(t *testing.T) {
	noProxy := func(*config.UpstreamServer) *socks5.Dialer { return nil }
	c := New(noProxy, 2*time.Second)
	c.Close() // shuts down tlcpPool and dtlcpPool

	msg := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	// Port 1 refuses instantly: if the fallback dial ran, the error would be
	// a dial error instead of the pool sentinel.
	server := &config.UpstreamServer{Address: "127.0.0.1:1", SkipTLSVerify: true}

	if _, err := c.ExecuteTLCP(context.Background(), msg, server); !errors.Is(err, zpool.ErrPoolShutdown) {
		t.Fatalf("ExecuteTLCP error = %v, want ErrPoolShutdown (no per-query dial fallback)", err)
	}
	if _, err := c.ExecuteDTLCP(context.Background(), msg, server); !errors.Is(err, zpool.ErrPoolShutdown) {
		t.Fatalf("ExecuteDTLCP error = %v, want ErrPoolShutdown (no per-query dial fallback)", err)
	}
}
