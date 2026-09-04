package middleware

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
)

// TestCacheLookup_HitRecordsCachedRcode verifies a fresh cache hit records the
// cached entry's real rcode into the rcode counters: a negative-cache NXDOMAIN
// entry served from cache must count as nx, not noerr (the pre-fix behaviour
// hardcoded RcodeSuccess). Hits do not enter the per-RCODE journal — the
// journal tracks non-hit results only (mirroring the old query_log semantics).
func TestCacheLookup_HitRecordsCachedRcode(t *testing.T) {
	store := testStore(t)
	defer func() { _ = store.Close() }()

	// Store an NXDOMAIN (negative) entry: no answers, rcode=3.
	store.Set("example.com.", dns.TypeA, dns.ClassINET, nil, nil, nil, nil, false, dns.RcodeNameError)

	// Fresh hit path: CacheLookup.Wrap builds the response from the entry.
	// Stats is the single journal recording site — exercise it around the
	// middleware under test, as AssembleChain wires it.
	// next must never run on a fresh hit.
	next := handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		t.Fatal("next chain invoked on a fresh cache hit")
		return nil
	})
	m := (&Stats{store: store}).Wrap((&CacheLookup{store: store}).Wrap(next))
	qctx := (&handler.QueryContext{
		Req:      testQuery(t),
		Qname:    "example.com.",
		Qtype:    dns.TypeA,
		Protocol: "udp",
	}).InitQuestion()
	if err := m.ServeDNS(context.Background(), qctx); err != nil {
		t.Fatal(err)
	}
	if qctx.Res == nil || qctx.Res.Rcode != dns.RcodeNameError {
		t.Fatalf("served rcode = %v, want NXDOMAIN", qctx.Res.Rcode)
	}

	lines := store.Stats()
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "nx=1") {
		t.Errorf("Stats() = %v, want the rcode counters to show nx=1", lines)
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "top-rcode3:") {
			t.Errorf("hits must not enter the per-RCODE journal, got %q", line)
		}
	}
}

// TestCacheLookup_NonLoopbackDestructiveChaosDenied guards the loopback gate
// on destructive CHAOS endpoints (cache/stats/querylog clear) — kept here to
// pin the Wrap path's response handling when a zone rule matches.
func TestCacheLookup_StaleRecordsCachedRcode(t *testing.T) {
	store := testStore(t)
	defer func() { _ = store.Close() }()

	// Store an entry with a 1-second TTL, then sleep past it.  Set computes
	// expires_at = now + ttl with second-granularity timestamps, so a TTL=1
	// entry must be read at least 2 seconds later to be reliably expired —
	// but still within the serve-stale window (DefaultStaleMaxAge).
	short := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 1}, Addr: netip.MustParseAddr("192.0.2.1")}
	store.Set("example.com.", dns.TypeA, dns.ClassINET, nil,
		[]dns.RR{short}, nil, nil, false, dns.RcodeNameError)
	time.Sleep(2500 * time.Millisecond)

	next := handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		return nil // miss path — unreachable for an expired-but-servable entry
	})
	m := (&Stats{store: store}).Wrap((&CacheLookup{store: store}).Wrap(next))
	qctx := (&handler.QueryContext{
		Req:      testQuery(t),
		Qname:    "example.com.",
		Qtype:    dns.TypeA,
		Protocol: "udp",
	}).InitQuestion()
	if err := m.ServeDNS(context.Background(), qctx); err != nil {
		t.Fatal(err)
	}
	if qctx.Res == nil {
		t.Fatal("expected a stale response")
	}
	// The stale entry was stored with rcode NXDOMAIN; the served stale
	// response must carry it and the journal must group under rcode 3.
	if qctx.Res.Rcode != dns.RcodeNameError {
		t.Fatalf("stale served rcode = %v, want NXDOMAIN", qctx.Res.Rcode)
	}

	lines := store.StatsRcode()
	var journalLine string
	for _, line := range lines {
		if strings.HasPrefix(line, "top-rcode3:") {
			journalLine = line
			break
		}
	}
	if journalLine == "" {
		t.Fatalf("no top-rcode3 journal line in StatsRcode(): %v", lines)
	}
	if !strings.Contains(journalLine, "example.com.=1") {
		t.Errorf("top-rcode3 line = %q, want it to contain example.com.=1 (the stale serve)", journalLine)
	}
}
