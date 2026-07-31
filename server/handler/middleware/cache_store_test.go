package middleware

import (
	"context"
	"net/netip"
	"testing"
	"zjdns/cache"
	"zjdns/database"
	"zjdns/edns"
	"zjdns/server/handler"
	"zjdns/server/resolver"
	"zjdns/stats"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

// newTestCacheStore creates a CacheStore with a real in-memory cache for testing.
func newTestCacheStore() *CacheStore {
	db, err := database.Open("", nil)
	if err != nil {
		panic(err)
	}
	store := cache.New(db)
	collector := stats.New()
	return &CacheStore{
		store: store,
		stats: collector,
	}
}

func TestCacheStore_ECSMismatch_ReturnsSERVFAIL(t *testing.T) {
	m := newTestCacheStore()
	defer func() { _ = m.store.Close() }()

	// Build a request with ECS option.
	req := new(dns.Msg)
	req.Question = []dns.RR{
		&dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}},
	}

	queryECS := &edns.ECSOption{
		Family:       1,
		SourcePrefix: 24,
		ScopePrefix:  0,
		Address:      []byte{192, 0, 2, 0},
	}

	// Simulate a resolution result with a mismatched ECS (spoofed response).
	responseECS := &edns.ECSOption{
		Family:       1,
		SourcePrefix: 16,
		ScopePrefix:  0,
		Address:      []byte{10, 0, 0, 0}, // different subnet
	}

	qctx := &handler.QueryContext{
		Req:                   req,
		Protocol:              "udp",
		ECSOpt:                queryECS,
		ClientRequestedDNSSEC: false,
		Resolved:              true,
		ResolutionResult: &resolver.QueryResult{
			Answer: []dns.RR{
				&dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("1.2.3.4")}},
			},
			Cacheable: true,
			ECS:       responseECS,
		},
	}

	// Wrap a no-op handler (should not be called since we're testing buildSuccess).
	next := handler.QueryHandlerFunc(func(_ context.Context, _ *handler.QueryContext) error {
		return nil
	})
	h := m.Wrap(next)
	_ = h.ServeDNS(context.Background(), qctx)

	// The response should be SERVFAIL, not nil (silent drop).
	if qctx.Res == nil {
		t.Fatal("response should not be nil on ECS mismatch — client would hang")
	}
	if qctx.Res.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %d, want RcodeServerFailure (%d)", qctx.Res.Rcode, dns.RcodeServerFailure)
	}
	if qctx.EDE == nil {
		t.Error("EDE should be set on ECS mismatch")
	}
}
