package resolver

import (
	"context"
	"testing"
	"time"
	"zjdns/edns"
	"zjdns/server/upstream"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// TestApplyDefenseUncertainty verifies the terminal-walk marking: an
// uncertain result loses Cacheable and carries the ZJDNS-private no-cache
// EDE; a certain result is untouched.
func TestApplyDefenseUncertainty(t *testing.T) {
	qr := &QueryResult{Cacheable: true}
	applyDefenseUncertainty(qr, true)
	if qr.Cacheable {
		t.Fatal("uncertain result must not be cacheable")
	}
	if !edns.IsZJDNSNoCacheEDE(qr.UpstreamEDE) {
		t.Fatalf("uncertain result must carry the no-cache EDE, got %+v", qr.UpstreamEDE)
	}
	if qr.UpstreamEDE.InfoCode != edns.EDEZJDNSDefenseUncertain {
		t.Fatalf("EDE code = %d, want %d", qr.UpstreamEDE.InfoCode, edns.EDEZJDNSDefenseUncertain)
	}

	// Certain results pass through untouched.
	untouched := &QueryResult{Cacheable: true}
	applyDefenseUncertainty(untouched, false)
	if !untouched.Cacheable || untouched.UpstreamEDE != nil {
		t.Fatal("certain result must not be marked")
	}

	// An existing no-cache EDE (fallback provenance) wins — no overwrite.
	withEDE := &QueryResult{Cacheable: true, UpstreamEDE: edns.DefenseUncertainEDE()}
	applyDefenseUncertainty(withEDE, true)
	if withEDE.UpstreamEDE.InfoCode != edns.EDEZJDNSDefenseUncertain {
		t.Fatal("existing no-cache EDE must not be overwritten")
	}
}

// TestResolveDefenseUncertainPropagation walks a scripted root→TLD→child
// hierarchy whose child answers carry Result.Uncertain (an unverified UDP
// defense response): the terminal marking must survive the CNAME-chain
// aggregation — the final QueryResult loses Cacheable and carries the
// ZJDNS no-cache EDE, so the answer is served but never cached.
func TestResolveDefenseUncertainPropagation(t *testing.T) {
	rootHintsOnce.Do(func() {})
	oldHints := rootHints
	rootHints = map[string][]string{"a.root-servers.test.": {"10.9.0.1:53"}}
	t.Cleanup(func() { rootHints = oldHints })

	rootHandler := func(ctx context.Context, msg *dns.Msg) *upstream.Result {
		resp := dnsutil.SetReply(new(dns.Msg), msg)
		resp.Ns = append(resp.Ns, &dns.NS{
			Hdr: dns.Header{Name: "test.", Class: dns.ClassINET, TTL: 300},
			Ns:  "ns.test.",
		})
		resp.Extra = append(resp.Extra, aRec("ns.test.", "10.9.0.2"))
		return &upstream.Result{Response: resp}
	}
	tldHandler := func(ctx context.Context, msg *dns.Msg) *upstream.Result {
		resp := dnsutil.SetReply(new(dns.Msg), msg)
		resp.Answer = append(resp.Answer, aRec("example.test.", "192.0.2.1"))
		// The defense layer could not positively verify this UDP response.
		return &upstream.Result{Response: resp, Uncertain: true}
	}

	client := &fakeNSClient{handlers: map[string]nsScriptHandler{
		"10.9.0.1:53": rootHandler,
		"10.9.0.2:53": tldHandler,
	}}
	r := newPrefetchTestRecursive(client)
	r.resolver.recursive = r

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	qr := (&CNAME{resolver: r.resolver}).resolve(ctx, Question{Name: "example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil)

	if qr.Err != nil {
		t.Fatalf("resolve failed: %v", qr.Err)
	}
	if len(qr.Answer) != 1 {
		t.Fatalf("answer = %d records, want 1", len(qr.Answer))
	}
	if qr.Cacheable {
		t.Fatal("defense-uncertain recursive answer must not be cacheable")
	}
	if !edns.IsZJDNSNoCacheEDE(qr.UpstreamEDE) {
		t.Fatalf("aggregated result must carry the no-cache EDE, got %+v", qr.UpstreamEDE)
	}

	// Control: the same walk with verified responses stays cacheable and
	// unmarked — the propagation must be uncertainty-driven, not
	// unconditional.
	verified := &fakeNSClient{handlers: map[string]nsScriptHandler{
		"10.9.0.1:53": rootHandler,
		"10.9.0.2:53": func(ctx context.Context, msg *dns.Msg) *upstream.Result {
			resp := dnsutil.SetReply(new(dns.Msg), msg)
			resp.Answer = append(resp.Answer, aRec("example.test.", "192.0.2.1"))
			return &upstream.Result{Response: resp}
		},
	}}
	r2 := newPrefetchTestRecursive(verified)
	r2.resolver.recursive = r2
	qr2 := (&CNAME{resolver: r2.resolver}).resolve(ctx, Question{Name: "example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil)
	if qr2.Err != nil {
		t.Fatalf("control resolve failed: %v", qr2.Err)
	}
	if !qr2.Cacheable || qr2.UpstreamEDE != nil {
		t.Fatalf("verified walk must remain cacheable and unmarked (cacheable=%v ede=%+v)", qr2.Cacheable, qr2.UpstreamEDE)
	}
}
