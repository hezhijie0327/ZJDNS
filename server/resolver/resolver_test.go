package resolver

import (
	"net/netip"
	"strings"
	"testing"
	"zjdns/edns"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// TestQueryResult_TruncatedField verifies the TC bit propagation field exists
// and defaults to false (zero value).
func TestQueryResult_TruncatedField(t *testing.T) {
	qr := &QueryResult{}
	if qr.Truncated {
		t.Error("new QueryResult should have Truncated=false by default")
	}

	// Verify the field is settable and readable.
	qr.Truncated = true
	if !qr.Truncated {
		t.Error("Truncated should be settable to true")
	}

	// Verify the field is preserved alongside other fields.
	qr = &QueryResult{
		Answer:    []dns.RR{&dns.A{Hdr: dns.Header{Name: "example.com."}}},
		Rcode:     dns.RcodeSuccess,
		Cacheable: true,
		Truncated: true,
		Server:    "test",
		ECS:       &edns.ECSOption{Address: nil, SourcePrefix: 0},
	}
	if !qr.Truncated {
		t.Error("QueryResult with Truncated=true should keep the value")
	}
	if qr.Rcode != dns.RcodeSuccess {
		t.Error("other fields should be preserved alongside Truncated")
	}
}

func cnameRec(name, target string) *dns.CNAME {
	return &dns.CNAME{
		Hdr:    dns.Header{Name: dnsutil.Fqdn(name), Class: dns.ClassINET, TTL: 300},
		Target: dnsutil.Fqdn(target),
	}
}

func aaaaRec(name, ip string) *dns.AAAA {
	return &dns.AAAA{
		Hdr:  dns.Header{Name: dnsutil.Fqdn(name), Class: dns.ClassINET, TTL: 300},
		Addr: netip.MustParseAddr(ip),
	}
}

// ── findChainStep: owner-scoped chain-step detection ──────────────────────────
// An authority that bundles the whole CNAME chain into one response (RFC 1034
// §3.6.2 — e.g. CDN aliases like www.iqiyi.com → static.cdn.iqiyi.com →
// ipv6-static.dns.iqiyi.com + A records) must not stop the chain on terminal
// records owned by a CNAME target — those records are dropped by the
// owner-scoped collection in resolveInner, leaving a CNAME-only answer.

func TestFindChainStep_BundledMultiHopChain(t *testing.T) {
	answer := []dns.RR{
		cnameRec("www.example.com", "static.cdn.example.com"),
		cnameRec("static.cdn.example.com", "ipv6-static.dns.example.com"),
		aRec("ipv6-static.dns.example.com", "192.0.2.9"),
	}
	next, hasTarget := findChainStep(answer, Question{Name: "www.example.com.", Qtype: dns.TypeA})
	if next == nil || !strings.EqualFold(next.Target, "static.cdn.example.com.") {
		t.Fatalf("nextCNAME = %v, want www → static.cdn", next)
	}
	if hasTarget {
		t.Error("bundled terminal records owned by the CNAME target must not count as the current step's answer (type-only break would drop them)")
	}
}

func TestFindChainStep_CurrentNameHasTerminal(t *testing.T) {
	answer := []dns.RR{aRec("www.example.com", "192.0.2.1")}
	next, hasTarget := findChainStep(answer, Question{Name: "www.example.com.", Qtype: dns.TypeA})
	if next != nil {
		t.Fatalf("nextCNAME = %v, want nil (chain ends here)", next)
	}
	if !hasTarget {
		t.Error("A record owned by the queried name should end the chain")
	}
}

func TestFindChainStep_SingleHopBundled(t *testing.T) {
	answer := []dns.RR{
		cnameRec("www.example.com", "cdn.example.com"),
		aRec("cdn.example.com", "192.0.2.5"),
	}
	next, hasTarget := findChainStep(answer, Question{Name: "www.example.com.", Qtype: dns.TypeA})
	if next == nil || !strings.EqualFold(next.Target, "cdn.example.com.") {
		t.Fatalf("nextCNAME = %v, want www → cdn", next)
	}
	if hasTarget {
		t.Error("single-hop bundled terminal records must continue the chain to the target")
	}
}

func TestFindChainStep_UnrelatedOwnerTerminal(t *testing.T) {
	// Same QTYPE, different owner (e.g. records of another zone in the
	// additional section) must neither end the chain nor be collected.
	answer := []dns.RR{
		cnameRec("www.example.com", "cdn.example.com"),
		aRec("other.example.net", "192.0.2.7"),
	}
	next, hasTarget := findChainStep(answer, Question{Name: "www.example.com.", Qtype: dns.TypeA})
	if next == nil || !strings.EqualFold(next.Target, "cdn.example.com.") {
		t.Fatalf("nextCNAME = %v, want www → cdn", next)
	}
	if hasTarget {
		t.Error("unrelated-owner terminal records must not end the chain (M-low regression)")
	}
}

func TestFindChainStep_WrongType(t *testing.T) {
	answer := []dns.RR{aaaaRec("www.example.com", "2001:db8::1")}
	next, hasTarget := findChainStep(answer, Question{Name: "www.example.com.", Qtype: dns.TypeA})
	if next != nil || hasTarget {
		t.Fatalf("AAAA records must not count for an A query: next=%v hasTarget=%t", next, hasTarget)
	}
}

// TestQuery_EmptyUpstream_NoImplicitRecursion verifies the deterministic
// routing rule: recursive resolution is explicit-only (protocol: recursive
// upstream).  An empty upstream list resolves to "no upstream servers"
// (SERVFAIL at the middleware layer), never implicit recursion.
func TestQuery_EmptyUpstream_NoImplicitRecursion(t *testing.T) {
	r := &Resolver{upstream: &upstreamSet{}}
	qr := r.Query(t.Context(), Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil)
	if qr == nil || qr.Err == nil {
		t.Fatalf("empty upstream must error, got %+v", qr)
	}
	if !strings.Contains(qr.Err.Error(), "no upstream servers") {
		t.Errorf("error = %v, want 'no upstream servers'", qr.Err)
	}
}
