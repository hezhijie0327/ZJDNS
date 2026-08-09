package resolver

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"zjdns/edns"
	"zjdns/internal/lrumap"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// newTestRecursiveWithHelpers creates a minimal Recursive for testing helpers.
func newTestRecursiveWithHelpers() *Recursive {
	return &Recursive{delegations: lrumap.New[string, *delegationEntry](10000)}
}

// ── applyQnameMinimisation ──────────────────────────────────────────────────

func TestApplyQnameMinimisation_Disabled(t *testing.T) {
	r := newTestRecursiveWithHelpers()
	q := Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	got, steps := r.applyQnameMinimisation(q, "www.example.com.", "example.com.", false, 0)
	if got.Name != q.Name {
		t.Errorf("expected unchanged question when disabled, got %s", got.Name)
	}
	if steps != 0 {
		t.Errorf("expected 0 steps, got %d", steps)
	}
}

func TestApplyQnameMinimisation_FirstStep(t *testing.T) {
	r := newTestRecursiveWithHelpers()
	q := Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	got, steps := r.applyQnameMinimisation(q, "www.example.com.", ".", true, 0)
	if got.Name == q.Name {
		t.Errorf("expected minimised name, got same name %s", got.Name)
	}
	if steps != 1 {
		t.Errorf("expected 1 step, got %d", steps)
	}
	if got.Qtype != dns.TypeA {
		t.Errorf("expected minimisation qtype=A, got %d", got.Qtype)
	}
}

func TestApplyQnameMinimisation_StepIncrements(t *testing.T) {
	r := newTestRecursiveWithHelpers()
	q := Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	// Step 0: from root, expose first label → step increments
	_, steps := r.applyQnameMinimisation(q, "www.example.com.", ".", true, 0)
	if steps != 1 {
		t.Errorf("step 0 should increment to 1, got %d", steps)
	}
	// With a deep qname, early steps keep incrementing
	qDeep := Question{Name: "a.b.c.d.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	_, steps2 := r.applyQnameMinimisation(qDeep, "a.b.c.d.example.com.", ".", true, 1)
	if steps2 != 2 {
		t.Errorf("step 1 should increment to 2, got %d", steps2)
	}
}

func TestApplyQnameMinimisation_DSQueryPreservesQtype(t *testing.T) {
	r := newTestRecursiveWithHelpers()
	q := Question{Name: "example.com.", Qtype: dns.TypeDS, Qclass: dns.ClassINET}
	got, _ := r.applyQnameMinimisation(q, "example.com.", ".", true, 0)
	if got.Qtype != dns.TypeDS {
		t.Errorf("expected DS qtype preserved, got %d", got.Qtype)
	}
}

// ── collectBestNSMatch ──────────────────────────────────────────────────────

func TestCollectBestNSMatch_FindsNS(t *testing.T) {
	r := newTestRecursiveWithHelpers()
	resp := &dns.Msg{
		Ns: []dns.RR{
			&dns.NS{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}, NS: rdata.NS{Ns: "ns1.example.com."}},
		},
	}
	bestMatch, nsRecords, shouldContinue, termRes := r.collectBestNSMatch(
		resp, "www.example.com", "www.example.com.", "www.example.com.", false, false, nil,
	)
	if shouldContinue {
		t.Error("should not continue")
	}
	if termRes != nil {
		t.Error("should not return terminal result")
	}
	if bestMatch != "example.com." {
		t.Errorf("expected bestMatch=example.com., got %s", bestMatch)
	}
	if len(nsRecords) != 1 {
		t.Errorf("expected 1 NS record, got %d", len(nsRecords))
	}
}

func TestCollectBestNSMatch_LongestMatch(t *testing.T) {
	r := newTestRecursiveWithHelpers()
	resp := &dns.Msg{
		Ns: []dns.RR{
			&dns.NS{Hdr: dns.Header{Name: "com.", Class: dns.ClassINET}, NS: rdata.NS{Ns: "a.gtld-servers.net."}},
			&dns.NS{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}, NS: rdata.NS{Ns: "ns1.example.com."}},
		},
	}
	bestMatch, nsRecords, _, _ := r.collectBestNSMatch(
		resp, "www.example.com", "www.example.com.", "www.example.com.", false, false, nil,
	)
	if bestMatch != "example.com." {
		t.Errorf("expected longest match example.com., got %s", bestMatch)
	}
	if len(nsRecords) != 1 {
		t.Errorf("expected 1 NS record (longest match only), got %d", len(nsRecords))
	}
}

func TestCollectBestNSMatch_NoMatchReturnsTerminal(t *testing.T) {
	r := newTestRecursiveWithHelpers()
	resp := &dns.Msg{
		Ns: []dns.RR{
			&dns.SOA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}},
		},
	}
	_, _, shouldContinue, termRes := r.collectBestNSMatch(
		resp, "www.other.com", "www.other.com.", "www.other.com.", false, true,
		&edns.ECSOption{Family: 1, Address: net.IPv4(192, 0, 2, 1)},
	)
	if shouldContinue {
		t.Error("should not continue when qnameMinimise=false")
	}
	if termRes == nil {
		t.Fatal("should return terminal result when no NS match")
	}
}

// ── resolveNextNameservers ──────────────────────────────────────────────────

// TestResolveNextNameservers_SkipsInBailiwickNoGlue guards against circular
// in-bailiwick NS resolution: resolving ns1.example.com to enter example.com
// requires querying example.com's servers, whose addresses are exactly what
// is being resolved.  With no cache and no glue the delegation is
// unreachable — the walk must fail cleanly instead of recursing into itself
// until the depth limit.  r.resolver is intentionally nil here: reaching
// resolveNSAddressesConcurrent would nil-panic, so the test proves the guard
// fires before any NS-address walk is attempted.
func TestResolveNextNameservers_SkipsInBailiwickNoGlue(t *testing.T) {
	r := newTestRecursiveWithHelpers() // cache nil, resolver nil
	nsRecords := []*dns.NS{
		{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}, NS: rdata.NS{Ns: "ns1.example.com."}},
		{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}, NS: rdata.NS{Ns: "ns2.example.com."}},
	}

	res := r.resolveNextNameservers(context.Background(), nsRecords, &dns.Msg{}, "www.example.com.", "com.", 0, false)
	if len(res.addrs) != 0 {
		t.Fatalf("expected no addresses for glue-less in-bailiwick NS, got %v", res.addrs)
	}
	if res.source != "" {
		t.Fatalf("expected empty source, got %q", res.source)
	}
}

// TestResolveNextNameservers_UsesInBailiwickGlue verifies the glue path still
// serves in-bailiwick NS names — the skip guard must only apply to names with
// neither cache nor glue.
func TestResolveNextNameservers_UsesInBailiwickGlue(t *testing.T) {
	r := newTestRecursiveWithHelpers()
	nsRecords := []*dns.NS{
		{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}, NS: rdata.NS{Ns: "ns1.example.com."}},
	}
	resp := &dns.Msg{
		Extra: []dns.RR{
			&dns.A{Hdr: dns.Header{Name: "ns1.example.com.", Class: dns.ClassINET}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}},
		},
	}

	res := r.resolveNextNameservers(context.Background(), nsRecords, resp, "www.example.com.", "com.", 0, false)
	if len(res.addrs) != 1 {
		t.Fatalf("expected 1 glue address, got %v", res.addrs)
	}
	if res.source != "glue" {
		t.Fatalf("expected source=glue, got %q", res.source)
	}
}

func TestCollectBestNSMatch_QnameMinimiseContinue(t *testing.T) {
	r := newTestRecursiveWithHelpers()
	resp := &dns.Msg{
		Ns: []dns.RR{
			&dns.SOA{Hdr: dns.Header{Name: "com.", Class: dns.ClassINET}},
		},
	}
	_, _, shouldContinue, termRes := r.collectBestNSMatch(
		resp, "com", "com.", "www.example.com.", true, false, nil,
	)
	if !shouldContinue {
		t.Error("should continue when qnameMinimise enabled and no NS match")
	}
	if termRes != nil {
		t.Error("should not return terminal result on continue")
	}
}

// ── checkLameDelegation ─────────────────────────────────────────────────────

func TestCheckLameDelegation_NotLame(t *testing.T) {
	r := newTestRecursiveWithHelpers()
	resp := &dns.Msg{
		Answer: []dns.RR{
			&dns.A{Hdr: dns.Header{Name: dnsutil.Fqdn("www.example.com"), Class: dns.ClassINET, TTL: 300}, A: rdata.A{}},
		},
		Ns: []dns.RR{
			&dns.NS{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}, NS: rdata.NS{Ns: "ns1.example.com."}},
		},
	}
	termRes := r.checkLameDelegation(resp, "com.", "example.com", false, nil)
	if termRes != nil {
		t.Error("should return nil when bestMatch differs from currentDomain")
	}
}

func TestCheckLameDelegation_LameDetected(t *testing.T) {
	r := newTestRecursiveWithHelpers()
	resp := &dns.Msg{
		Ns: []dns.RR{
			&dns.NS{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}, NS: rdata.NS{Ns: "ns1.example.com."}},
		},
	}
	termRes := r.checkLameDelegation(resp, "example.com.", "example.com.", false, nil)
	if termRes == nil {
		t.Fatal("should detect lame delegation")
	}
	if termRes.Err == nil {
		t.Error("lame delegation should have an error")
	}
}

func TestCheckLameDelegation_AuthoritativeNODATA(t *testing.T) {
	r := newTestRecursiveWithHelpers()
	resp := &dns.Msg{
		Ns: []dns.RR{
			&dns.NS{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}, NS: rdata.NS{Ns: "ns1.example.com."}},
		},
	}
	resp.Authoritative = true
	termRes := r.checkLameDelegation(resp, "example.com.", "example.com.", true, nil)
	if termRes == nil {
		t.Fatal("should return terminal result for authoritative self-referral")
	}
	if termRes.Err != nil {
		t.Errorf("authoritative NODATA should not be an error: %v", termRes.Err)
	}
}

// ── responseEchoesQuestion (R3-H1) ────────────────────────────────────────────
// RFC 5452 §9.3: a response that does not echo the query's question must be
// rejected — a replayed signed response for a different name in the same zone
// would otherwise validate and poison the cache.

func TestResponseEchoesQuestion_Match(t *testing.T) {
	resp := &dns.Msg{Question: []dns.RR{&dns.A{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET}}}}
	q := Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	if !responseEchoesQuestion(resp, q) {
		t.Error("matching question should echo")
	}
}

func TestResponseEchoesQuestion_NameMismatch(t *testing.T) {
	resp := &dns.Msg{Question: []dns.RR{&dns.A{Hdr: dns.Header{Name: "bank.example.com.", Class: dns.ClassINET}}}}
	q := Question{Name: "attacker.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	if responseEchoesQuestion(resp, q) {
		t.Error("different-name question must be rejected (cross-name replay)")
	}
}

func TestResponseEchoesQuestion_TypeMismatch(t *testing.T) {
	resp := &dns.Msg{Question: []dns.RR{&dns.A{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET}}}}
	q := Question{Name: "www.example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
	if responseEchoesQuestion(resp, q) {
		t.Error("different qtype must be rejected")
	}
}

func TestResponseEchoesQuestion_MissingQuestion(t *testing.T) {
	resp := &dns.Msg{} // no question section — some broken servers omit it
	q := Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	if responseEchoesQuestion(resp, q) {
		t.Error("missing question section must be rejected")
	}
	if responseEchoesQuestion(nil, q) {
		t.Error("nil response must be rejected")
	}
}

func TestResponseEchoesQuestion_CaseInsensitive(t *testing.T) {
	resp := &dns.Msg{Question: []dns.RR{&dns.A{Hdr: dns.Header{Name: "WWW.Example.COM.", Class: dns.ClassINET}}}}
	q := Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	if !responseEchoesQuestion(resp, q) {
		t.Error("question names must compare case-insensitively (RFC 4343)")
	}
}
