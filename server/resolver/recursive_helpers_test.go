package resolver

import (
	"net"
	"testing"
	"zjdns/edns"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// newTestRecursiveWithHelpers creates a minimal Recursive for testing helpers.
func newTestRecursiveWithHelpers() *Recursive {
	return &Recursive{}
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
	if bestMatch != "example.com" {
		t.Errorf("expected bestMatch=example.com, got %s", bestMatch)
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
	if bestMatch != "example.com" {
		t.Errorf("expected longest match example.com, got %s", bestMatch)
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
	termRes := r.checkLameDelegation(resp, "example.com.", "example.com", false, nil)
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
	termRes := r.checkLameDelegation(resp, "example.com.", "example.com", true, nil)
	if termRes == nil {
		t.Fatal("should return terminal result for authoritative self-referral")
	}
	if termRes.Err != nil {
		t.Errorf("authoritative NODATA should not be an error: %v", termRes.Err)
	}
}
