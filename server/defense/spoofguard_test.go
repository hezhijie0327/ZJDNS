package defense

import (
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

func TestSemanticHash_SameAnswerDiffTTL(t *testing.T) {
	a := newMsg(dns.RcodeSuccess, false, []dns.RR{
		testA("example.com.", "1.2.3.4", 60),
	})
	b := newMsg(dns.RcodeSuccess, false, []dns.RR{
		testA("example.com.", "1.2.3.4", 300),
	})

	if semanticHash(a) != semanticHash(b) {
		t.Error("semanticHash should be equal for same answer with different TTL")
	}
}

func TestSemanticHash_SameAnswerDiffOrder(t *testing.T) {
	a := newMsg(dns.RcodeSuccess, false, []dns.RR{
		testA("example.com.", "1.2.3.4", 60),
		testA("example.com.", "5.6.7.8", 60),
	})
	b := newMsg(dns.RcodeSuccess, false, []dns.RR{
		testA("example.com.", "5.6.7.8", 300),
		testA("example.com.", "1.2.3.4", 300),
	})

	if semanticHash(a) != semanticHash(b) {
		t.Error("semanticHash should be equal regardless of RR order")
	}
}

func TestSemanticHash_DifferentAnswer(t *testing.T) {
	a := newMsg(dns.RcodeSuccess, false, []dns.RR{
		testA("example.com.", "1.2.3.4", 60),
	})
	b := newMsg(dns.RcodeSuccess, false, []dns.RR{
		testA("example.com.", "9.9.9.9", 60),
	})

	if semanticHash(a) == semanticHash(b) {
		t.Error("semanticHash should differ for different IPs")
	}
}

func TestSemanticHash_DifferentRcode(t *testing.T) {
	a := newMsg(dns.RcodeSuccess, false, []dns.RR{testA("x.com.", "1.1.1.1", 60)})
	b := newMsg(dns.RcodeNameError, false, []dns.RR{testA("x.com.", "1.1.1.1", 60)})

	if semanticHash(a) == semanticHash(b) {
		t.Error("semanticHash should differ for different Rcodes")
	}
}

func TestSemanticHash_DiffAAFlag(t *testing.T) {
	a := newMsg(dns.RcodeSuccess, false, []dns.RR{testA("x.com.", "1.1.1.1", 60)})
	b := newMsg(dns.RcodeSuccess, true, []dns.RR{testA("x.com.", "1.1.1.1", 60)})

	if semanticHash(a) == semanticHash(b) {
		t.Error("semanticHash should differ for different AA flags")
	}
}

func TestCollectAndVote_MajorityWins(t *testing.T) {
	common := newMsg(dns.RcodeSuccess, false, []dns.RR{testA("x.com.", "1.1.1.1", 60)})
	rogue := newMsg(dns.RcodeSuccess, false, []dns.RR{testA("x.com.", "9.9.9.9", 60)})

	responses := []*dns.Msg{common, rogue, common}
	winner := CollectAndVote(responses, 2)
	if winner == nil {
		t.Fatal("expected a winner")
	}
	ips := extractIPsFromMsg(winner)
	if len(ips) != 1 || ips[0] != "1.1.1.1" {
		t.Errorf("expected 1.1.1.1 (majority), got %v", ips)
	}
}

func TestCollectAndVote_NoMajority(t *testing.T) {
	a := newMsg(dns.RcodeSuccess, false, []dns.RR{testA("x.com.", "1.1.1.1", 60)})
	b := newMsg(dns.RcodeSuccess, false, []dns.RR{testA("x.com.", "2.2.2.2", 60)})
	c := newMsg(dns.RcodeSuccess, false, []dns.RR{testA("x.com.", "3.3.3.3", 60)})

	responses := []*dns.Msg{a, b, c}
	winner := CollectAndVote(responses, 2)
	if winner != nil {
		t.Errorf("expected no majority, got %v", extractIPsFromMsg(winner))
	}
}

func TestCollectAndVote_Empty(t *testing.T) {
	if CollectAndVote(nil, 2) != nil {
		t.Error("expected nil for empty input")
	}
	if CollectAndVote([]*dns.Msg{}, 2) != nil {
		t.Error("expected nil for empty input")
	}
}

func TestCollectAndVote_ThresholdOne(t *testing.T) {
	// threshold=1: first response always wins (fallback mode).
	first := newMsg(dns.RcodeSuccess, false, []dns.RR{testA("x.com.", "1.1.1.1", 60)})
	second := newMsg(dns.RcodeSuccess, false, []dns.RR{testA("x.com.", "9.9.9.9", 60)})

	winner := CollectAndVote([]*dns.Msg{first, second}, 1)
	if winner != first {
		t.Error("threshold=1 should return the first response")
	}
}

func TestDrainResponseChan_Populated(t *testing.T) {
	ch := make(chan *dns.Msg, 3)
	ch <- newMsg(dns.RcodeSuccess, false, []dns.RR{testA("a.com.", "1.1.1.1", 60)})
	ch <- newMsg(dns.RcodeSuccess, false, []dns.RR{testA("b.com.", "2.2.2.2", 60)})
	ch <- newMsg(dns.RcodeSuccess, false, []dns.RR{testA("c.com.", "3.3.3.3", 60)})

	results := DrainResponseChan(ch)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
}

func TestDrainResponseChan_Empty(t *testing.T) {
	ch := make(chan *dns.Msg, 1)
	results := DrainResponseChan(ch)
	if len(results) != 0 {
		t.Errorf("expected empty slice, got %d items", len(results))
	}
}

func TestDrainResponseChan_NilSkipped(t *testing.T) {
	ch := make(chan *dns.Msg, 3)
	ch <- newMsg(dns.RcodeSuccess, false, []dns.RR{testA("a.com.", "1.1.1.1", 60)})
	var nilMsg *dns.Msg
	ch <- nilMsg
	ch <- newMsg(dns.RcodeSuccess, false, []dns.RR{testA("c.com.", "3.3.3.3", 60)})

	results := DrainResponseChan(ch)
	if len(results) != 2 {
		t.Fatalf("expected 2 results (nil skipped), got %d", len(results))
	}
}

func TestLastResponse_PicksLast(t *testing.T) {
	first := newMsg(dns.RcodeSuccess, false, []dns.RR{testA("x.com.", "1.1.1.1", 60)})
	second := newMsg(dns.RcodeSuccess, false, []dns.RR{testA("x.com.", "2.2.2.2", 60)})
	third := newMsg(dns.RcodeSuccess, false, []dns.RR{testA("x.com.", "3.3.3.3", 60)})

	winner := LastResponse([]*dns.Msg{first, second, third})
	ips := extractIPsFromMsg(winner)
	if len(ips) != 1 || ips[0] != "3.3.3.3" {
		t.Errorf("expected last response (3.3.3.3), got %v", ips)
	}
}

func TestLastResponse_Empty(t *testing.T) {
	if LastResponse(nil) != nil {
		t.Error("expected nil for nil input")
	}
	if LastResponse([]*dns.Msg{}) != nil {
		t.Error("expected nil for empty input")
	}
}

// --- helpers ---

func newMsg(rcode uint16, aa bool, answer []dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.Rcode = rcode
	m.Authoritative = aa
	m.Answer = answer
	return m
}

func testA(name, ip string, ttl uint32) *dns.A {
	return &dns.A{
		Hdr: dns.Header{
			Name:  dnsutil.Fqdn(name),
			Class: dns.ClassINET,
			TTL:   ttl,
		},
		A: rdata.A{Addr: netip.MustParseAddr(ip)},
	}
}

func extractIPsFromMsg(msg *dns.Msg) []string {
	var ips []string
	for _, rr := range msg.Answer {
		if a, ok := rr.(*dns.A); ok {
			ips = append(ips, a.A.Addr.String()) //nolint:staticcheck // QF1008 field selection
		}
	}
	return ips
}
