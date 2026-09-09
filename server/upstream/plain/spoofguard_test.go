package plain

import (
	"net/netip"
	"testing"
	"zjdns/config"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// spoofguardResponse packs a DNS response for processPacket.  answers, ns,
// and extras map to the Answer, Ns, and Extra sections.
func spoofguardResponse(t *testing.T, answers, ns, extras []dns.RR, rcode uint16) []byte {
	t.Helper()
	m := &dns.Msg{}
	dnsutil.SetQuestion(m, "example.com.", dns.TypeA)
	m.Response = true
	m.Rcode = rcode
	m.Answer = answers
	m.Ns = ns
	m.Extra = extras
	if err := m.Pack(); err != nil {
		t.Fatalf("pack spoofguard response: %v", err)
	}
	return m.Data
}

// spoofguardQuery returns the query message the packed test responses answer
// (UDPSize set so the EDNS gate is active, as a real EDNS query would be).
func spoofguardQuery() *dns.Msg {
	m := &dns.Msg{}
	dnsutil.SetQuestion(m, "example.com.", dns.TypeA)
	m.UDPSize = 4096
	return m
}

func aRR(ip string) *dns.A {
	return &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 60}, Addr: netip.MustParseAddr(ip)}
}

func optRR() *dns.OPT {
	return &dns.OPT{Hdr: dns.Header{Name: "."}}
}

// TestSpoofguard_NonEDNSSingleAnswer_CollectedAsFallback locks in that a
// NOERROR single-answer non-EDNS response is collected as the low-priority
// fallback, never dropped as a "GFW signature".
// Legitimate authorities that do not echo EDNS return exactly this shape
// (github.com nsone) — dropping it made every such query block the full 9s
// budget and SERVFAIL.  pickBest must return the fallback when no EDNS
// candidate arrives.
func TestSpoofguard_NonEDNSSingleAnswer_CollectedAsFallback(t *testing.T) {
	raw := spoofguardResponse(t, []dns.RR{aRR("93.46.8.89")}, nil, nil, dns.RcodeSuccess)

	s := &spoofguardState{}
	if resp := s.processPacket(raw, len(raw), spoofguardQuery(), "1.2.3.4:53", false, 64, true); resp != nil {
		t.Fatalf("expected nil (continue collecting), got a response")
	}
	if s.nonEDNS == nil {
		t.Fatal("single-answer non-EDNS must be collected as the fallback candidate")
	}
	if s.nonEDNSAns != 1 {
		t.Fatalf("nonEDNSAns = %d, want 1", s.nonEDNSAns)
	}
	if s.rejected != 1 {
		t.Fatalf("rejected/collected counter = %d, want 1", s.rejected)
	}
	if s.nonEDNSSafe {
		t.Fatal("bare single-answer non-EDNS must be marked ambiguous (nonEDNSSafe=false)")
	}
	if best, _ := s.pickBest(); best == nil {
		t.Fatal("pickBest must return the non-EDNS fallback")
	}
}

// TestSpoofguard_NonEDNS_CNAME_Safe verifies CNAME-bearing non-EDNS
// responses are marked safe — GFW does not inject CNAME chains, so they can
// be served directly without a confirmation re-query.
func TestSpoofguard_NonEDNS_CNAME_Safe(t *testing.T) {
	m := &dns.Msg{}
	dnsutil.SetQuestion(m, "example.com.", dns.TypeA)
	m.Response = true
	m.Answer = []dns.RR{&dns.CNAME{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}, Target: "www.example.net."}}
	if err := m.Pack(); err != nil {
		t.Fatalf("pack: %v", err)
	}
	raw := m.Data

	s := &spoofguardState{}
	if resp := s.processPacket(raw, len(raw), spoofguardQuery(), "1.2.3.4:53", false, 64, true); resp != nil {
		t.Fatalf("expected nil (continue collecting), got a response")
	}
	if !s.nonEDNSSafe {
		t.Fatal("CNAME-bearing non-EDNS must be marked safe (nonEDNSSafe=true)")
	}
}

// TestSameUDPAnswer verifies the re-query confirmation comparison: the same
// answer records match regardless of TTL, and differing records do not.
func TestSameUDPAnswer(t *testing.T) {
	mk := func(ip string, ttl uint32) *dns.Msg {
		m := &dns.Msg{}
		dnsutil.SetQuestion(m, "example.com.", dns.TypeA)
		m.Response = true
		m.Answer = []dns.RR{&dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: ttl}, Addr: netip.MustParseAddr(ip)}}
		return m
	}
	if !sameUDPAnswer(mk("142.250.80.4", 300), mk("142.250.80.4", 300)) {
		t.Error("identical answers must match")
	}
	if !sameUDPAnswer(mk("142.250.80.4", 300), mk("142.250.80.4", 250)) {
		t.Error("answers must match with different TTLs (TTL is not part of the answer identity)")
	}
	if sameUDPAnswer(mk("142.250.80.4", 300), mk("93.46.8.89", 300)) {
		t.Error("different A records must not match")
	}
	if sameUDPAnswer(mk("142.250.80.4", 300), nil) {
		t.Error("nil must not match")
	}
}

// TestSpoofguard_EDNSPreferredOverNonEDNSFallback verifies the anti-poison
// property that remains after the change: when a real EDNS-bearing response
// arrives after an injected bare-A fake, pickBest returns the EDNS response
// and discards the fallback.
func TestSpoofguard_EDNSPreferredOverNonEDNSFallback(t *testing.T) {
	s := &spoofguardState{}

	fakeRaw := spoofguardResponse(t, []dns.RR{aRR("93.46.8.89")}, nil, nil, dns.RcodeSuccess)
	if resp := s.processPacket(fakeRaw, len(fakeRaw), spoofguardQuery(), "1.2.3.4:53", false, 64, true); resp != nil {
		t.Fatal("injected bare-A fake must be collected as fallback, not returned")
	}

	realRaw := spoofguardResponse(t, []dns.RR{aRR("142.250.80.4")}, nil, []dns.RR{optRR()}, dns.RcodeSuccess)
	if resp := s.processPacket(realRaw, len(realRaw), spoofguardQuery(), "1.2.3.4:53", false, 64, true); resp != nil {
		t.Fatal("EDNS response without TTL confidence must be collected, not returned")
	}

	best, _ := s.pickBest()
	if best == nil {
		t.Fatal("pickBest returned nil")
	}
	if s.nonEDNS != nil {
		t.Fatal("pickBest must discard the non-EDNS fallback when an EDNS candidate exists")
	}
	got := ""
	for _, rr := range best.Answer {
		if a, ok := rr.(*dns.A); ok {
			got = a.A.String()
			break
		}
	}
	if got != "142.250.80.4" {
		t.Fatalf("pickBest must return the EDNS real response, got %q", got)
	}
}

// TestSpoofguard_FastReturn_AuthoritySignals verifies the unchanged fast-return
// paths: NS>0 and AN>=2 return immediately without candidate collection.
func TestSpoofguard_FastReturn_AuthoritySignals(t *testing.T) {
	// NS>0 (referral/NXDOMAIN authority section) — strong authority signal.
	nsRaw := spoofguardResponse(t, nil, []dns.RR{
		&dns.NS{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}, Ns: "ns1.example.com."},
	}, nil, dns.RcodeSuccess)
	s := &spoofguardState{}
	if resp := s.processPacket(nsRaw, len(nsRaw), spoofguardQuery(), "1.2.3.4:53", false, 64, true); resp == nil {
		t.Fatal("NS>0 must fast-return")
	}

	// AN>=2 — multi-answer responses are inherently trustworthy.
	anRaw := spoofguardResponse(t, []dns.RR{aRR("1.1.1.1"), aRR("1.0.0.1")}, nil, nil, dns.RcodeSuccess)
	s2 := &spoofguardState{}
	if resp := s2.processPacket(anRaw, len(anRaw), spoofguardQuery(), "1.2.3.4:53", false, 64, true); resp == nil {
		t.Fatal("AN>=2 must fast-return")
	}
}

// TestSpoofguard_EDNSFastAccept_TTLConfident verifies hopguard TTL confidence
// fast-accepts an EDNS candidate immediately.
func TestSpoofguard_EDNSFastAccept_TTLConfident(t *testing.T) {
	raw := spoofguardResponse(t, []dns.RR{aRR("142.250.80.4")}, nil, []dns.RR{optRR()}, dns.RcodeSuccess)
	s := &spoofguardState{}
	if resp := s.processPacket(raw, len(raw), spoofguardQuery(), "1.2.3.4:53", true, 64, true); resp == nil {
		t.Fatal("TTL-confident EDNS response must fast-accept")
	}
}

// TestSpoofguard_IdenticalRepeat_ConfirmsImmediately verifies the
// identical-repeat fast path: two identical EDNS candidates confirm the
// server's answer and return immediately, instead of waiting out the collect
// window (GFW fakes vary per packet; the real answer is deterministic).
func TestSpoofguard_IdenticalRepeat_ConfirmsImmediately(t *testing.T) {
	raw := spoofguardResponse(t, []dns.RR{aRR("142.250.80.4")}, nil, []dns.RR{optRR()}, dns.RcodeSuccess)
	s := &spoofguardState{}
	if resp := s.processPacket(raw, len(raw), spoofguardQuery(), "1.2.3.4:53", false, 64, true); resp != nil {
		t.Fatalf("first EDNS candidate must collect (nil), got a response")
	}
	if resp := s.processPacket(raw, len(raw), spoofguardQuery(), "1.2.3.4:53", false, 64, true); resp == nil {
		t.Fatal("identical repeat must confirm and return immediately")
	}
}

// TestSpoofguard_MismatchedRepeat_KeepsCollecting verifies the fast path does
// not fire on divergent candidates — a fake varies per packet, so a differing
// repeat must keep collecting until the window expires.
func TestSpoofguard_MismatchedRepeat_KeepsCollecting(t *testing.T) {
	raw1 := spoofguardResponse(t, []dns.RR{aRR("142.250.80.4")}, nil, []dns.RR{optRR()}, dns.RcodeSuccess)
	raw2 := spoofguardResponse(t, []dns.RR{aRR("93.46.8.89")}, nil, []dns.RR{optRR()}, dns.RcodeSuccess)
	s := &spoofguardState{}
	if resp := s.processPacket(raw1, len(raw1), spoofguardQuery(), "1.2.3.4:53", false, 64, true); resp != nil {
		t.Fatalf("first candidate must collect (nil), got a response")
	}
	if resp := s.processPacket(raw2, len(raw2), spoofguardQuery(), "1.2.3.4:53", false, 64, true); resp != nil {
		t.Fatalf("mismatched repeat must keep collecting (nil), got a response")
	}
	if s.last == nil || s.prev == nil {
		t.Fatal("both divergent candidates must be retained for pickBest")
	}
}

// TestSpoofguard_CollectWindow_Adaptive verifies the window adapts to the
// packet count: a single datagram (nothing to compare) waits only the short
// window; a second datagram (possible injected peer) keeps the full collect
// window for comparison.
func TestSpoofguard_CollectWindow_Adaptive(t *testing.T) {
	s := &spoofguardState{}
	if w := s.collectWindow(); w != config.DefaultSpoofguardSingleWindow {
		t.Errorf("single-packet window = %v, want %v", w, config.DefaultSpoofguardSingleWindow)
	}
	s.packets = 2
	if w := s.collectWindow(); w != config.DefaultSpoofguardCollectWindow {
		t.Errorf("multi-packet window = %v, want %v", w, config.DefaultSpoofguardCollectWindow)
	}
}

// TestSpoofguard_NonNOERROR_Collected verifies a non-NOERROR response without
// authority signals is still treated as a real server signal: it is collected
// as a candidate (never dropped) and returned by pickBest.
func TestSpoofguard_NonNOERROR_Collected(t *testing.T) {
	// NXDOMAIN with no answers and no authority records — pathological, but
	// must not be dropped by the fallback gate.
	raw := spoofguardResponse(t, nil, nil, nil, dns.RcodeNameError)
	s := &spoofguardState{}
	if resp := s.processPacket(raw, len(raw), spoofguardQuery(), "1.2.3.4:53", false, 64, true); resp != nil {
		t.Fatal("non-NOERROR without authority signals must be collected, not returned early")
	}
	if s.last == nil {
		t.Fatal("non-NOERROR response must be collected as a candidate")
	}
	if best, _ := s.pickBest(); best == nil {
		t.Fatal("pickBest must return the non-NOERROR candidate")
	}
}

// TestSpoofguard_PickBest_TakesOwnership verifies pickBest clears the winning
// slot: the returned message must be the caller's only reference, so the next
// collect round can never recycle it while still referenced.
func TestSpoofguard_PickBest_TakesOwnership(t *testing.T) {
	raw := spoofguardResponse(t, []dns.RR{aRR("93.46.8.89")}, nil, nil, dns.RcodeSuccess)
	s := &spoofguardState{}
	if resp := s.processPacket(raw, len(raw), spoofguardQuery(), "1.2.3.4:53", false, 64, true); resp != nil {
		t.Fatal("expected nil (continue collecting)")
	}
	best, ttl := s.pickBest()
	if best == nil {
		t.Fatal("pickBest must return the fallback")
	}
	if ttl != 64 {
		t.Fatalf("pickBest TTL = %d, want 64", ttl)
	}
	if s.nonEDNS != nil {
		t.Fatal("pickBest must clear the winning slot")
	}
}

// TestSpoofguard_QuestionMismatch_Dropped verifies a datagram that does not
// echo the query's question never enters the candidate set, whatever its
// fast signals say.
func TestSpoofguard_QuestionMismatch_Dropped(t *testing.T) {
	m := &dns.Msg{}
	dnsutil.SetQuestion(m, "other.example.org.", dns.TypeA)
	m.Response = true
	m.Answer = []dns.RR{aRR("93.46.8.89"), aRR("93.46.8.90")}
	if err := m.Pack(); err != nil {
		t.Fatalf("pack: %v", err)
	}
	s := &spoofguardState{}
	if resp := s.processPacket(m.Data, len(m.Data), spoofguardQuery(), "1.2.3.4:53", false, 64, true); resp != nil {
		t.Fatal("question-mismatched datagram must be dropped even with AN>=2")
	}
	if s.last != nil || s.nonEDNS != nil {
		t.Fatal("no candidate may be retained from a mismatched datagram")
	}
}

// TestSpoofguard_HopGuardOnly_LearningUsesCollectDiscipline verifies the
// hopguard-only mode does NOT return the first matching datagram while the
// TTL baseline is unarmed: during learning it falls through to the full
// collect discipline so the baseline can only be fed corroborated samples
// (window-silence singles or identical repeats) — a first-datagram return
// under injection would teach the injector's TTL 1:1.
func TestSpoofguard_HopGuardOnly_LearningUsesCollectDiscipline(t *testing.T) {
	raw := spoofguardResponse(t, []dns.RR{aRR("93.46.8.89")}, nil, []dns.RR{optRR()}, dns.RcodeSuccess)

	// Unarmed (ttlConfident=false): no direct return — collected.
	s := &spoofguardState{}
	if resp := s.processPacket(raw, len(raw), spoofguardQuery(), "1.2.3.4:53", false, 64, false); resp != nil {
		t.Fatal("hopguard-only learning must not return the first datagram")
	}
	if s.last == nil {
		t.Fatal("the datagram must be collected as a candidate")
	}

	// Armed (ttlConfident=true): direct return, no content heuristics.
	s = &spoofguardState{}
	if resp := s.processPacket(raw, len(raw), spoofguardQuery(), "1.2.3.4:53", true, 64, false); resp == nil {
		t.Fatal("armed hopguard-only must return the validated datagram directly")
	}
}

// TestSpoofguard_FastReturnNotConfirmedWhileUnarmed verifies the fast-signal
// return path does not mark the sample corroborated: forgeable header bits
// (AN>=2/NS>0/AD=1) must not feed an unarmed hopguard baseline.
func TestSpoofguard_FastReturnNotConfirmedWhileUnarmed(t *testing.T) {
	raw := spoofguardResponse(t, []dns.RR{aRR("93.46.8.89"), aRR("93.46.8.90")}, nil, nil, dns.RcodeSuccess)

	s := &spoofguardState{}
	resp := s.processPacket(raw, len(raw), spoofguardQuery(), "1.2.3.4:53", false, 64, true)
	if resp == nil {
		t.Fatal("fast-signal return expected")
	}
	if s.confirmed {
		t.Fatal("fast-signal return must not count as corroborated (sg.confirmed)")
	}
}

// TestSpoofguard_IdenticalRepeatMarksConfirmed verifies the repeat-confirm
// branch sets sg.confirmed so the unarmed Feed sites accept the sample.
func TestSpoofguard_IdenticalRepeatMarksConfirmed(t *testing.T) {
	raw := spoofguardResponse(t, []dns.RR{aRR("93.46.8.89")}, nil, []dns.RR{optRR()}, dns.RcodeSuccess)

	s := &spoofguardState{}
	if resp := s.processPacket(raw, len(raw), spoofguardQuery(), "1.2.3.4:53", false, 64, true); resp != nil {
		t.Fatal("first candidate must be collected, not returned")
	}
	resp := s.processPacket(raw, len(raw), spoofguardQuery(), "1.2.3.4:53", false, 64, true)
	if resp == nil {
		t.Fatal("identical repeat must confirm and return")
	}
	if !s.confirmed {
		t.Fatal("repeat-confirm must set sg.confirmed")
	}
}

// TestSpoofguard_NonEDNSQueryResponse_UsesFallbackSlot verifies responses to
// a non-EDNS query (RFC 6891 §6.2.2 FORMERR retry) go through the non-EDNS
// fallback slot with ambiguity marking — a bare single-answer response must
// not be served as an unconfirmed direct candidate.
func TestSpoofguard_NonEDNSQueryResponse_UsesFallbackSlot(t *testing.T) {
	raw := spoofguardResponse(t, []dns.RR{aRR("93.46.8.89")}, nil, nil, dns.RcodeSuccess)

	// Query without UDPSize — the FORMERR-retry shape.
	query := &dns.Msg{}
	dnsutil.SetQuestion(query, "example.com.", dns.TypeA)

	s := &spoofguardState{}
	if resp := s.processPacket(raw, len(raw), query, "1.2.3.4:53", false, 64, true); resp != nil {
		t.Fatal("bare single answer to a non-EDNS query must be collected, not returned")
	}
	if s.nonEDNS == nil {
		t.Fatal("response must land in the non-EDNS fallback slot")
	}
	if s.nonEDNSSafe {
		t.Fatal("bare single-answer A is ambiguous (nonEDNSSafe=false)")
	}
}
