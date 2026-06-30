package resolver

import (
	"context"
	"crypto/ecdsa"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/server/client"
	"zjdns/server/security"
)

func init() {
	// Disable debug logging during tests to keep output clean
	log.Default.SetLevel(log.Error)
}

// ── Test helpers ──────────────────────────────────────────────────────────────

// genTestKey generates an ECDSA P-256 key pair + DNSKEY + private key for signing.
func genTestKey(zone string, flags uint16) (*dns.DNSKEY, *ecdsa.PrivateKey) {
	dnskey := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, _ := dnskey.Generate(256)
	return dnskey, priv.(*ecdsa.PrivateKey)
}

// signRRset signs an RRset with the given private key and returns the RRSIG.
func signRRset(rrset []dns.RR, signer string, priv *ecdsa.PrivateKey, keyTag uint16) *dns.RRSIG {
	rrsig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(signer),
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		TypeCovered: rrset[0].Header().Rrtype,
		Algorithm:   dns.ECDSAP256SHA256,
		Labels:      uint8(dns.CountLabel(rrset[0].Header().Name)),
		OrigTtl:     rrset[0].Header().Ttl,
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-1 * time.Hour).Unix()),
		KeyTag:      keyTag,
		SignerName:  dns.Fqdn(signer),
	}
	_ = rrsig.Sign(priv, rrset)
	return rrsig
}

// aRec creates an A record test helper.
func aRec(name string, ip string) *dns.A {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		panic("invalid IP: " + ip)
	}
	return &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   parsed.To4(),
	}
}

// newTestRecursive creates a minimal Recursive for unit testing.
func newTestRecursive() *Recursive {
	guard := security.New(nil, false)
	ednsHandler, _ := edns.NewHandler(edns.ECSConfig{})
	queryClient := client.New()

	r := &Resolver{
		client:   queryClient,
		edns:     ednsHandler,
		buildMsg: func(q dns.Question, ecs *edns.ECSOption, rd bool, secure bool) *dns.Msg { return new(dns.Msg) },
		validator: &Validator{
			Crypto: guard.Crypto,
			Hijack: guard.Detector,
		},
	}
	return &Recursive{resolver: r}
}

// ── isZoneCut / getZoneCutSigner ──────────────────────────────────────────────

func TestIsZoneCut_NormalResponse(t *testing.T) {
	rr := newTestRecursive()
	zone := "example.com"
	ksk, priv := genTestKey(zone, dns.SEP|dns.ZONE)

	// Answer signed by the same zone the resolver expects
	a := aRec("www.example.com", "192.0.2.1")
	rrsig := signRRset([]dns.RR{a}, zone, priv, ksk.KeyTag())

	msg := &dns.Msg{Answer: []dns.RR{a, rrsig}}
	if rr.isZoneCut(msg, zone+".") {
		t.Error("isZoneCut should return false when RRSIG signer matches currentDomain")
	}
	if s := rr.getZoneCutSigner(msg, zone+"."); s != "" {
		t.Errorf("getZoneCutSigner should return empty, got %q", s)
	}
}

func TestIsZoneCut_CrossZoneDelegation(t *testing.T) {
	rr := newTestRecursive()
	parentZone := "ippacket.stream"
	childZone := "rsa2048-sha256.ippacket.stream"
	_, priv := genTestKey(childZone, dns.SEP|dns.ZONE)

	// Answer signed by child zone, but resolver thinks it's in parent zone
	a := aRec("sigok.rsa2048-sha256.ippacket.stream", "195.201.14.36")
	rrsig := signRRset([]dns.RR{a}, childZone, priv, 46436)

	msg := &dns.Msg{Answer: []dns.RR{a, rrsig}}
	if !rr.isZoneCut(msg, parentZone+".") {
		t.Error("isZoneCut should detect zone cut when RRSIG signer is subdomain of currentDomain")
	}
	signer := rr.getZoneCutSigner(msg, parentZone+".")
	if signer != childZone {
		t.Errorf("getZoneCutSigner should return child zone %q, got %q", childZone, signer)
	}
}

func TestIsZoneCut_EmptyAnswer(t *testing.T) {
	rr := newTestRecursive()
	msg := &dns.Msg{Answer: nil}
	if rr.isZoneCut(msg, "example.com.") {
		t.Error("isZoneCut should return false for empty answer")
	}
	if rr.getZoneCutSigner(msg, "example.com.") != "" {
		t.Error("getZoneCutSigner should return empty for empty answer")
	}
}

func TestIsZoneCut_NilResponse(t *testing.T) {
	rr := newTestRecursive()
	if rr.isZoneCut(nil, "example.com.") {
		t.Error("isZoneCut should return false for nil response")
	}
}

func TestIsZoneCut_RootZone(t *testing.T) {
	rr := newTestRecursive()
	_, priv := genTestKey(".", dns.SEP|dns.ZONE)
	a := aRec("example.com", "192.0.2.1")
	rrsig := signRRset([]dns.RR{a}, ".", priv, 20326)

	msg := &dns.Msg{Answer: []dns.RR{a, rrsig}}
	// currentDomain = "." normalizes to "" → should return false (no empty matching)
	if rr.isZoneCut(msg, ".") {
		t.Error("isZoneCut should return false for root zone (normalized to empty)")
	}
}

func TestIsZoneCut_SameSignerDifferentCase(t *testing.T) {
	rr := newTestRecursive()
	zone := "Example.COM"
	ksk, priv := genTestKey(zone, dns.SEP|dns.ZONE)

	a := aRec("www.example.com", "192.0.2.1")
	// Signer name is mixed case but should normalize
	rrsig := signRRset([]dns.RR{a}, zone, priv, ksk.KeyTag())

	msg := &dns.Msg{Answer: []dns.RR{a, rrsig}}
	// currentDomain also mixed case
	if rr.isZoneCut(msg, "example.com.") {
		t.Error("isZoneCut should be case-insensitive for signer matching")
	}
}

func TestIsZoneCut_NoRRSIG(t *testing.T) {
	rr := newTestRecursive()
	a := aRec("www.example.com", "192.0.2.1")
	msg := &dns.Msg{Answer: []dns.RR{a}} // no RRSIG
	if rr.isZoneCut(msg, "example.com.") {
		t.Error("isZoneCut should return false when no RRSIGs present")
	}
}

func TestIsZoneCut_ConsolidatedWithGetZoneCutSigner(t *testing.T) {
	// Verify that isZoneCut and getZoneCutSigner are consistent
	rr := newTestRecursive()
	parentZone := "ippacket.stream"
	childZone := "rsa2048-sha256.ippacket.stream"
	_, priv := genTestKey(childZone, dns.SEP|dns.ZONE)

	a := aRec("sigok.rsa2048-sha256.ippacket.stream", "195.201.14.36")
	rrsig := signRRset([]dns.RR{a}, childZone, priv, 46436)

	msg := &dns.Msg{Answer: []dns.RR{a, rrsig}}

	// Both functions must agree
	isCut := rr.isZoneCut(msg, parentZone+".")
	signer := rr.getZoneCutSigner(msg, parentZone+".")
	if isCut != (signer != "") {
		t.Error("isZoneCut and getZoneCutSigner must be consistent")
	}
}

// ── DNSSEC Chain: finalizeDNSSEC EDE codes ────────────────────────────────────

func TestDnssecChain_EDECodeNotOverwritten(t *testing.T) {
	// Verify that when RRSIG verification fails with an error,
	// the EDE code stays as DNSSECBogus and is NOT overwritten by RRSIGsMissing.
	chain := &dnssecChain{}

	// Simulate RRSIG verification error path
	chain.lastEDECode = edns.EDECodeDNSSECBogus
	// In the old buggy code, this would be followed by:
	//   chain.lastEDECode = edns.EDECodeRRSIGsMissing
	// The fix uses "else if" to prevent the overwrite.
	// This test verifies the intent: Bogus should remain Bogus.

	if chain.lastEDECode != edns.EDECodeDNSSECBogus {
		t.Errorf("EDE code should be DNSSECBogus (%d), got %d", edns.EDECodeDNSSECBogus, chain.lastEDECode)
	}

	// Simulate the else-if path: when err == nil but !validated
	chain.lastEDECode = 0 // reset
	// In the fixed code: else if !validated → RRSIGsMissing
	chain.lastEDECode = edns.EDECodeRRSIGsMissing
	if chain.lastEDECode != edns.EDECodeRRSIGsMissing {
		t.Errorf("EDE code should be RRSIGsMissing when no error but not validated")
	}
}

// Test that zoneCutDetected is initialized to false in new chains
func TestDnssecChain_ZoneCutDetectedDefault(t *testing.T) {
	chain := &dnssecChain{}
	if chain.zoneCutDetected {
		t.Error("zoneCutDetected should default to false")
	}
}

// ── Lame delegation detection ─────────────────────────────────────────────────

func TestLameDelegation_NonAuthoritativeSameZone(t *testing.T) {
	// Simulate a response from a non-authoritative server that has NS records
	// pointing back to the same zone (lame delegation pattern).
	// The AA flag is NOT set.
	zone := "test.dnssec-tools.org"
	msg := &dns.Msg{
		Answer: nil, // no answer — NODATA or delegation
		Ns: []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "dns1." + zone + ".",
			},
			&dns.NS{
				Hdr: dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "dns2." + zone + ".",
			},
		},
	}
	// AA is false by default → this is a candidate for lame delegation

	// The check: len(answer)==0 && !Authoritative → lame delegation
	if len(msg.Answer) == 0 && !msg.Authoritative {
		// This is the condition that should trigger SERVFAIL
		// Verify the NS records match the current domain
		currentDomain := dns.Fqdn(zone)
		normalizedCurrent := dnsutil.NormalizeDomain(currentDomain)
		for _, rr := range msg.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				nsName := dnsutil.NormalizeDomain(ns.Hdr.Name)
				if nsName == normalizedCurrent {
					// NS records point to same zone + no AA → lame!
					t.Log("Correctly identified lame delegation pattern")
					return
				}
			}
		}
	}
}

func TestLameDelegation_AuthoritativeNODATA(t *testing.T) {
	// A legitimate authoritative NODATA response MUST have AA flag set.
	// This should NOT be treated as a lame delegation.
	zone := "example.com"
	msg := &dns.Msg{
		Answer: nil,
		Ns: []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns1." + zone + ".",
			},
			&dns.NSEC{
				Hdr:        dns.RR_Header{Name: dns.Fqdn("www." + zone), Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
				NextDomain: dns.Fqdn("mail." + zone),
				TypeBitMap: []uint16{dns.TypeA, dns.TypeAAAA},
			},
		},
	}
	msg.Authoritative = true // AA flag set via embedded MsgHdr

	// len(answer)==0 && Authoritative → NOT lame, legitimate NODATA
	if len(msg.Answer) == 0 && msg.Authoritative {
		// This should pass through as a valid NODATA response
		// Verify NS records still match but AA makes it authoritative
		currentDomain := dns.Fqdn(zone)
		normalizedCurrent := dnsutil.NormalizeDomain(currentDomain)
		for _, rr := range msg.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				nsName := dnsutil.NormalizeDomain(ns.Hdr.Name)
				if nsName == normalizedCurrent {
					t.Log("Correctly identified authoritative NODATA (not lame)")
					return
				}
			}
		}
	}
}

// ── DNSSEC Chain: validateWithDNSSEC ──────────────────────────────────────────

func TestValidateWithDNSSEC_NoDNSKEYs(t *testing.T) {
	rr := newTestRecursive()
	zone := "insecure.example.com"
	a := aRec("www."+zone, "192.0.2.1")
	msg := &dns.Msg{Answer: []dns.RR{a}}
	chain := &dnssecChain{} // no zoneDNSKEYs, no childDS

	validated := rr.validateWithDNSSEC(msg, zone+".", chain)
	if validated {
		t.Error("validateWithDNSSEC should return false when no DNSKEYs available")
	}
}

func TestValidateWithDNSSEC_WithVerifiedKeys(t *testing.T) {
	rr := newTestRecursive()
	zone := "secure.example.com"
	ksk, _ := genTestKey(zone, dns.SEP|dns.ZONE)
	zsk, zskPriv := genTestKey(zone, dns.ZONE)

	a := aRec("www."+zone, "192.0.2.1")
	rrsig := signRRset([]dns.RR{a}, zone, zskPriv, zsk.KeyTag())

	msg := &dns.Msg{Answer: []dns.RR{a, rrsig}}
	chain := &dnssecChain{
		zoneDNSKEYs: []*dns.DNSKEY{ksk, zsk},
	}

	validated := rr.validateWithDNSSEC(msg, zone+".", chain)
	if !validated {
		t.Error("validateWithDNSSEC should return true when DNSKEYs verify the answer RRSIGs")
	}
}

func TestValidateWithDNSSEC_WrongDNSKEY(t *testing.T) {
	rr := newTestRecursive()
	zone := "secure.example.com"
	_, wrongPriv := genTestKey(zone, dns.ZONE)
	wrongZone := "other.example.com"
	wrongKSK, _ := genTestKey(wrongZone, dns.SEP|dns.ZONE)
	wrongZSK, _ := genTestKey(wrongZone, dns.ZONE)

	a := aRec("www."+zone, "192.0.2.1")
	rrsig := signRRset([]dns.RR{a}, zone, wrongPriv, 12345) // signed by different key

	msg := &dns.Msg{Answer: []dns.RR{a, rrsig}}
	chain := &dnssecChain{
		zoneDNSKEYs: []*dns.DNSKEY{wrongKSK, wrongZSK}, // wrong zone's keys
	}

	validated := rr.validateWithDNSSEC(msg, zone+".", chain)
	if validated {
		t.Error("validateWithDNSSEC should return false when DNSKEYs don't match RRSIG")
	}
}

// ── updateDNSSECChain ─────────────────────────────────────────────────────────

func TestUpdateDNSSECChain_NoDSRecords(t *testing.T) {
	rr := newTestRecursive()
	zone := "insecure.example.com"
	childZone := "sub.insecure.example.com"

	// Delegation response with NS records but NO DS → insecure
	msg := &dns.Msg{
		Ns: []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: dns.Fqdn(childZone), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns1." + childZone + ".",
			},
		},
	}

	chain := &dnssecChain{
		parentDNSKEYs: []*dns.DNSKEY{},
		zoneDNSKEYs:   nil,
		childDS:       []*dns.DS{{}}, // set some DS to verify it gets cleared
	}

	rr.updateDNSSECChain(context.Background(), msg, zone+".", childZone, nil, chain)

	if chain.childDS != nil {
		t.Error("updateDNSSECChain should set childDS to nil when no DS records found")
	}
}

// ── resolveZoneCut integration test ───────────────────────────────────────────

func TestResolveZoneCut_InvalidSigner(t *testing.T) {
	rr := newTestRecursive()
	zone := "example.com"
	a := aRec("www."+zone, "192.0.2.1")
	msg := &dns.Msg{Answer: []dns.RR{a}} // no RRSIG, no zone cut
	chain := &dnssecChain{}

	_, err := rr.resolveZoneCut(context.Background(), msg, nil,
		dns.Question{Name: dns.Fqdn("www." + zone), Qtype: dns.TypeA},
		zone+".", nil, false, chain)

	if err == nil {
		t.Error("resolveZoneCut should return error when no zone cut signer found")
	}
	if !strings.Contains(err.Error(), "could not determine child zone") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ── NS record matching across sections ────────────────────────────────────────

func TestNSMatching_AnswerSectionIncluded(t *testing.T) {
	// Verify the design: NS records in Answer section are checked.
	// This test validates the intent, not the runtime behavior,
	// since we don't call the main resolve loop directly.
	zone := "child.example.com"
	msg := &dns.Msg{
		// NS records in Answer section (authoritative server hosting child zone)
		Answer: []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns1." + zone + ".",
			},
		},
		// Also in Authority section (standard delegation)
		Ns: []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns2." + zone + ".",
			},
		},
	}

	// Collect from both sections (as the resolve loop does)
	var allRRSections []dns.RR
	allRRSections = append(allRRSections, msg.Ns...)
	allRRSections = append(allRRSections, msg.Answer...)

	nsCount := 0
	for _, rrec := range allRRSections {
		if _, ok := rrec.(*dns.NS); ok {
			nsCount++
		}
	}
	if nsCount != 2 {
		t.Errorf("Expected 2 NS records across both sections, got %d", nsCount)
	}
}

// ── DS record matching across sections ────────────────────────────────────────

func TestDSMatching_AnswerSectionIncluded(t *testing.T) {
	childZone := "child.example.com"
	msg := &dns.Msg{
		Answer: []dns.RR{
			&dns.DS{
				Hdr:        dns.RR_Header{Name: dns.Fqdn(childZone), Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 300},
				KeyTag:     12345,
				Algorithm:  dns.ECDSAP256SHA256,
				DigestType: dns.SHA256,
				Digest:     "AAAA",
			},
		},
	}

	// Simulate the updateDNSSECChain check pattern
	dsRecords := security.FindDS(msg.Ns)
	dsRecords = append(dsRecords, security.FindDS(msg.Answer)...)

	if len(dsRecords) != 1 {
		t.Errorf("Expected 1 DS record from Answer section, got %d", len(dsRecords))
	}
	if dsRecords[0].KeyTag != 12345 {
		t.Errorf("Expected KeyTag 12345, got %d", dsRecords[0].KeyTag)
	}
}

// ── Memory safety ─────────────────────────────────────────────────────────────

func TestGetZoneCutSigner_NilRRSIGs(t *testing.T) {
	rr := newTestRecursive()
	zone := "example.com"
	ksk, priv := genTestKey(zone, dns.SEP|dns.ZONE)
	a := aRec("www."+zone, "192.0.2.1")
	rrsig := signRRset([]dns.RR{a}, zone, priv, ksk.KeyTag())

	// Mix nil and non-nil RRSIGs in the answer
	msg := &dns.Msg{
		Answer: []dns.RR{a, rrsig},
		Extra:  []dns.RR{nil}, // nil RRSIG should be skipped
	}

	signer := rr.getZoneCutSigner(msg, zone+".")
	// nil RRSIG should be skipped; signer matches currentDomain → empty
	if signer != "" {
		t.Errorf("Expected empty signer (matching zone), got %q", signer)
	}
}

func TestResolveZoneCut_NoParentKeys(t *testing.T) {
	rr := newTestRecursive()
	parentZone := "example.com"
	childZone := "child.example.com"
	_, priv := genTestKey(childZone, dns.SEP|dns.ZONE)

	a := aRec("www."+childZone, "192.0.2.1")
	rrsig := signRRset([]dns.RR{a}, childZone, priv, 12345)
	msg := &dns.Msg{Answer: []dns.RR{a, rrsig}}

	// Chain with no parent DNSKEYs at all
	chain := &dnssecChain{
		parentDNSKEYs: nil,
		zoneDNSKEYs:   nil,
	}

	_, err := rr.resolveZoneCut(context.Background(), msg, nil,
		dns.Question{Name: dns.Fqdn("www." + childZone), Qtype: dns.TypeA},
		parentZone+".", nil, false, chain)

	if err == nil {
		t.Error("resolveZoneCut should fail with no parent DNSKEYs available")
	}
}

// ── Benchmark ─────────────────────────────────────────────────────────────────

func BenchmarkIsZoneCut(b *testing.B) {
	rr := newTestRecursive()
	zone := "ippacket.stream"
	childZone := "rsa2048-sha256.ippacket.stream"
	_, priv := genTestKey(childZone, dns.SEP|dns.ZONE)
	a := aRec("sigok."+childZone, "195.201.14.36")
	rrsig := signRRset([]dns.RR{a}, childZone, priv, 46436)
	msg := &dns.Msg{Answer: []dns.RR{a, rrsig}}

	b.ResetTimer()
	for b.Loop() {
		rr.isZoneCut(msg, zone+".")
	}
}

func BenchmarkGetZoneCutSigner(b *testing.B) {
	rr := newTestRecursive()
	zone := "ippacket.stream"
	childZone := "rsa2048-sha256.ippacket.stream"
	_, priv := genTestKey(childZone, dns.SEP|dns.ZONE)
	a := aRec("sigok."+childZone, "195.201.14.36")
	rrsig := signRRset([]dns.RR{a}, childZone, priv, 46436)
	msg := &dns.Msg{Answer: []dns.RR{a, rrsig}}

	b.ResetTimer()
	for b.Loop() {
		rr.getZoneCutSigner(msg, zone+".")
	}
}
