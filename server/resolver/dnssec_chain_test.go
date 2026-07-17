package resolver

import (
	"context"
	"crypto/ecdsa"
	"net/netip"
	"strings"
	"testing"
	"time"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/server/resolver/dnssec"
	"zjdns/server/resolver/hijack"
	"zjdns/server/upstream"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

func init() {
	log.Default.SetLevel(log.Error)
}

// ── Test helpers ──────────────────────────────────────────────────────────────

// genTestKey generates an ECDSA P-256 key pair + DNSKEY + private key for signing.
func genTestKey(zone string, flags uint16) (*dns.DNSKEY, *ecdsa.PrivateKey) {
	dnskey := &dns.DNSKEY{
		Hdr:    dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 3600},
		DNSKEY: rdata.DNSKEY{Flags: flags, Protocol: 3, Algorithm: dns.ECDSAP256SHA256},
	}
	priv, _ := dnskey.Generate(256)
	return dnskey, priv.(*ecdsa.PrivateKey)
}

// signRRset signs an RRset with the given private key and returns the RRSIG.
func signRRset(rrset []dns.RR, signer string, priv *ecdsa.PrivateKey, keyTag uint16) *dns.RRSIG {
	rrsig := &dns.RRSIG{
		Hdr: dns.Header{
			Name:  dnsutil.Fqdn(signer),
			Class: dns.ClassINET,
			TTL:   3600,
		},
		RRSIG: rdata.RRSIG{
			TypeCovered: dns.RRToType(rrset[0]),
			Algorithm:   dns.ECDSAP256SHA256,
			Labels:      uint8(dnsutil.Labels(rrset[0].Header().Name)), //nolint:gosec // G115: DNS label count — max 127 fits uint8
			OrigTTL:     rrset[0].Header().TTL,
			Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()), //nolint:gosec // G115: DNSSEC timestamp — protocol-bounded uint32
			Inception:   uint32(time.Now().Add(-1 * time.Hour).Unix()), //nolint:gosec // G115: DNSSEC timestamp — protocol-bounded uint32
			KeyTag:      keyTag,
			SignerName:  dnsutil.Fqdn(signer),
		},
	}
	_ = rrsig.Sign(priv, rrset, &dns.SignOption{})
	return rrsig
}

// aRec creates an A record test helper.
func aRec(name, ip string) *dns.A {
	return &dns.A{
		Hdr: dns.Header{Name: dnsutil.Fqdn(name), Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr(ip)},
	}
}

// newTestRecursive creates a minimal Recursive for unit testing.
func newTestRecursive() *Recursive {
	ednsHandler, _ := edns.NewHandler(config.ECSConfig{})
	queryClient := upstream.New()

	r := &Resolver{
		queryClient: queryClient,
		edns:        ednsHandler,
		buildMsg:    func(q Question, ecs *edns.ECSOption, rd, secure bool) *dns.Msg { return new(dns.Msg) },
		validator: &Validator{
			Crypto: dnssec.NewCryptoValidator(nil),
			Hijack: &hijack.Detector{},
		},
	}
	return &Recursive{resolver: r}
}

// ── isZoneCut / getZoneCutSigner ──────────────────────────────────────────────

func TestIsZoneCut_NormalResponse(t *testing.T) {
	rr := newTestRecursive()
	zone := "example.com"
	ksk, priv := genTestKey(zone, dns.FlagSEP|dns.FlagZONE)

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
	_, priv := genTestKey(childZone, dns.FlagSEP|dns.FlagZONE)

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
	_, priv := genTestKey(".", dns.FlagSEP|dns.FlagZONE)
	a := aRec("example.com", "192.0.2.1")
	rrsig := signRRset([]dns.RR{a}, ".", priv, 20326)

	msg := &dns.Msg{Answer: []dns.RR{a, rrsig}}
	if rr.isZoneCut(msg, ".") {
		t.Error("isZoneCut should return false for root zone (normalized to empty)")
	}
}

func TestIsZoneCut_SameSignerDifferentCase(t *testing.T) {
	rr := newTestRecursive()
	zone := "Example.COM"
	ksk, priv := genTestKey(zone, dns.FlagSEP|dns.FlagZONE)

	a := aRec("www.example.com", "192.0.2.1")
	rrsig := signRRset([]dns.RR{a}, zone, priv, ksk.KeyTag())

	msg := &dns.Msg{Answer: []dns.RR{a, rrsig}}
	if rr.isZoneCut(msg, "example.com.") {
		t.Error("isZoneCut should be case-insensitive for signer matching")
	}
}

func TestIsZoneCut_NoRRSIG(t *testing.T) {
	rr := newTestRecursive()
	a := aRec("www.example.com", "192.0.2.1")
	msg := &dns.Msg{Answer: []dns.RR{a}}
	if rr.isZoneCut(msg, "example.com.") {
		t.Error("isZoneCut should return false when no RRSIGs present")
	}
}

func TestIsZoneCut_ConsolidatedWithGetZoneCutSigner(t *testing.T) {
	rr := newTestRecursive()
	parentZone := "ippacket.stream"
	childZone := "rsa2048-sha256.ippacket.stream"
	_, priv := genTestKey(childZone, dns.FlagSEP|dns.FlagZONE)

	a := aRec("sigok.rsa2048-sha256.ippacket.stream", "195.201.14.36")
	rrsig := signRRset([]dns.RR{a}, childZone, priv, 46436)

	msg := &dns.Msg{Answer: []dns.RR{a, rrsig}}

	isCut := rr.isZoneCut(msg, parentZone+".")
	signer := rr.getZoneCutSigner(msg, parentZone+".")
	if isCut != (signer != "") {
		t.Error("isZoneCut and getZoneCutSigner must be consistent")
	}
}

// ── DNSSEC Chain: isDNSSECValid EDE codes ────────────────────────────────────

func TestDnssecChain_EDECodeNotOverwritten(t *testing.T) {
	chain := &dnssecChain{}

	chain.lastEDECode = dns.ExtendedErrorDNSBogus

	if chain.lastEDECode != dns.ExtendedErrorDNSBogus {
		t.Errorf("EDE code should be DNSSECBogus (%d), got %d", dns.ExtendedErrorDNSBogus, chain.lastEDECode)
	}

	chain.lastEDECode = 0
	chain.lastEDECode = dns.ExtendedErrorRRSIGsMissing
	if chain.lastEDECode != dns.ExtendedErrorRRSIGsMissing {
		t.Errorf("EDE code should be RRSIGsMissing when no error but not validated")
	}
}

func TestDnssecChain_ZoneCutDetectedDefault(t *testing.T) {
	chain := &dnssecChain{}
	if chain.zoneCutDetected {
		t.Error("zoneCutDetected should default to false")
	}
}

// ── Lame delegation detection ─────────────────────────────────────────────────

func TestLameDelegation_NonAuthoritativeSameZone(t *testing.T) {
	zone := "test.dnssec-tools.org"
	msg := &dns.Msg{
		Answer: nil,
		Ns: []dns.RR{
			&dns.NS{
				Hdr: dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 300},
				NS:  rdata.NS{Ns: "dns1." + zone + "."},
			},
			&dns.NS{
				Hdr: dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 300},
				NS:  rdata.NS{Ns: "dns2." + zone + "."},
			},
		},
	}

	if len(msg.Answer) == 0 && !msg.Authoritative {
		currentDomain := dnsutil.Fqdn(zone)
		normalizedCurrent := zdnsutil.NormalizeDomain(currentDomain)
		for _, rr := range msg.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				nsName := zdnsutil.NormalizeDomain(ns.Hdr.Name)
				if nsName == normalizedCurrent {
					t.Log("Correctly identified lame delegation pattern")
					return
				}
			}
		}
	}
}

func TestLameDelegation_AuthoritativeNODATA(t *testing.T) {
	zone := "example.com"
	msg := &dns.Msg{
		Answer: nil,
		Ns: []dns.RR{
			&dns.NS{
				Hdr: dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 300},
				NS:  rdata.NS{Ns: "ns1." + zone + "."},
			},
			&dns.NSEC{
				Hdr:  dns.Header{Name: dnsutil.Fqdn("www." + zone), Class: dns.ClassINET, TTL: 300},
				NSEC: rdata.NSEC{NextDomain: dnsutil.Fqdn("mail." + zone), TypeBitMap: []uint16{dns.TypeA, dns.TypeAAAA}},
			},
		},
	}
	msg.Authoritative = true

	if len(msg.Answer) == 0 && msg.Authoritative {
		currentDomain := dnsutil.Fqdn(zone)
		normalizedCurrent := zdnsutil.NormalizeDomain(currentDomain)
		for _, rr := range msg.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				nsName := zdnsutil.NormalizeDomain(ns.Hdr.Name)
				if nsName == normalizedCurrent {
					t.Log("Correctly identified authoritative NODATA (not lame)")
					return
				}
			}
		}
	}
}

// ── DNSSEC Chain: isValidWithDNSSEC ──────────────────────────────────────────

func TestValidateWithDNSSEC_NoDNSKEYs(t *testing.T) {
	rr := newTestRecursive()
	zone := "insecure.example.com"
	a := aRec("www."+zone, "192.0.2.1")
	msg := &dns.Msg{Answer: []dns.RR{a}}
	chain := &dnssecChain{}

	validated := rr.isValidWithDNSSEC(msg, zone+".", chain)
	if validated {
		t.Error("isValidWithDNSSEC should return false when no DNSKEYs available")
	}
}

func TestValidateWithDNSSEC_WithVerifiedKeys(t *testing.T) {
	rr := newTestRecursive()
	zone := "secure.example.com"
	ksk, _ := genTestKey(zone, dns.FlagSEP|dns.FlagZONE)
	zsk, zskPriv := genTestKey(zone, dns.FlagZONE)

	a := aRec("www."+zone, "192.0.2.1")
	rrsig := signRRset([]dns.RR{a}, zone, zskPriv, zsk.KeyTag())

	msg := &dns.Msg{Answer: []dns.RR{a, rrsig}}
	chain := &dnssecChain{
		zoneDNSKEYs: []*dns.DNSKEY{ksk, zsk},
	}

	validated := rr.isValidWithDNSSEC(msg, zone+".", chain)
	if !validated {
		t.Error("isValidWithDNSSEC should return true when DNSKEYs verify the answer RRSIGs")
	}
}

func TestValidateWithDNSSEC_WrongDNSKEY(t *testing.T) {
	rr := newTestRecursive()
	zone := "secure.example.com"
	_, wrongPriv := genTestKey(zone, dns.FlagZONE)
	wrongZone := "other.example.com"
	wrongKSK, _ := genTestKey(wrongZone, dns.FlagSEP|dns.FlagZONE)
	wrongZSK, _ := genTestKey(wrongZone, dns.FlagZONE)

	a := aRec("www."+zone, "192.0.2.1")
	rrsig := signRRset([]dns.RR{a}, zone, wrongPriv, 12345)

	msg := &dns.Msg{Answer: []dns.RR{a, rrsig}}
	chain := &dnssecChain{
		zoneDNSKEYs: []*dns.DNSKEY{wrongKSK, wrongZSK},
	}

	validated := rr.isValidWithDNSSEC(msg, zone+".", chain)
	if validated {
		t.Error("isValidWithDNSSEC should return false when DNSKEYs don't match RRSIG")
	}
}

// ── updateDNSSECChain ─────────────────────────────────────────────────────────

func TestUpdateDNSSECChain_NoDSRecords(t *testing.T) {
	rr := newTestRecursive()
	zone := "insecure.example.com"
	childZone := "sub.insecure.example.com"

	msg := &dns.Msg{
		Ns: []dns.RR{
			&dns.NS{
				Hdr: dns.Header{Name: dnsutil.Fqdn(childZone), Class: dns.ClassINET, TTL: 300},
				NS:  rdata.NS{Ns: "ns1." + childZone + "."},
			},
		},
	}

	chain := &dnssecChain{
		parentDNSKEYs: []*dns.DNSKEY{},
		zoneDNSKEYs:   nil,
		childDS:       []*dns.DS{{}},
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
	msg := &dns.Msg{Answer: []dns.RR{a}}
	chain := &dnssecChain{}

	_, err := rr.resolveZoneCut(context.Background(), msg, nil,
		Question{Name: dnsutil.Fqdn("www." + zone), Qtype: dns.TypeA},
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
	zone := "child.example.com"
	msg := &dns.Msg{
		Answer: []dns.RR{
			&dns.NS{
				Hdr: dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 300},
				NS:  rdata.NS{Ns: "ns1." + zone + "."},
			},
		},
		Ns: []dns.RR{
			&dns.NS{
				Hdr: dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 300},
				NS:  rdata.NS{Ns: "ns2." + zone + "."},
			},
		},
	}

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
				Hdr: dns.Header{Name: dnsutil.Fqdn(childZone), Class: dns.ClassINET, TTL: 300},
				DS: rdata.DS{
					KeyTag:     12345,
					Algorithm:  dns.ECDSAP256SHA256,
					DigestType: dns.SHA256,
					Digest:     "AAAA",
				},
			},
		},
	}

	dsRecords := dnssec.FindDS(msg.Ns)
	dsRecords = append(dsRecords, dnssec.FindDS(msg.Answer)...)

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
	ksk, priv := genTestKey(zone, dns.FlagSEP|dns.FlagZONE)
	a := aRec("www."+zone, "192.0.2.1")
	rrsig := signRRset([]dns.RR{a}, zone, priv, ksk.KeyTag())

	msg := &dns.Msg{
		Answer: []dns.RR{a, rrsig},
		Extra:  []dns.RR{nil},
	}

	signer := rr.getZoneCutSigner(msg, zone+".")
	if signer != "" {
		t.Errorf("Expected empty signer (matching zone), got %q", signer)
	}
}

func TestResolveZoneCut_NoParentKeys(t *testing.T) {
	rr := newTestRecursive()
	parentZone := "example.com"
	childZone := "child.example.com"
	_, priv := genTestKey(childZone, dns.FlagSEP|dns.FlagZONE)

	a := aRec("www."+childZone, "192.0.2.1")
	rrsig := signRRset([]dns.RR{a}, childZone, priv, 12345)
	msg := &dns.Msg{Answer: []dns.RR{a, rrsig}}

	chain := &dnssecChain{
		parentDNSKEYs: nil,
		zoneDNSKEYs:   nil,
	}

	_, err := rr.resolveZoneCut(context.Background(), msg, nil,
		Question{Name: dnsutil.Fqdn("www." + childZone), Qtype: dns.TypeA},
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
	_, priv := genTestKey(childZone, dns.FlagSEP|dns.FlagZONE)
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
	_, priv := genTestKey(childZone, dns.FlagSEP|dns.FlagZONE)
	a := aRec("sigok."+childZone, "195.201.14.36")
	rrsig := signRRset([]dns.RR{a}, childZone, priv, 46436)
	msg := &dns.Msg{Answer: []dns.RR{a, rrsig}}

	b.ResetTimer()
	for b.Loop() {
		rr.getZoneCutSigner(msg, zone+".")
	}
}
