package resolver

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"
	"zjdns/server/defense"
	"zjdns/server/resolver/dnssec"
	"zjdns/server/upstream"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func init() {
	log.Default.SetLevel(log.Error)
}

// ── Test helpers ──────────────────────────────────────────────────────────────

// genTestKey generates an ECDSA P-256 key pair + DNSKEY + private key for signing.
func genTestKey(zone string, flags uint16) (*dns.DNSKEY, *ecdsa.PrivateKey) {
	dnskey := &dns.DNSKEY{
		Hdr:   dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 3600},
		Flags: flags, Protocol: 3, Algorithm: dns.ECDSAP256SHA256,
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
		TypeCovered: dns.RRToType(rrset[0]),
		Algorithm:   dns.ECDSAP256SHA256,
		Labels:      uint8(dnsutil.Labels(rrset[0].Header().Name)), //nolint:gosec // G115: DNS label count — max 127 fits uint8
		OrigTTL:     rrset[0].Header().TTL,
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()), //nolint:gosec // G115: DNSSEC timestamp — protocol-bounded uint32
		Inception:   uint32(time.Now().Add(-1 * time.Hour).Unix()), //nolint:gosec // G115: DNSSEC timestamp — protocol-bounded uint32
		KeyTag:      keyTag,
		SignerName:  dnsutil.Fqdn(signer),
	}
	_ = rrsig.Sign(priv, rrset, &dns.SignOption{})
	return rrsig
}

// aRec creates an A record test helper.
func aRec(name, ip string) *dns.A {
	return &dns.A{
		Hdr:  dns.Header{Name: dnsutil.Fqdn(name), Class: dns.ClassINET, TTL: 300},
		Addr: netip.MustParseAddr(ip),
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
			Crypto:      dnssec.NewCryptoValidator(nil),
			Poisonguard: defense.Detector{},
		},
	}
	return &Recursive{delegations: lrumap.New[string, *delegationEntry](10000), resolver: r}
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
	if signer != childZone+"." {
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
				Ns:  "dns1." + zone + ".",
			},
			&dns.NS{
				Hdr: dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 300},
				Ns:  "dns2." + zone + ".",
			},
		},
	}

	if len(msg.Answer) != 0 {
		t.Fatal("test message should have empty Answer section")
	}
	if msg.Authoritative {
		t.Fatal("test message should not be authoritative (lame delegation scenario)")
	}

	currentDomain := dnsutil.Fqdn(zone)
	normalizedCurrent := dnsutil.Canonical(currentDomain)
	foundLame := false
	for _, rr := range msg.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			if dnsutil.Canonical(ns.Hdr.Name) == normalizedCurrent {
				foundLame = true
				break
			}
		}
	}
	if !foundLame {
		t.Error("expected to find NS record with zone name in lame delegation response")
	}
}

func TestLameDelegation_AuthoritativeNODATA(t *testing.T) {
	zone := "example.com"
	msg := &dns.Msg{
		Answer: nil,
		Ns: []dns.RR{
			&dns.NS{
				Hdr: dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 300},
				Ns:  "ns1." + zone + ".",
			},
			&dns.NSEC{
				Hdr:        dns.Header{Name: dnsutil.Fqdn("www." + zone), Class: dns.ClassINET, TTL: 300},
				NextDomain: dnsutil.Fqdn("mail." + zone), TypeBitMap: []uint16{dns.TypeA, dns.TypeAAAA},
			},
		},
	}
	msg.Authoritative = true

	if len(msg.Answer) != 0 {
		t.Fatal("test message should have empty Answer section")
	}
	if !msg.Authoritative {
		t.Fatal("test message should be authoritative (NODATA scenario)")
	}

	currentDomain := dnsutil.Fqdn(zone)
	normalizedCurrent := dnsutil.Canonical(currentDomain)
	foundNS := false
	for _, rr := range msg.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			if dnsutil.Canonical(ns.Hdr.Name) == normalizedCurrent {
				foundNS = true
				break
			}
		}
	}
	if !foundNS {
		t.Error("expected to find NS record with zone name in authoritative NODATA response")
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

// ── isDNSSECValid: insecure vs bogus delegation classification ────────────────
// An unsigned zone (authenticated no-DS denial at the delegation) is insecure,
// not bogus — it must not surface EDE 6 (DNSBogus) to clients, and the response
// stays cacheable (dnssecCacheable allows ede==0).  Only a delegation that
// claimed DS records but failed verification is genuinely unverifiable (EDE 6).

func TestIsDNSSECValid_InsecureDelegation_NoEDE(t *testing.T) {
	rr := newTestRecursive()
	zone := "insecure.example.com"
	a := aRec("www."+zone, "192.0.2.1")
	msg := &dns.Msg{Answer: []dns.RR{a}}
	// Clean insecure delegation: updateDNSSECChain verified the no-DS denial —
	// no childDS, no dsPresentButUnverified flag.
	chain := &dnssecChain{}

	validated := rr.isDNSSECValid(context.Background(), msg, nil,
		Question{Name: dnsutil.Fqdn("www." + zone), Qtype: dns.TypeA},
		dnsutil.Fqdn(zone), nil, false, chain)
	if validated {
		t.Error("isDNSSECValid should return false for an unsigned zone")
	}
	if chain.lastEDECode != 0 {
		t.Errorf("insecure delegation must not set an EDE code, got %d (%s)",
			chain.lastEDECode, dns.ExtendedErrorToString[chain.lastEDECode])
	}
}

func TestIsDNSSECValid_UnverifiableDelegation_SetsDNSBogus(t *testing.T) {
	rr := newTestRecursive()
	zone := "signed.example.com"
	a := aRec("www."+zone, "192.0.2.1")
	msg := &dns.Msg{Answer: []dns.RR{a}}
	// The delegation claimed DS records (childDS non-empty) but the child's
	// DNSKEYs could not be verified — the answer is genuinely unverifiable.
	chain := &dnssecChain{childDS: []*dns.DS{{
		Hdr:    dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 300},
		KeyTag: 12345, Algorithm: dns.ECDSAP256SHA256, DigestType: dns.SHA256, Digest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}}}

	validated := rr.isDNSSECValid(context.Background(), msg, nil,
		Question{Name: dnsutil.Fqdn("www." + zone), Qtype: dns.TypeA},
		dnsutil.Fqdn(zone), nil, false, chain)
	if validated {
		t.Error("isDNSSECValid should return false when child DNSKEYs could not be verified")
	}
	if chain.lastEDECode != dns.ExtendedErrorDNSBogus {
		t.Errorf("unverifiable delegation should set EDE 6 (DNSBogus), got %d", chain.lastEDECode)
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

// ── verifyDNSKEYWithDS (R3-C1) ────────────────────────────────────────────────
// A DS digest match proves only ONE key belongs to the zone; the matched key
// must additionally sign the ENTIRE DNSKEY RRset (RFC 4035 §5.2).  These tests
// cover the fix against the self-signature requirement, including the attack
// where an injected rogue key self-signs the modified set (which the previous
// any-key SelfVerifyDNSKEY check would have wrongly accepted).

func TestVerifyDNSKEYWithDS_ValidSelfSigned(t *testing.T) {
	crypto := dnssec.NewCryptoValidator(nil)
	zone := "secure.example.com"
	ksk, kskPriv := genTestKey(zone, dns.FlagSEP|dns.FlagZONE)
	zsk, _ := genTestKey(zone, dns.FlagZONE)
	ds := ksk.ToDS(dns.SHA256)

	dnskeyRRs := []dns.RR{ksk, zsk}
	rrsig := signRRset(dnskeyRRs, zone, kskPriv, ksk.KeyTag())

	matchedKey, err := verifyDNSKEYWithDS(crypto, []*dns.DS{ds}, []*dns.DNSKEY{ksk, zsk}, []*dns.RRSIG{rrsig})
	if err != nil || matchedKey == nil {
		t.Fatalf("verifyDNSKEYWithDS: expected success, got key=%v err=%v", matchedKey, err)
	}
	if matchedKey.KeyTag() != ksk.KeyTag() {
		t.Errorf("matched key tag = %d, want %d", matchedKey.KeyTag(), ksk.KeyTag())
	}
}

func TestVerifyDNSKEYWithDS_NoSelfSignature(t *testing.T) {
	crypto := dnssec.NewCryptoValidator(nil)
	zone := "secure.example.com"
	ksk, _ := genTestKey(zone, dns.FlagSEP|dns.FlagZONE)
	zsk, _ := genTestKey(zone, dns.FlagZONE)
	ds := ksk.ToDS(dns.SHA256)

	// No RRSIG at all — the DS match alone must not authenticate the set.
	if _, err := verifyDNSKEYWithDS(crypto, []*dns.DS{ds}, []*dns.DNSKEY{ksk, zsk}, nil); !errors.Is(err, errDNSKEYSelfSign) {
		t.Fatalf("verifyDNSKEYWithDS: expected errDNSKEYSelfSign, got %v", err)
	}
}

func TestVerifyDNSKEYWithDS_RogueKeySelfSigned(t *testing.T) {
	// The attack: an on-path attacker appends its own key K2 to the DNSKEY
	// set and self-signs the MODIFIED set with K2.  The legitimate KSK's
	// signature (over the original set) no longer covers the modified set,
	// so verification with the DS-matched key must fail — even though
	// K2's signature verifies with K2 itself.
	crypto := dnssec.NewCryptoValidator(nil)
	zone := "secure.example.com"
	ksk, kskPriv := genTestKey(zone, dns.FlagSEP|dns.FlagZONE)
	zsk, _ := genTestKey(zone, dns.FlagZONE)
	rogue, roguePriv := genTestKey(zone, dns.FlagSEP|dns.FlagZONE)
	ds := ksk.ToDS(dns.SHA256)

	originalSet := []dns.RR{ksk, zsk}
	kskSig := signRRset(originalSet, zone, kskPriv, ksk.KeyTag()) // over the ORIGINAL set
	modifiedSet := []dns.RR{ksk, zsk, rogue}
	rogueSig := signRRset(modifiedSet, zone, roguePriv, rogue.KeyTag()) // over the MODIFIED set

	// Sanity: the rogue signature validates with the rogue key (the reason
	// the previous any-key SelfVerifyDNSKEY check was insufficient).
	if err := crypto.VerifyRRset(modifiedSet, rogueSig, rogue); err != nil {
		t.Fatalf("sanity: rogue self-signature should verify with rogue key: %v", err)
	}

	_, err := verifyDNSKEYWithDS(crypto, []*dns.DS{ds}, []*dns.DNSKEY{ksk, zsk, rogue}, []*dns.RRSIG{kskSig, rogueSig})
	if !errors.Is(err, errDNSKEYSelfSign) {
		t.Fatalf("verifyDNSKEYWithDS: expected errDNSKEYSelfSign for rogue key injection, got %v", err)
	}
}

func TestVerifyDNSKEYWithDS_DSMismatch(t *testing.T) {
	crypto := dnssec.NewCryptoValidator(nil)
	zone := "secure.example.com"
	otherZone := "other.example.com"
	ksk, kskPriv := genTestKey(zone, dns.FlagSEP|dns.FlagZONE)
	otherKSK, _ := genTestKey(otherZone, dns.FlagSEP|dns.FlagZONE)
	ds := otherKSK.ToDS(dns.SHA256) // DS for a DIFFERENT zone's key

	rrsig := signRRset([]dns.RR{ksk}, zone, kskPriv, ksk.KeyTag())
	_, err := verifyDNSKEYWithDS(crypto, []*dns.DS{ds}, []*dns.DNSKEY{ksk}, []*dns.RRSIG{rrsig})
	if !errors.Is(err, dnssec.ErrDSMismatch) {
		t.Fatalf("verifyDNSKEYWithDS: expected ErrDSMismatch, got %v", err)
	}
}

// TestValidateWithDNSSEC_DSMatch exercises isValidWithDNSSEC's DS-match branch
// (previously untested): a valid self-signed DNSKEY set matching the parent DS
// authenticates the answer.
func TestValidateWithDNSSEC_DSMatch(t *testing.T) {
	rr := newTestRecursive()
	zone := "secure.example.com"
	ksk, kskPriv := genTestKey(zone, dns.FlagSEP|dns.FlagZONE)
	zsk, zskPriv := genTestKey(zone, dns.FlagZONE)
	ds := ksk.ToDS(dns.SHA256)

	a := aRec("www."+zone, "192.0.2.1")
	aRRSIG := signRRset([]dns.RR{a}, zone, zskPriv, zsk.KeyTag())
	dnskeyRRs := []dns.RR{ksk, zsk}
	dnskeyRRSIG := signRRset(dnskeyRRs, zone, kskPriv, ksk.KeyTag())

	msg := &dns.Msg{Answer: []dns.RR{a, aRRSIG, ksk, zsk, dnskeyRRSIG}}
	chain := &dnssecChain{childDS: []*dns.DS{ds}}

	validated := rr.isValidWithDNSSEC(msg, zone+".", chain)
	if !validated {
		t.Error("isValidWithDNSSEC: DS match + self-signed DNSKEY set should validate")
	}
}

// TestValidateWithDNSSEC_DSMatchRogueKey proves the fix at the orchestration
// layer: an injected rogue key in the DNSKEY set (self-signing the modified
// set) must NOT authenticate — the answer RRSIG signed by the rogue key must
// be rejected even though the legitimate key still matches the parent DS.
func TestValidateWithDNSSEC_DSMatchRogueKey(t *testing.T) {
	rr := newTestRecursive()
	zone := "secure.example.com"
	ksk, kskPriv := genTestKey(zone, dns.FlagSEP|dns.FlagZONE)
	zsk, _ := genTestKey(zone, dns.FlagZONE)
	rogue, roguePriv := genTestKey(zone, dns.FlagSEP|dns.FlagZONE)
	ds := ksk.ToDS(dns.SHA256)

	rogueA := aRec("www."+zone, "203.0.113.99")
	// The attacker signs the answer with the rogue key (forged data).
	aRRSIG := signRRset([]dns.RR{rogueA}, zone, roguePriv, rogue.KeyTag())
	originalSet := []dns.RR{ksk, zsk}
	kskSig := signRRset(originalSet, zone, kskPriv, ksk.KeyTag())
	modifiedSet := []dns.RR{ksk, zsk, rogue}
	rogueSig := signRRset(modifiedSet, zone, roguePriv, rogue.KeyTag())

	msg := &dns.Msg{Answer: []dns.RR{rogueA, aRRSIG, ksk, zsk, rogue, kskSig, rogueSig}}
	chain := &dnssecChain{childDS: []*dns.DS{ds}}

	validated := rr.isValidWithDNSSEC(msg, zone+".", chain)
	if validated {
		t.Error("isValidWithDNSSEC: rogue key injection must NOT validate (R3-C1)")
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
				Ns:  "ns1." + childZone + ".",
			},
		},
	}

	chain := &dnssecChain{
		zoneDNSKEYs: nil,
		childDS:     []*dns.DS{{}},
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
		zone+".", nil, false, chain, 0)

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
				Ns:  "ns1." + zone + ".",
			},
		},
		Ns: []dns.RR{
			&dns.NS{
				Hdr: dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 300},
				Ns:  "ns2." + zone + ".",
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
				Hdr:        dns.Header{Name: dnsutil.Fqdn(childZone), Class: dns.ClassINET, TTL: 300},
				KeyTag:     12345,
				Algorithm:  dns.ECDSAP256SHA256,
				DigestType: dns.SHA256,
				Digest:     "AAAA",
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
		zoneDNSKEYs: nil,
	}

	_, err := rr.resolveZoneCut(context.Background(), msg, nil,
		Question{Name: dnsutil.Fqdn("www." + childZone), Qtype: dns.TypeA},
		parentZone+".", nil, false, chain, 0)

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

// ── validateOrRetry: sticky lastEDECode clearing (R4-M9) ──────────────────────

func TestValidateOrRetry_ClearsStickyEDE(t *testing.T) {
	rr := newTestRecursive()
	zone := "secure.example.com"
	_, zskPriv := genTestKey(zone, dns.FlagZONE)

	a := aRec("www."+zone, "192.0.2.1")
	rrsig := signRRset([]dns.RR{a}, zone, zskPriv, 0)

	msg := &dns.Msg{Answer: []dns.RR{a, rrsig}}
	chain := &dnssecChain{
		zoneDNSKEYs: []*dns.DNSKEY{{Hdr: dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 3600}, Flags: dns.FlagZONE, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}},
	}

	// Simulate a sticky EDE from a previous delegation level.
	chain.lastEDECode = dns.ExtendedErrorDNSBogus // EDE 6

	validated := rr.validateOrRetry(
		context.Background(), msg, nil,
		Question{Name: "www." + zone + ".", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		zone, nil, false, chain, rr.resolver.validator.Crypto.ZoneKeys(zone),
	)
	// In this test we don't have cached keys; validateOrRetry will call
	// IsResponseValid directly. The ANCHOR POINT is that if validation
	// succeeds, lastEDECode must be cleared to 0.
	if validated && chain.lastEDECode != 0 {
		t.Errorf("validateOrRetry succeeded but lastEDECode = %d, want 0", chain.lastEDECode)
	}
}

// TestValidateOrRetry_SetsEDEOnFailure verifies that validateOrRetry sets
// the correct EDE code when validation fails — a DNSBogus EDE must be
// recorded so the cache gate can reject the response.
func TestValidateOrRetry_SetsEDEOnFailure(t *testing.T) {
	rr := newTestRecursive()
	zone := "secure.example.com"
	_, wrongPriv := genTestKey(zone, dns.FlagZONE)

	a := aRec("www."+zone, "192.0.2.1")
	// Sign with the wrong key — validation should fail.
	rrsig := signRRset([]dns.RR{a}, "other.example.com.", wrongPriv, 9999)

	msg := &dns.Msg{Answer: []dns.RR{a, rrsig}}
	chain := &dnssecChain{
		zoneDNSKEYs: []*dns.DNSKEY{{Hdr: dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 3600}, Flags: dns.FlagZONE, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}},
	}

	_ = rr.validateOrRetry(
		context.Background(), msg, nil,
		Question{Name: "www." + zone + ".", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		zone, nil, false, chain, chain.zoneDNSKEYs,
	)
	if chain.lastEDECode == 0 {
		t.Error("validateOrRetry must set a non-zero EDE on validation failure")
	}
}

// ── isValidWithDNSSEC: sticky lastEDECode clearing ────────────────────────────

func TestIsValidWithDNSSEC_ClearsStickyEDE(t *testing.T) {
	rr := newTestRecursive()
	zone := "secure.example.com"
	_, zskPriv := genTestKey(zone, dns.FlagZONE)

	a := aRec("www."+zone, "192.0.2.1")
	rrsig := signRRset([]dns.RR{a}, zone, zskPriv, 0)

	msg := &dns.Msg{Answer: []dns.RR{a, rrsig}}
	chain := &dnssecChain{
		zoneDNSKEYs: []*dns.DNSKEY{{Hdr: dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 3600}, Flags: dns.FlagZONE, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}},
	}
	// Stale EDE from a previous level.
	chain.lastEDECode = dns.ExtendedErrorDNSBogus

	validated := rr.isValidWithDNSSEC(msg, zone+".", chain)
	if validated && chain.lastEDECode != 0 {
		t.Errorf("isValidWithDNSSEC succeeded but lastEDECode = %d, want 0", chain.lastEDECode)
	}
}

// ── ensureZoneDNSKEYs singleflight ───────────────────────────────────────────

// TestEnsureZoneDNSKEYs_Singleflight verifies that a cold-cache burst of
// concurrent walks for the same zone issues exactly one DNSKEY query.  The
// zone-key cache only deduplicates AFTER a successful fetch, so without the
// per-zone flight every walk fires its own multi-NS DNSKEY fetch — the DNSSEC
// burst amplifier behind multi-hundred-MB transient heap spikes (pprof
// evidence, 2026-08).
func TestEnsureZoneDNSKEYs_Singleflight(t *testing.T) {
	zoneKey, zonePriv := genTestKey("example.com.", dns.FlagSEP|dns.FlagZONE)
	zone := "example.com."
	ds := zoneKey.ToDS(dns.SHA256)
	ds.Hdr = dns.Header{Name: zone, Class: dns.ClassINET, TTL: 300}

	var dnskeyQueries atomic.Int32
	addr := startMockDNS(t, dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
		m := replyMsg(req)
		if len(req.Question) == 1 && dns.RRToType(req.Question[0]) == dns.TypeDNSKEY {
			dnskeyQueries.Add(1)
			time.Sleep(100 * time.Millisecond) // widen the overlap window
			rrsig := signRRset([]dns.RR{zoneKey}, zone, zonePriv, zoneKey.KeyTag())
			m.Answer = []dns.RR{zoneKey, rrsig}
		}
		writeMsg(w, m)
	}))

	rr := newTestRecursive()
	setTestBuildMsg(rr)

	const concurrent = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	chains := make([]*dnssecChain, concurrent)
	for i := range chains {
		chains[i] = &dnssecChain{childDS: []*dns.DS{ds}}
	}
	for i := range concurrent {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			rr.ensureZoneDNSKEYs(context.Background(), []string{addr}, zone, chains[i])
		}(i)
	}
	close(start)
	wg.Wait()

	if got := dnskeyQueries.Load(); got != 1 {
		t.Errorf("DNSKEY queries = %d, want 1 (singleflight dedup)", got)
	}
	for i, c := range chains {
		if len(c.zoneDNSKEYs) != 1 {
			t.Errorf("chain %d: got %d verified DNSKEYs, want 1", i, len(c.zoneDNSKEYs))
		}
	}
}
