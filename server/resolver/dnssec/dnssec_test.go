package dnssec

import (
	"crypto/ecdsa"
	"net/netip"
	"testing"
	"time"
	"zjdns/cache"
	"zjdns/database"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// ── Test helpers ─────────────────────────────────────────────────────────────

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
			Labels:      uint8(dnsutil.Labels(rrset[0].Header().Name)), //nolint:gosec // G115: DNS label count — protocol-bounded byte
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

// aRec is a helper to create an A record with an IP address.
func aRec(name, ip string) *dns.A {
	return &dns.A{
		Hdr: dns.Header{Name: dnsutil.Fqdn(name), Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr(ip)},
	}
}

// ── VerifyRRset ──────────────────────────────────────────────────────────────

func TestVerifyRRset_ValidSignature(t *testing.T) {
	cv := NewCryptoValidator(nil)
	zone := "test.example.com"
	ksk, priv := genTestKey(zone, dns.FlagSEP|dns.FlagZONE)

	rrset := []dns.RR{aRec(zone, "192.0.2.1")}
	rrsig := signRRset(rrset, zone, priv, ksk.KeyTag())

	if err := cv.VerifyRRset(rrset, rrsig, ksk); err != nil {
		t.Errorf("valid signature should pass: %v", err)
	}
}

func TestVerifyRRset_WrongKey(t *testing.T) {
	cv := NewCryptoValidator(nil)
	zone := "test.example.com"
	ksk, priv := genTestKey(zone, dns.FlagSEP|dns.FlagZONE)
	wrongKey, _ := genTestKey(zone, dns.FlagSEP|dns.FlagZONE)

	rrset := []dns.RR{aRec(zone, "192.0.2.1")}
	rrsig := signRRset(rrset, zone, priv, ksk.KeyTag())

	if err := cv.VerifyRRset(rrset, rrsig, wrongKey); err == nil {
		t.Error("signature with wrong key should fail")
	}
}

func TestVerifyRRset_ExpiredSignature(t *testing.T) {
	cv := NewCryptoValidator(nil)
	zone := "test.example.com"
	ksk, priv := genTestKey(zone, dns.FlagSEP|dns.FlagZONE)

	rrset := []dns.RR{aRec(zone, "192.0.2.1")}
	rrsig := &dns.RRSIG{
		Hdr: dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 300},
		RRSIG: rdata.RRSIG{
			TypeCovered: dns.TypeA,
			Algorithm:   dns.ECDSAP256SHA256,
			Labels:      3,
			OrigTTL:     300,
			Expiration:  uint32(time.Now().Add(-48 * time.Hour).Unix()), //nolint:gosec // G115: DNSSEC timestamp — protocol-bounded uint32
			Inception:   uint32(time.Now().Add(-72 * time.Hour).Unix()), //nolint:gosec // G115: DNSSEC timestamp — protocol-bounded uint32
			KeyTag:      ksk.KeyTag(),
			SignerName:  dnsutil.Fqdn(zone),
		},
	}
	_ = rrsig.Sign(priv, rrset, &dns.SignOption{})

	if err := cv.VerifyRRset(rrset, rrsig, ksk); err == nil {
		t.Error("expired signature should fail")
	}
}

// ── VerifyDelegationDS ───────────────────────────────────────────────────────

func TestVerifyDelegationDS_Matching(t *testing.T) {
	cv := NewCryptoValidator(nil)
	childZone := "child.example.com"
	ksk, _ := genTestKey(childZone, dns.FlagSEP|dns.FlagZONE)

	ds := ksk.ToDS(dns.SHA256)
	if ds == nil {
		t.Fatal("ToDS returned nil")
	}

	matchedKey, err := cv.VerifyDelegationDS([]*dns.DS{ds}, []*dns.DNSKEY{ksk})
	if err != nil {
		t.Errorf("matching DS should pass: %v", err)
	}
	if matchedKey.KeyTag() != ksk.KeyTag() {
		t.Errorf("matched key tag %d != expected %d", matchedKey.KeyTag(), ksk.KeyTag())
	}
}

func TestVerifyDelegationDS_Mismatch(t *testing.T) {
	cv := NewCryptoValidator(nil)
	childZone := "child.example.com"
	ksk, _ := genTestKey(childZone, dns.FlagSEP|dns.FlagZONE)
	otherKey, _ := genTestKey("other.example.com", dns.FlagSEP|dns.FlagZONE)

	ds := ksk.ToDS(dns.SHA256)

	_, err := cv.VerifyDelegationDS([]*dns.DS{ds}, []*dns.DNSKEY{otherKey})
	if err == nil {
		t.Error("mismatched DS should fail")
	}
}

func TestVerifyDelegationDS_SkipsNonSEP(t *testing.T) {
	cv := NewCryptoValidator(nil)
	childZone := "child.example.com"
	zsk, _ := genTestKey(childZone, dns.FlagZONE)
	ksk, _ := genTestKey(childZone, dns.FlagSEP|dns.FlagZONE)

	ds := ksk.ToDS(dns.SHA256)

	matchedKey, err := cv.VerifyDelegationDS([]*dns.DS{ds}, []*dns.DNSKEY{zsk, ksk})
	if err != nil {
		t.Errorf("DS should match KSK even when ZSK present: %v", err)
	}
	if matchedKey.Flags&dns.FlagSEP == 0 {
		t.Error("matched key should have SEP flag set")
	}
}

// ── SelfVerifyDNSKEY ─────────────────────────────────────────────────────────

func TestSelfVerifyDNSKEY_Valid(t *testing.T) {
	cv := NewCryptoValidator(nil)
	zone := "example.net"
	ksk, kskPriv := genTestKey(zone, dns.FlagSEP|dns.FlagZONE)
	zsk, _ := genTestKey(zone, dns.FlagZONE)

	dnskeys := []*dns.DNSKEY{ksk, zsk}
	rrset := make([]dns.RR, len(dnskeys))
	for i, k := range dnskeys {
		rrset[i] = k
	}
	rrsig := signRRset(rrset, zone, kskPriv, ksk.KeyTag())

	if err := cv.SelfVerifyDNSKEY(dnskeys, []*dns.RRSIG{rrsig}); err != nil {
		t.Errorf("self-verify should pass for valid self-signed DNSKEY: %v", err)
	}
}

func TestSelfVerifyDNSKEY_ForeignSignature(t *testing.T) {
	cv := NewCryptoValidator(nil)
	zone := "example.net"
	ksk, _ := genTestKey(zone, dns.FlagSEP|dns.FlagZONE)
	zsk, _ := genTestKey(zone, dns.FlagZONE)
	wrongKey, wrongPriv := genTestKey("attacker.com", dns.FlagSEP|dns.FlagZONE)

	dnskeys := []*dns.DNSKEY{ksk, zsk}
	rrset := make([]dns.RR, len(dnskeys))
	for i, k := range dnskeys {
		rrset[i] = k
	}
	rrsig := signRRset(rrset, zone, wrongPriv, wrongKey.KeyTag())

	if err := cv.SelfVerifyDNSKEY(dnskeys, []*dns.RRSIG{rrsig}); err == nil {
		t.Error("self-verify should fail when signed by foreign key")
	}
}

func TestSelfVerifyDNSKEY_NoSEPKey(t *testing.T) {
	cv := NewCryptoValidator(nil)
	zone := "example.net"
	zsk, zskPriv := genTestKey(zone, dns.FlagZONE)

	dnskeys := []*dns.DNSKEY{zsk}
	rrset := make([]dns.RR, len(dnskeys))
	for i, k := range dnskeys {
		rrset[i] = k
	}
	rrsig := signRRset(rrset, zone, zskPriv, zsk.KeyTag())

	if err := cv.SelfVerifyDNSKEY(dnskeys, []*dns.RRSIG{rrsig}); err == nil {
		t.Error("self-verify should fail when no KSK (SEP) is present")
	}
}

// ── IsResponseValid (end-to-end answer validation) ──────────────────────────

func TestIsResponseValid_SignedAnswer(t *testing.T) {
	cv := NewCryptoValidator(nil)
	zone := "signed.example.com"
	ksk, _ := genTestKey(zone, dns.FlagSEP|dns.FlagZONE)
	zsk, zskPriv := genTestKey(zone, dns.FlagZONE)

	aRec := &dns.A{
		Hdr: dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("203.0.113.1")},
	}
	rrsig := signRRset([]dns.RR{aRec}, zone, zskPriv, zsk.KeyTag())

	response := &dns.Msg{
		MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess},
		Answer:    []dns.RR{aRec, rrsig},
	}
	verified, err := cv.IsResponseValid(response, zone, []*dns.DNSKEY{zsk, ksk})
	if err != nil {
		t.Errorf("IsResponseValid should pass: %v", err)
	}
	if !verified {
		t.Error("signed answer should be verified")
	}
}

func TestIsResponseValid_UnsignedAnswer(t *testing.T) {
	cv := NewCryptoValidator(nil)
	zone := "unsigned.example.com"
	_, _ = genTestKey(zone, dns.FlagSEP|dns.FlagZONE)
	zsk, _ := genTestKey(zone, dns.FlagZONE)

	aRec := &dns.A{
		Hdr: dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("203.0.113.1")},
	}
	response := &dns.Msg{
		MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess},
		Answer:    []dns.RR{aRec},
	}
	verified, _ := cv.IsResponseValid(response, zone, []*dns.DNSKEY{zsk})
	if verified {
		t.Error("unsigned answer should not be verified")
	}
}

func TestIsResponseValid_NoDNSKEYs(t *testing.T) {
	cv := NewCryptoValidator(nil)
	response := &dns.Msg{
		MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess},
		Answer:    []dns.RR{aRec("test.example.com", "192.0.2.1")},
	}
	verified, _ := cv.IsResponseValid(response, "test.example.com", nil)
	if verified {
		t.Error("should return false with no DNSKEYs")
	}
}

// ── NSEC / NSEC3 ─────────────────────────────────────────────────────────────

func TestFindNSEC(t *testing.T) {
	nsec := &dns.NSEC{Hdr: dns.Header{Name: "a.com.", Class: dns.ClassINET}}
	rrs := []dns.RR{nsec, &dns.A{Hdr: dns.Header{Name: "a.com.", Class: dns.ClassINET}}}
	if len(findNSEC(rrs)) != 1 {
		t.Error("should find NSEC record")
	}
}

func TestFindNSEC3(t *testing.T) {
	nsec3 := &dns.NSEC3{Hdr: dns.Header{Name: "abc.a.com.", Class: dns.ClassINET}}
	rrs := []dns.RR{nsec3}
	if len(findNSEC3(rrs)) != 1 {
		t.Error("should find NSEC3 record")
	}
}

func TestIsResponseValid_NXDOMAIN(t *testing.T) {
	cv := NewCryptoValidator(nil)
	zone := "signed.example.com"
	_, _ = genTestKey(zone, dns.FlagSEP|dns.FlagZONE)
	zsk, zskPriv := genTestKey(zone, dns.FlagZONE)

	// Query for a name that doesn't exist. The NSEC range
	// [aaaa.signed.example.com., zzzz.signed.example.com.) covers
	// nonexistent.signed.example.com. in canonical ordering (aaaa < nonexistent < zzzz).
	qname := "nonexistent.signed.example.com."
	qtype := dns.TypeA

	nsec := &dns.NSEC{
		Hdr:  dns.Header{Name: "aaaa.signed.example.com.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "zzzz.signed.example.com.", TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC}},
	}
	rrsig := signRRset([]dns.RR{nsec}, zone, zskPriv, zsk.KeyTag())

	response := &dns.Msg{
		MsgHeader: dns.MsgHeader{Rcode: dns.RcodeNameError},
		Ns:        []dns.RR{nsec, rrsig},
	}
	dnsutil.SetQuestion(response, dnsutil.Fqdn(qname), qtype)
	verified, err := cv.IsResponseValid(response, zone, []*dns.DNSKEY{zsk})
	if err != nil {
		t.Errorf("NXDOMAIN with signed NSEC should pass: %v", err)
	}
	if !verified {
		t.Error("signed NSEC for NXDOMAIN should be verified")
	}
}

// ── Full chain: DS → DNSKEY → answer ────────────────────────────────────────

func testCache() cache.Store {
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		panic(err)
	}
	return cache.New(db, 0, 0)
}

func TestFullDNSSECChain(t *testing.T) {
	store := testCache()
	t.Cleanup(func() { _ = store.Close() })
	cv := NewCryptoValidator(store)
	childZone := "child.example.net"

	childKSK, _ := genTestKey(childZone, dns.FlagSEP|dns.FlagZONE)
	childZSK, childZSKPriv := genTestKey(childZone, dns.FlagZONE)
	ds := childKSK.ToDS(dns.SHA256)

	// Step 1: verify child DNSKEY against parent DS
	matchedKey, err := cv.VerifyDelegationDS([]*dns.DS{ds}, []*dns.DNSKEY{childKSK, childZSK})
	if err != nil {
		t.Fatalf("DS→DNSKEY should match: %v", err)
	}
	if matchedKey.KeyTag() != childKSK.KeyTag() {
		t.Fatalf("matched wrong key: tag %d != %d", matchedKey.KeyTag(), childKSK.KeyTag())
	}
	cv.CacheZoneKeys(childZone, []*dns.DNSKEY{childKSK, childZSK})

	// Step 2: verify a signed A record against child's verified DNSKEYs
	aRec := &dns.A{
		Hdr: dns.Header{Name: dnsutil.Fqdn(childZone), Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("198.51.100.1")},
	}
	rrsig := signRRset([]dns.RR{aRec}, childZone, childZSKPriv, childZSK.KeyTag())
	response := &dns.Msg{
		MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess},
		Answer:    []dns.RR{aRec, rrsig},
	}

	verifiedKeys := cv.ZoneKeys(childZone)
	if len(verifiedKeys) == 0 {
		t.Fatal("zone keys not cached")
	}
	validated, err := cv.IsResponseValid(response, childZone, verifiedKeys)
	if err != nil {
		t.Errorf("full chain validation should pass: %v", err)
	}
	if !validated {
		t.Error("full chain should produce validated=true")
	}
}

// ── Edge cases ───────────────────────────────────────────────────────────────

func TestDNSSEC_BogusDelegation(t *testing.T) {
	cv := NewCryptoValidator(nil)
	childZone := "bogus.example.com"

	realKSK, _ := genTestKey(childZone, dns.FlagSEP|dns.FlagZONE)
	ds := realKSK.ToDS(dns.SHA256)

	// Child presents a DIFFERENT KSK (not matching the DS)
	fakeKSK, _ := genTestKey(childZone, dns.FlagSEP|dns.FlagZONE)

	_, err := cv.VerifyDelegationDS([]*dns.DS{ds}, []*dns.DNSKEY{fakeKSK})
	if err == nil {
		t.Error("bogus delegation: DS from parent must not match a different child KSK")
	}
}

// TestIsResponseValid_MixedRRsetWithForeignRRSIG verifies that when a response
// contains multiple RRsets and one has RRSIGs from a foreign zone's keys (zone cut),
// validateAnswerSection returns an error rather than silently skipping the
// unverifiable RRset. This prevents a valid parent-zone RRSIG from masking a broken
// or foreign child-zone RRSIG.
func TestIsResponseValid_MixedRRsetWithForeignRRSIG(t *testing.T) {
	cv := NewCryptoValidator(nil)
	parentZone := "parent.example.com"
	childZone := "child.parent.example.com"

	parentZSK, parentZSKPriv := genTestKey(parentZone, dns.FlagZONE)
	childZSK, childZSKPriv := genTestKey(childZone, dns.FlagZONE)

	// Build a response that mimics a typical zone-cut scenario:
	// CNAME record signed by parent zone (valid) +
	// A record signed by child zone (parent can't verify this RRSIG)
	cnameRec := &dns.CNAME{
		Hdr:   dns.Header{Name: dnsutil.Fqdn("query.parent.example.com"), Class: dns.ClassINET, TTL: 300},
		CNAME: rdata.CNAME{Target: dnsutil.Fqdn("target.child.parent.example.com")},
	}
	cnameRRSIG := signRRset([]dns.RR{cnameRec}, parentZone, parentZSKPriv, parentZSK.KeyTag())

	aRec := &dns.A{
		Hdr: dns.Header{Name: dnsutil.Fqdn("target.child.parent.example.com"), Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	}
	aRRSIG := signRRset([]dns.RR{aRec}, childZone, childZSKPriv, childZSK.KeyTag())

	response := &dns.Msg{
		MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess},
		Answer:    []dns.RR{cnameRec, cnameRRSIG, aRec, aRRSIG},
	}

	// Validate with ONLY parent zone keys.
	// The CNAME RRSIG should validate, but the A RRSIG comes from child zone
	// whose key is NOT in the verified set.
	verified, err := cv.IsResponseValid(response, parentZone, []*dns.DNSKEY{parentZSK})
	if err == nil {
		t.Error("IsResponseValid should return error when an RRset has RRSIGs that don't match any verified DNSKEY")
	}
	if verified {
		t.Error("should not claim validated when one RRset's RRSIG can't be verified")
	}
}
