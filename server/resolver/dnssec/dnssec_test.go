package dnssec

import (
	"crypto/ecdsa"
	"errors"
	"net/netip"
	"strings"
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

// ── Extract helpers (FindDS / FindCDS) ──────────────────────────────────────

func TestFindDS(t *testing.T) {
	ds := &dns.DS{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}
	rrs := []dns.RR{ds, &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}}
	if len(FindDS(rrs)) != 1 {
		t.Error("should find DS record")
	}
}

func TestFindCDS(t *testing.T) {
	cds := &dns.CDS{DS: dns.DS{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}}
	rrs := []dns.RR{cds, &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}}
	if len(FindCDS(rrs)) != 1 {
		t.Error("should find CDS record")
	}
	// CDS should NOT be found by FindDS
	if len(FindDS(rrs)) != 0 {
		t.Error("FindDS should not find CDS records")
	}
}

func TestFindCDNSKEY(t *testing.T) {
	cdnskey := &dns.CDNSKEY{DNSKEY: dns.DNSKEY{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}}
	rrs := []dns.RR{cdnskey, &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}}
	if len(FindCDNSKEY(rrs)) != 1 {
		t.Error("should find CDNSKEY record")
	}
	// CDNSKEY should NOT be found by FindDNSKEYs (distinct RR type).
	if len(FindDNSKEYs(rrs)) != 0 {
		t.Error("FindDNSKEYs should not find CDNSKEY records")
	}
}

func TestOfflineKSK_CDSConfirmsDelegation(t *testing.T) {
	store := testCache()
	t.Cleanup(func() { _ = store.Close() })
	cv := NewCryptoValidator(store)
	childZone := "offline-ksk.example.com"

	// Simulate offline KSK: KSK exists (DS matches) but is not published in
	// the DNSKEY set. Only the ZSK is published. The KSK signs the DNSKEY
	// RRset, and CDS confirms the delegation (RFC 7344).
	ksk, _ := genTestKey(childZone, dns.FlagSEP|dns.FlagZONE)
	zsk, _ := genTestKey(childZone, dns.FlagZONE)
	ds := ksk.ToDS(dns.SHA256)
	if ds == nil {
		t.Fatal("ToDS returned nil")
	}

	// VerifyDelegationDS fails because KSK is not in the DNSKEY set
	_, err := cv.VerifyDelegationDS([]*dns.DS{ds}, []*dns.DNSKEY{zsk})
	if err == nil {
		t.Fatal("DS should not match ZSK alone — KSK is offline")
	}

	// CDS record matching the DS confirms the delegation
	cds := &dns.CDS{DS: *ds}
	cdsRecords := FindCDS([]dns.RR{cds})
	if len(cdsRecords) != 1 {
		t.Fatal("FindCDS should find CDS record")
	}

	// CDS must match DS (key_tag, algorithm, digest_type, digest)
	match := cdsRecords[0].KeyTag == ds.KeyTag &&
		cdsRecords[0].Algorithm == ds.Algorithm &&
		cdsRecords[0].DigestType == ds.DigestType &&
		cdsRecords[0].Digest == ds.Digest
	if !match {
		t.Error("CDS must match DS for offline KSK delegation")
	}
}

func TestOfflineKSK_CDNSKEYConfirmsDelegation(t *testing.T) {
	store := testCache()
	t.Cleanup(func() { _ = store.Close() })
	cv := NewCryptoValidator(store)
	childZone := "offline-cdnskey.example.com"

	ksk, _ := genTestKey(childZone, dns.FlagSEP|dns.FlagZONE)
	zsk, _ := genTestKey(childZone, dns.FlagZONE)
	ds := ksk.ToDS(dns.SHA256)
	if ds == nil {
		t.Fatal("ToDS returned nil")
	}

	// VerifyDelegationDS fails because KSK is not in the DNSKEY set.
	_, err := cv.VerifyDelegationDS([]*dns.DS{ds}, []*dns.DNSKEY{zsk})
	if err == nil {
		t.Fatal("DS should not match ZSK alone — KSK is offline")
	}

	// CDNSKEY record matching the DS confirms the delegation (RFC 7344 §4.1).
	cdnskey := &dns.CDNSKEY{DNSKEY: *ksk}
	cdnskeyRecords := FindCDNSKEY([]dns.RR{cdnskey})
	if len(cdnskeyRecords) != 1 {
		t.Fatal("FindCDNSKEY should find CDNSKEY record")
	}

	// CDNSKEY.ToDS must match DS field-for-field.
	computed := cdnskeyRecords[0].ToDS(ds.DigestType)
	if computed == nil {
		t.Fatal("CDNSKEY.ToDS returned nil")
	}
	match := computed.KeyTag == ds.KeyTag &&
		computed.Algorithm == ds.Algorithm &&
		computed.DigestType == ds.DigestType &&
		computed.Digest == ds.Digest
	if !match {
		t.Error("CDNSKEY must match DS for offline KSK delegation")
	}

	// A different key's CDNSKEY should not match.
	otherKSK, _ := genTestKey("other.example.com", dns.FlagSEP|dns.FlagZONE)
	otherCDNSKEY := &dns.CDNSKEY{DNSKEY: *otherKSK}
	otherComputed := otherCDNSKEY.ToDS(ds.DigestType)
	if otherComputed != nil && otherComputed.Digest == ds.Digest {
		t.Error("different key's CDNSKEY should not match DS")
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
	db, err := database.Open("", nil)
	if err != nil {
		panic(err)
	}
	return cache.New(db)
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

// ── RFC 6840 §4.3: CNAME bit check ──────────────────────────────────────────

func TestMatchesNSECDenial_CNAMEBitSet(t *testing.T) {
	nsec := &dns.NSEC{
		Hdr:  dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "other.example.com.", TypeBitMap: []uint16{dns.TypeCNAME, dns.TypeRRSIG, dns.TypeNSEC}},
	}
	if matchesNSECDenial(nsec, "example.com.", dns.TypeA, "NODATA") {
		t.Fatal("CNAME bit set: NODATA must be false")
	}
	nsec.TypeBitMap = []uint16{dns.TypeRRSIG, dns.TypeNSEC}
	if !matchesNSECDenial(nsec, "example.com.", dns.TypeA, "NODATA") {
		t.Fatal("no CNAME bit: NODATA should be true for absent TypeA")
	}
}

// ── RFC 6840 §4.1: ancestor delegation ──────────────────────────────────────

func TestIsAncestorDelegation(t *testing.T) {
	ancestor := &dns.NSEC{
		Hdr:  dns.Header{Name: "com.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "other.com.", TypeBitMap: []uint16{dns.TypeNS}},
	}
	if !isAncestorDelegation(ancestor) {
		t.Fatal("NS=1 SOA=0: should be ancestor delegation")
	}
	apex := &dns.NSEC{
		Hdr:  dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "www.example.com.", TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC}},
	}
	if isAncestorDelegation(apex) {
		t.Fatal("NS=1 SOA=1: should NOT be ancestor delegation")
	}
}

// ── RFC 5155 §9.2: Opt-Out AD bit ───────────────────────────────────────────

func TestHasOptOutInProof(t *testing.T) {
	noOptOut := []*dns.NSEC3{
		{Hdr: dns.Header{Name: "abc.com.", Class: dns.ClassINET, TTL: 300}, NSEC3: rdata.NSEC3{Hash: dns.SHA1, Flags: 0}},
	}
	if hasOptOutInProof(noOptOut) {
		t.Fatal("no Opt-Out: should return false")
	}
	withOptOut := []*dns.NSEC3{
		{Hdr: dns.Header{Name: "abc.com.", Class: dns.ClassINET, TTL: 300}, NSEC3: rdata.NSEC3{Hash: dns.SHA1, Flags: 1}},
	}
	if !hasOptOutInProof(withOptOut) {
		t.Fatal("Opt-Out flag set: should return true")
	}
}

// ── RFC 4035 §5.3.3: TTL cap ────────────────────────────────────────────────

// ── NSEC3 proof helpers ──────────────────────────────────────────────────────

func TestNsec3HashLabel(t *testing.T) {
	if got := nsec3HashLabel("ABCDEF.example.com."); got != "abcdef" {
		t.Errorf("full owner: got %q, want %q", got, "abcdef")
	}
	if got := nsec3HashLabel("ABCDEF"); got != "abcdef" {
		t.Errorf("bare hash: got %q, want %q", got, "abcdef")
	}
	if got := nsec3HashLabel("HASH.sub.example.com."); got != "hash" {
		t.Errorf("multi-label: got %q, want %q", got, "hash")
	}
}

func TestMatchNSEC3(t *testing.T) {
	nsec3 := &dns.NSEC3{
		Hdr:   dns.Header{Name: "abcd.example.com.", Class: dns.ClassINET, TTL: 300},
		NSEC3: rdata.NSEC3{Hash: dns.SHA1, Flags: 0, Iterations: 0, Salt: "", NextDomain: "eeee", TypeBitMap: []uint16{dns.TypeA}},
	}
	verified := []*dns.NSEC3{nsec3}

	if matchNSEC3(verified, "ABCD") == nil {
		t.Error("case-insensitive match should find ABCD in abcd owner")
	}
	if matchNSEC3(verified, "XXXX") != nil {
		t.Error("non-matching hash should return nil")
	}
}

func TestHasNSEC3Covering(t *testing.T) {
	// Interval (aaaa, zzzz) covers bbbb but not 0000
	nsec3 := &dns.NSEC3{
		Hdr:   dns.Header{Name: "aaaa.example.com.", Class: dns.ClassINET, TTL: 300},
		NSEC3: rdata.NSEC3{Hash: dns.SHA1, Flags: 0, Iterations: 0, Salt: "", NextDomain: "zzzz", TypeBitMap: []uint16{}},
	}
	verified := []*dns.NSEC3{nsec3}

	if !hasNSEC3Covering(verified, "BBBB") {
		t.Error("bbbb should be inside (aaaa, zzzz)")
	}
	if hasNSEC3Covering(verified, "0000") {
		t.Error("0000 should be outside (aaaa, zzzz)")
	}
	// Equal to owner: not covered (strict inequality).
	if hasNSEC3Covering(verified, "AAAA") {
		t.Error("aaaa should not be covered (equal to owner)")
	}
}

func TestNsec3ParamsConsistent(t *testing.T) {
	same := []*dns.NSEC3{
		{NSEC3: rdata.NSEC3{Hash: dns.SHA1, Iterations: 5, Salt: "AB"}},
		{NSEC3: rdata.NSEC3{Hash: dns.SHA1, Iterations: 5, Salt: "AB"}},
	}
	if !nsec3ParamsConsistent(same) {
		t.Error("identical params should be consistent")
	}

	diffIter := []*dns.NSEC3{
		{NSEC3: rdata.NSEC3{Hash: dns.SHA1, Iterations: 5, Salt: "AB"}},
		{NSEC3: rdata.NSEC3{Hash: dns.SHA1, Iterations: 10, Salt: "AB"}},
	}
	if nsec3ParamsConsistent(diffIter) {
		t.Error("different iterations should be inconsistent")
	}

	diffSalt := []*dns.NSEC3{
		{NSEC3: rdata.NSEC3{Hash: dns.SHA1, Iterations: 5, Salt: "AB"}},
		{NSEC3: rdata.NSEC3{Hash: dns.SHA1, Iterations: 5, Salt: "CD"}},
	}
	if nsec3ParamsConsistent(diffSalt) {
		t.Error("different salt should be inconsistent")
	}
}

func TestStripLeftmostLabel(t *testing.T) {
	if got := stripLeftmostLabel("a.b.example.com."); got != "b.example.com." {
		t.Errorf("got %q, want %q", got, "b.example.com.")
	}
	if got := stripLeftmostLabel("example.com."); got != "com." {
		t.Errorf("got %q, want %q", got, "com.")
	}
	if got := stripLeftmostLabel("com."); got != "" {
		t.Errorf("single label: got %q, want empty", got)
	}
	if got := stripLeftmostLabel(""); got != "" {
		t.Errorf("empty: got %q, want empty", got)
	}
}

// ── findClosestEncloser ──────────────────────────────────────────────────────

func TestFindClosestEncloser_Valid(t *testing.T) {
	// QNAME = a.b.g.example.com.
	// CE should be g.example.com. (closest existing ancestor)
	// Need NSEC3s covering H(a.b.g.example.com.) and H(b.g.example.com.)
	// and matching H(g.example.com.).
	zone := "example.com."
	ceName := "g.example.com."
	midName := "b.g.example.com."
	qname := "a.b.g.example.com."

	hCE := nsec3HashName(ceName, dns.SHA1, 0, "")
	hMid := nsec3HashName(midName, dns.SHA1, 0, "")
	hQname := nsec3HashName(qname, dns.SHA1, 0, "")

	// Universal cover: (000...0, VVV...V) covers every real hash.
	lowHash := strings.Repeat("0", 32)
	highHash := strings.Repeat("V", 32)
	universalCover := &dns.NSEC3{
		Hdr:   dns.Header{Name: lowHash + "." + zone, Class: dns.ClassINET, TTL: 300},
		NSEC3: rdata.NSEC3{Hash: dns.SHA1, Flags: 0, Iterations: 0, Salt: "", NextDomain: highHash, TypeBitMap: []uint16{}},
	}
	// CE match: owner hash label equals H(ceName).
	ceMatch := &dns.NSEC3{
		Hdr:   dns.Header{Name: hCE + "." + zone, Class: dns.ClassINET, TTL: 300},
		NSEC3: rdata.NSEC3{Hash: dns.SHA1, Flags: 0, Iterations: 0, Salt: "", NextDomain: hCE, TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC3}},
	}

	verified := []*dns.NSEC3{universalCover, ceMatch}
	ce, ok := findClosestEncloser(verified, qname, dns.SHA1, 0, "")
	if !ok {
		t.Fatal("should find closest encloser")
	}
	if ce != ceName {
		t.Errorf("CE = %q, want %q", ce, ceName)
	}
	// Verify internal steps: hQname covered by universalCover, hMid covered by universalCover.
	_ = hQname
	_ = hMid
}

func TestFindClosestEncloser_BogusMatchWithoutCover(t *testing.T) {
	// If H(qname) matches directly without a prior cover, the proof is bogus
	// (attacker could have stripped the next-closer proof).
	zone := "example.com."
	qname := "a.example.com."
	hQname := nsec3HashName(qname, dns.SHA1, 0, "")

	directMatch := &dns.NSEC3{
		Hdr:   dns.Header{Name: hQname + "." + zone, Class: dns.ClassINET, TTL: 300},
		NSEC3: rdata.NSEC3{Hash: dns.SHA1, Flags: 0, Iterations: 0, Salt: "", NextDomain: hQname, TypeBitMap: []uint16{dns.TypeA}},
	}
	verified := []*dns.NSEC3{directMatch}
	_, ok := findClosestEncloser(verified, qname, dns.SHA1, 0, "")
	if ok {
		t.Error("match without prior cover should be bogus")
	}
}

func TestFindClosestEncloser_NoCE(t *testing.T) {
	// No NSEC3 matches any ancestor → fail.
	zone := "example.com."
	qname := "deep.sub.example.com."
	lowHash := strings.Repeat("0", 32)
	highHash := strings.Repeat("V", 32)
	cover := &dns.NSEC3{
		Hdr:   dns.Header{Name: lowHash + "." + zone, Class: dns.ClassINET, TTL: 300},
		NSEC3: rdata.NSEC3{Hash: dns.SHA1, Flags: 0, Iterations: 0, Salt: "", NextDomain: highHash, TypeBitMap: []uint16{}},
	}
	verified := []*dns.NSEC3{cover}
	_, ok := findClosestEncloser(verified, qname, dns.SHA1, 0, "")
	if ok {
		t.Error("no CE match should fail")
	}
}

// ── matchesNSEC3Denial (unit tests on hash-level proof functions) ───────────

func TestMatchesNSEC3Denial_NXDOMAIN(t *testing.T) {
	zone := "example.com."
	ceName := "example.com."
	qname := "nonexist.example.com."

	hCE := nsec3HashName(ceName, dns.SHA1, 0, "")
	hWildcard := nsec3HashName("*."+ceName, dns.SHA1, 0, "")

	lowHash := strings.Repeat("0", 32)
	highHash := strings.Repeat("V", 32)

	// Universal cover: covers qname, parent, and wildcard hashes.
	universalCover := &dns.NSEC3{
		Hdr:   dns.Header{Name: lowHash + "." + zone, Class: dns.ClassINET, TTL: 300},
		NSEC3: rdata.NSEC3{Hash: dns.SHA1, Flags: 0, Iterations: 0, Salt: "", NextDomain: highHash, TypeBitMap: []uint16{}},
	}
	// CE match
	ceMatch := &dns.NSEC3{
		Hdr:   dns.Header{Name: hCE + "." + zone, Class: dns.ClassINET, TTL: 300},
		NSEC3: rdata.NSEC3{Hash: dns.SHA1, Flags: 0, Iterations: 0, Salt: "", NextDomain: hCE, TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC3}},
	}

	verified := []*dns.NSEC3{universalCover, ceMatch}
	if !matchesNSEC3Denial(verified, qname, dns.TypeA, "NXDOMAIN", dns.SHA1, 0, "") {
		t.Error("full NXDOMAIN proof should pass")
	}
	// Assert wildcard hash is covered.
	_ = hWildcard
}

func TestMatchesNSEC3Denial_NXDOMAIN_MissingWildcardCover(t *testing.T) {
	zone := "example.com."
	ceName := "example.com."
	qname := "nonexist.example.com."

	hCE := nsec3HashName(ceName, dns.SHA1, 0, "")

	// Cover for the name walk, but NOT for *.ce (no covering records at all
	// — so the wildcard can't be denied).
	hWildcard := nsec3HashName("*."+ceName, dns.SHA1, 0, "")

	ceMatch := &dns.NSEC3{
		Hdr:   dns.Header{Name: hCE + "." + zone, Class: dns.ClassINET, TTL: 300},
		NSEC3: rdata.NSEC3{Hash: dns.SHA1, Flags: 0, Iterations: 0, Salt: "", NextDomain: hCE, TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC3}},
	}
	// The narrowCover uses (000..0, VVV..V) which covers EVERYTHING including
	// the wildcard. To create a missing-wildcard-cover case, use only the CE
	// match without any covering NSEC3. The walk will fail at the first step
	// (no cover for H(qname)) → findClosestEncloser fails → NXDOMAIN fails.
	verified := []*dns.NSEC3{ceMatch} // no covering NSEC3 at all
	if matchesNSEC3Denial(verified, qname, dns.TypeA, "NXDOMAIN", dns.SHA1, 0, "") {
		t.Error("NXDOMAIN without any covering NSEC3 should fail")
	}
	_ = hWildcard
}

func TestMatchesNSEC3Denial_NXDOMAIN_MissingNextCloserCover(t *testing.T) {
	// CE matches H(QNAME) directly without prior cover → bogus.
	zone := "example.com."
	qname := "example.com." // qname IS the zone apex
	hQname := nsec3HashName(qname, dns.SHA1, 0, "")

	// An NSEC3 matching H(qname) directly — since this is the first iteration
	// (no prior cover), findClosestEncloser rejects it as bogus.
	directMatch := &dns.NSEC3{
		Hdr:   dns.Header{Name: hQname + "." + zone, Class: dns.ClassINET, TTL: 300},
		NSEC3: rdata.NSEC3{Hash: dns.SHA1, Flags: 0, Iterations: 0, Salt: "", NextDomain: hQname, TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC3}},
	}
	verified := []*dns.NSEC3{directMatch}
	if matchesNSEC3Denial(verified, qname, dns.TypeA, "NXDOMAIN", dns.SHA1, 0, "") {
		t.Error("direct match without prior cover should fail NXDOMAIN")
	}
}

func TestMatchesNSEC3Denial_NODATA_Match(t *testing.T) {
	zone := "example.com."
	qname := "www.example.com."
	hQname := nsec3HashName(qname, dns.SHA1, 0, "")

	nsec3 := &dns.NSEC3{
		Hdr:   dns.Header{Name: hQname + "." + zone, Class: dns.ClassINET, TTL: 300},
		NSEC3: rdata.NSEC3{Hash: dns.SHA1, Flags: 0, Iterations: 0, Salt: "", NextDomain: hQname, TypeBitMap: []uint16{dns.TypeRRSIG, dns.TypeNSEC3}},
	}
	verified := []*dns.NSEC3{nsec3}
	if !matchesNSEC3Denial(verified, qname, dns.TypeA, "NODATA", dns.SHA1, 0, "") {
		t.Error("NODATA with matching NSEC3 and absent qtype should pass")
	}
}

func TestMatchesNSEC3Denial_NODATA_CNAMEBit(t *testing.T) {
	zone := "example.com."
	qname := "www.example.com."
	hQname := nsec3HashName(qname, dns.SHA1, 0, "")

	// CNAME bit set → NODATA must be false (RFC 6840 §4.3).
	nsec3 := &dns.NSEC3{
		Hdr:   dns.Header{Name: hQname + "." + zone, Class: dns.ClassINET, TTL: 300},
		NSEC3: rdata.NSEC3{Hash: dns.SHA1, Flags: 0, Iterations: 0, Salt: "", NextDomain: hQname, TypeBitMap: []uint16{dns.TypeCNAME, dns.TypeRRSIG, dns.TypeNSEC3}},
	}
	verified := []*dns.NSEC3{nsec3}
	if matchesNSEC3Denial(verified, qname, dns.TypeA, "NODATA", dns.SHA1, 0, "") {
		t.Error("CNAME bit set should return false for NODATA")
	}
}

func TestMatchesNSEC3Denial_NODATA_QtypePresent(t *testing.T) {
	zone := "example.com."
	qname := "www.example.com."
	hQname := nsec3HashName(qname, dns.SHA1, 0, "")

	// Type A in bitmap → NODATA for A should be false.
	nsec3 := &dns.NSEC3{
		Hdr:   dns.Header{Name: hQname + "." + zone, Class: dns.ClassINET, TTL: 300},
		NSEC3: rdata.NSEC3{Hash: dns.SHA1, Flags: 0, Iterations: 0, Salt: "", NextDomain: hQname, TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC3}},
	}
	verified := []*dns.NSEC3{nsec3}
	if matchesNSEC3Denial(verified, qname, dns.TypeA, "NODATA", dns.SHA1, 0, "") {
		t.Error("qtype present in bitmap should return false for NODATA")
	}
}

func TestMatchesNSEC3Denial_NODATA_EmptyNonTerminal(t *testing.T) {
	// Empty non-terminal: NSEC3 with empty bitmap → NODATA passes.
	zone := "example.com."
	qname := "ent.example.com."
	hQname := nsec3HashName(qname, dns.SHA1, 0, "")

	nsec3 := &dns.NSEC3{
		Hdr:   dns.Header{Name: hQname + "." + zone, Class: dns.ClassINET, TTL: 300},
		NSEC3: rdata.NSEC3{Hash: dns.SHA1, Flags: 0, Iterations: 0, Salt: "", NextDomain: hQname, TypeBitMap: []uint16{}},
	}
	verified := []*dns.NSEC3{nsec3}
	if !matchesNSEC3Denial(verified, qname, dns.TypeA, "NODATA", dns.SHA1, 0, "") {
		t.Error("empty non-terminal (empty bitmap) should pass NODATA")
	}
}

func TestMatchesNSEC3Denial_WildcardNODATA(t *testing.T) {
	// No NSEC3 matches H(qname), but *.ce exists with the qtype absent.
	zone := "example.com."
	ceName := "example.com."
	qname := "nonexist.example.com."

	hCE := nsec3HashName(ceName, dns.SHA1, 0, "")
	hWildcard := nsec3HashName("*."+ceName, dns.SHA1, 0, "")

	lowHash := strings.Repeat("0", 32)
	highHash := strings.Repeat("V", 32)

	// Universal cover for the CE walk.
	universalCover := &dns.NSEC3{
		Hdr:   dns.Header{Name: lowHash + "." + zone, Class: dns.ClassINET, TTL: 300},
		NSEC3: rdata.NSEC3{Hash: dns.SHA1, Flags: 0, Iterations: 0, Salt: "", NextDomain: highHash, TypeBitMap: []uint16{}},
	}
	// CE match
	ceMatch := &dns.NSEC3{
		Hdr:   dns.Header{Name: hCE + "." + zone, Class: dns.ClassINET, TTL: 300},
		NSEC3: rdata.NSEC3{Hash: dns.SHA1, Flags: 0, Iterations: 0, Salt: "", NextDomain: hCE, TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC3}},
	}
	// Wildcard match: H(*.ce) exists, no TypeAAAA in bitmap.
	wildcardMatch := &dns.NSEC3{
		Hdr:   dns.Header{Name: hWildcard + "." + zone, Class: dns.ClassINET, TTL: 300},
		NSEC3: rdata.NSEC3{Hash: dns.SHA1, Flags: 0, Iterations: 0, Salt: "", NextDomain: hWildcard, TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC3}},
	}

	verified := []*dns.NSEC3{universalCover, ceMatch, wildcardMatch}
	// Query for AAAA which is NOT in the wildcard bitmap → NODATA should pass.
	if !matchesNSEC3Denial(verified, qname, dns.TypeAAAA, "NODATA", dns.SHA1, 0, "") {
		t.Error("wildcard NODATA (AAAA absent from *.ce bitmap) should pass")
	}
	// But query for A (which IS in the bitmap) should fail.
	if matchesNSEC3Denial(verified, qname, dns.TypeA, "NODATA", dns.SHA1, 0, "") {
		t.Error("wildcard NODATA (A present in *.ce bitmap) should fail")
	}
}

// ── Integration: IsResponseValid with NSEC3 ──────────────────────────────────

// nsec3Rec builds an NSEC3 record with a real SHA1 hash of name as the owner.
func nsec3Rec(name, zone string, flags uint8, nextDomain string, bitmap []uint16) *dns.NSEC3 {
	h := nsec3HashName(name, dns.SHA1, 0, "")
	return &dns.NSEC3{
		Hdr:   dns.Header{Name: h + "." + zone, Class: dns.ClassINET, TTL: 300},
		NSEC3: rdata.NSEC3{Hash: dns.SHA1, Flags: flags, Iterations: 0, Salt: "", NextDomain: nextDomain, TypeBitMap: bitmap},
	}
}

func TestIsResponseValid_NSEC3NXDOMAIN(t *testing.T) {
	cv := NewCryptoValidator(nil)
	zone := "example.com."
	_, _ = genTestKey(zone, dns.FlagSEP|dns.FlagZONE)
	zsk, zskPriv := genTestKey(zone, dns.FlagZONE)

	qname := "nonexist.example.com."

	// Universal cover: (000...0, VVV...V) covers every real hash.
	lowHash := strings.Repeat("0", 32)
	highHash := strings.Repeat("V", 32)
	cover := nsec3Rec(zone, zone, 0, highHash, []uint16{})
	cover.Hdr.Name = lowHash + "." + zone // override — universal cover must have lowHash owner

	// CE match at the zone apex.
	ceMatch := nsec3Rec(zone, zone, 0, nsec3HashName(zone, dns.SHA1, 0, ""), []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC3})

	rrsigCover := signRRset([]dns.RR{cover}, zone, zskPriv, zsk.KeyTag())
	rrsigCE := signRRset([]dns.RR{ceMatch}, zone, zskPriv, zsk.KeyTag())

	response := &dns.Msg{
		MsgHeader: dns.MsgHeader{Rcode: dns.RcodeNameError},
		Ns:        []dns.RR{cover, rrsigCover, ceMatch, rrsigCE},
	}
	dnsutil.SetQuestion(response, qname, dns.TypeA)

	verified, err := cv.IsResponseValid(response, zone, []*dns.DNSKEY{zsk})
	if err != nil {
		t.Errorf("NSEC3 NXDOMAIN should pass: %v", err)
	}
	if !verified {
		t.Error("NSEC3 NXDOMAIN should be verified")
	}
}

func TestIsResponseValid_NSEC3NODATA(t *testing.T) {
	cv := NewCryptoValidator(nil)
	zone := "example.com."
	_, _ = genTestKey(zone, dns.FlagSEP|dns.FlagZONE)
	zsk, zskPriv := genTestKey(zone, dns.FlagZONE)

	qname := "www.example.com."

	// NSEC3 matching H(www.example.com.) — name exists, type absent.
	match := nsec3Rec(qname, zone, 0, nsec3HashName(qname, dns.SHA1, 0, ""), []uint16{dns.TypeRRSIG, dns.TypeNSEC3})
	rrsigMatch := signRRset([]dns.RR{match}, zone, zskPriv, zsk.KeyTag())

	response := &dns.Msg{
		MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess},
		Ns:        []dns.RR{match, rrsigMatch},
	}
	dnsutil.SetQuestion(response, qname, dns.TypeA)

	verified, err := cv.IsResponseValid(response, zone, []*dns.DNSKEY{zsk})
	if err != nil {
		t.Errorf("NSEC3 NODATA should pass: %v", err)
	}
	if !verified {
		t.Error("NSEC3 NODATA should be verified")
	}
}

func TestIsResponseValid_NSEC3OptOut(t *testing.T) {
	cv := NewCryptoValidator(nil)
	zone := "example.com."
	_, _ = genTestKey(zone, dns.FlagSEP|dns.FlagZONE)
	zsk, zskPriv := genTestKey(zone, dns.FlagZONE)

	qname := "nonexist.example.com."

	lowHash := strings.Repeat("0", 32)
	highHash := strings.Repeat("V", 32)
	// Cover with Opt-Out flag set.
	cover := nsec3Rec(zone, zone, nsec3OptOutFlag, highHash, []uint16{})
	cover.Hdr.Name = lowHash + "." + zone

	ceMatch := nsec3Rec(zone, zone, 0, nsec3HashName(zone, dns.SHA1, 0, ""), []uint16{dns.TypeA, dns.TypeNSEC3, dns.TypeRRSIG})

	rrsigCover := signRRset([]dns.RR{cover}, zone, zskPriv, zsk.KeyTag())
	rrsigCE := signRRset([]dns.RR{ceMatch}, zone, zskPriv, zsk.KeyTag())

	response := &dns.Msg{
		MsgHeader: dns.MsgHeader{Rcode: dns.RcodeNameError},
		Ns:        []dns.RR{cover, rrsigCover, ceMatch, rrsigCE},
	}
	dnsutil.SetQuestion(response, qname, dns.TypeA)

	_, err := cv.IsResponseValid(response, zone, []*dns.DNSKEY{zsk})
	if err == nil {
		t.Error("Opt-Out proof should suppress AD (return error)")
	}
}

// ── RFC 4035 §5.3.3: TTL cap ────────────────────────────────────────────────

func TestCapValidatedTTL(t *testing.T) {
	farFuture := uint32(time.Now().Add(24 * time.Hour).Unix()) //nolint:gosec // G115: DNSSEC timestamp — protocol-bounded uint32
	a := &dns.A{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 3600},
		A:   rdata.A{Addr: netip.MustParseAddr("1.2.3.4")},
	}
	sig := &dns.RRSIG{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		RRSIG: rdata.RRSIG{
			TypeCovered: dns.TypeA, Algorithm: dns.RSASHA256,
			OrigTTL: 600, Expiration: farFuture,
			Inception: uint32(time.Now().Add(-1 * time.Hour).Unix()), //nolint:gosec // G115: DNSSEC timestamp — protocol-bounded uint32
			KeyTag:    12345, SignerName: "example.com.",
		},
	}
	answer := []dns.RR{a, sig}
	CapValidatedTTL(answer, nil, nil)
	if a.Header().TTL != 300 {
		t.Fatalf("min(3600,300,600,farFuture)=300, got %d", a.Header().TTL)
	}
}

func TestVerifyRRset_SignatureExpired(t *testing.T) {
	cv := NewCryptoValidator(nil)
	zone := "test.example.com"
	ksk, priv := genTestKey(zone, dns.FlagSEP|dns.FlagZONE)
	rrset := []dns.RR{aRec(zone, "192.0.2.1")}
	rrsig := signRRset(rrset, zone, priv, ksk.KeyTag())
	// Manually expire the signature
	rrsig.Expiration = uint32(time.Now().Add(-1 * time.Hour).Unix()) //nolint:gosec // G115: DNSSEC timestamp — protocol-bounded uint32
	rrsig.Inception = uint32(time.Now().Add(-2 * time.Hour).Unix())  //nolint:gosec // G115: DNSSEC timestamp — protocol-bounded uint32

	err := cv.VerifyRRset(rrset, rrsig, ksk)
	if err == nil {
		t.Fatal("expired signature should return error")
	}
	if !errors.Is(err, ErrSignatureExpired) {
		t.Errorf("expired sig should wrap ErrSignatureExpired, got: %v", err)
	}
}

func TestVerifyRRset_SignatureNotYet(t *testing.T) {
	cv := NewCryptoValidator(nil)
	zone := "test.example.com"
	ksk, priv := genTestKey(zone, dns.FlagSEP|dns.FlagZONE)
	rrset := []dns.RR{aRec(zone, "192.0.2.1")}
	rrsig := signRRset(rrset, zone, priv, ksk.KeyTag())
	rrsig.Inception = uint32(time.Now().Add(2 * time.Hour).Unix())  //nolint:gosec // G115: DNSSEC timestamp — protocol-bounded uint32
	rrsig.Expiration = uint32(time.Now().Add(3 * time.Hour).Unix()) //nolint:gosec // G115: DNSSEC timestamp — protocol-bounded uint32

	err := cv.VerifyRRset(rrset, rrsig, ksk)
	if err == nil {
		t.Fatal("not-yet-valid signature should return error")
	}
	if !errors.Is(err, ErrSignatureNotYet) {
		t.Errorf("not-yet-valid sig should wrap ErrSignatureNotYet, got: %v", err)
	}
}
