package security

import (
	"crypto/ecdsa"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ── Test helpers ─────────────────────────────────────────────────────────────

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

// aRec is a helper to create an A record with a net.IP.
func aRec(name string, ip string) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.IP{net.ParseIP(ip).To4()[0], net.ParseIP(ip).To4()[1], net.ParseIP(ip).To4()[2], net.ParseIP(ip).To4()[3]},
	}
}

// ── VerifyRRset ───────────────────────────────────────────────────────────────

func TestVerifyRRset_ValidSignature(t *testing.T) {
	cv := NewCryptoValidator()
	zone := "test.example.com"
	ksk, priv := genTestKey(zone, dns.SEP|dns.ZONE)

	// Create an A record + sign it
	rrset := []dns.RR{aRec(zone, "192.0.2.1")}
	rrsig := signRRset(rrset, zone, priv, ksk.KeyTag())

	if err := cv.VerifyRRset(rrset, rrsig, ksk); err != nil {
		t.Errorf("valid signature should pass: %v", err)
	}
}

func TestVerifyRRset_WrongKey(t *testing.T) {
	cv := NewCryptoValidator()
	zone := "test.example.com"
	ksk, priv := genTestKey(zone, dns.SEP|dns.ZONE)
	wrongKey, _ := genTestKey(zone, dns.SEP|dns.ZONE) // different key pair

	rrset := []dns.RR{aRec(zone, "192.0.2.1")}
	rrsig := signRRset(rrset, zone, priv, ksk.KeyTag())

	if err := cv.VerifyRRset(rrset, rrsig, wrongKey); err == nil {
		t.Error("signature with wrong key should fail")
	}
}

func TestVerifyRRset_ExpiredSignature(t *testing.T) {
	cv := NewCryptoValidator()
	zone := "test.example.com"
	ksk, priv := genTestKey(zone, dns.SEP|dns.ZONE)

	rrset := []dns.RR{aRec(zone, "192.0.2.1")}
	rrsig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: dns.TypeA,
		Algorithm:   dns.ECDSAP256SHA256,
		Labels:      3,
		OrigTtl:     300,
		Expiration:  uint32(time.Now().Add(-48 * time.Hour).Unix()), // expired!
		Inception:   uint32(time.Now().Add(-72 * time.Hour).Unix()),
		KeyTag:      ksk.KeyTag(),
		SignerName:  dns.Fqdn(zone),
	}
	_ = rrsig.Sign(priv, rrset)

	if err := cv.VerifyRRset(rrset, rrsig, ksk); err == nil {
		t.Error("expired signature should fail")
	}
}

// ── VerifyDelegationDS ────────────────────────────────────────────────────────

func TestVerifyDelegationDS_Matching(t *testing.T) {
	cv := NewCryptoValidator()
	childZone := "child.example.com"
	ksk, _ := genTestKey(childZone, dns.SEP|dns.ZONE)

	// Parent computes DS from child's KSK
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
	cv := NewCryptoValidator()
	childZone := "child.example.com"
	ksk, _ := genTestKey(childZone, dns.SEP|dns.ZONE)
	otherKey, _ := genTestKey("other.example.com", dns.SEP|dns.ZONE)

	// DS computed from ksk, but we present otherKey — should fail
	ds := ksk.ToDS(dns.SHA256)

	_, err := cv.VerifyDelegationDS([]*dns.DS{ds}, []*dns.DNSKEY{otherKey})
	if err == nil {
		t.Error("mismatched DS should fail")
	}
}

func TestVerifyDelegationDS_SkipsNonSEP(t *testing.T) {
	cv := NewCryptoValidator()
	childZone := "child.example.com"
	zsk, _ := genTestKey(childZone, dns.ZONE) // ZSK, no SEP flag
	ksk, _ := genTestKey(childZone, dns.SEP|dns.ZONE)

	// DS from KSK
	ds := ksk.ToDS(dns.SHA256)

	// Present both ZSK and KSK; DS should match KSK, not ZSK
	matchedKey, err := cv.VerifyDelegationDS([]*dns.DS{ds}, []*dns.DNSKEY{zsk, ksk})
	if err != nil {
		t.Errorf("DS should match KSK even when ZSK present: %v", err)
	}
	if matchedKey.Flags&dns.SEP == 0 {
		t.Error("matched key should have SEP flag set")
	}
}

// ── SelfVerifyDNSKEY ─────────────────────────────────────────────────────────

func TestSelfVerifyDNSKEY_Valid(t *testing.T) {
	cv := NewCryptoValidator()
	zone := "example.net"
	ksk, kskPriv := genTestKey(zone, dns.SEP|dns.ZONE)
	zsk, _ := genTestKey(zone, dns.ZONE)

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
	cv := NewCryptoValidator()
	zone := "example.net"
	ksk, _ := genTestKey(zone, dns.SEP|dns.ZONE)
	zsk, _ := genTestKey(zone, dns.ZONE)
	wrongKey, wrongPriv := genTestKey("attacker.com", dns.SEP|dns.ZONE)

	dnskeys := []*dns.DNSKEY{ksk, zsk}
	rrset := make([]dns.RR, len(dnskeys))
	for i, k := range dnskeys {
		rrset[i] = k
	}
	// Signed by attacker's key, not the zone's KSK
	rrsig := signRRset(rrset, zone, wrongPriv, wrongKey.KeyTag())

	if err := cv.SelfVerifyDNSKEY(dnskeys, []*dns.RRSIG{rrsig}); err == nil {
		t.Error("self-verify should fail when signed by foreign key")
	}
}

func TestSelfVerifyDNSKEY_NoSEPKey(t *testing.T) {
	cv := NewCryptoValidator()
	zone := "example.net"
	zsk, zskPriv := genTestKey(zone, dns.ZONE) // ZSK only, no KSK

	dnskeys := []*dns.DNSKEY{zsk}
	rrset := make([]dns.RR, len(dnskeys))
	for i, k := range dnskeys {
		rrset[i] = k
	}
	rrsig := signRRset(rrset, zone, zskPriv, zsk.KeyTag())

	// ZSK can sign, but SelfVerifyDNSKEY only checks KSK (SEP bit)
	if err := cv.SelfVerifyDNSKEY(dnskeys, []*dns.RRSIG{rrsig}); err == nil {
		t.Error("self-verify should fail when no KSK (SEP) is present")
	}
}

// ── ValidateResponse (end-to-end answer validation) ──────────────────────────

func TestValidateResponse_SignedAnswer(t *testing.T) {
	cv := NewCryptoValidator()
	zone := "signed.example.com"
	ksk, _ := genTestKey(zone, dns.SEP|dns.ZONE)
	zsk, zskPriv := genTestKey(zone, dns.ZONE)

	// Build a signed A record answer
	aRec := &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   aRec(zone, "203.0.113.1").A,
	}
	rrsig := signRRset([]dns.RR{aRec}, zone, zskPriv, zsk.KeyTag())

	response := &dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
		Answer: []dns.RR{aRec, rrsig},
	}
	// Both ZSK and KSK as verified keys (ZSK signed the A record)
	verified, err := cv.ValidateResponse(response, zone, []*dns.DNSKEY{zsk, ksk})
	if err != nil {
		t.Errorf("ValidateResponse should pass: %v", err)
	}
	if !verified {
		t.Error("signed answer should be verified")
	}
}

func TestValidateResponse_UnsignedAnswer(t *testing.T) {
	cv := NewCryptoValidator()
	zone := "unsigned.example.com"
	_, _ = genTestKey(zone, dns.SEP|dns.ZONE)
	zsk, _ := genTestKey(zone, dns.ZONE)

	aRec := &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   aRec(zone, "203.0.113.1").A,
	}
	// No RRSIG present
	response := &dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
		Answer: []dns.RR{aRec},
	}
	verified, _ := cv.ValidateResponse(response, zone, []*dns.DNSKEY{zsk})
	if verified {
		t.Error("unsigned answer should not be verified")
	}
}

func TestValidateResponse_NoDNSKEYs(t *testing.T) {
	cv := NewCryptoValidator()
	response := &dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
		Answer: []dns.RR{aRec("test.example.com", "192.0.2.1")},
	}
	verified, _ := cv.ValidateResponse(response, "test.example.com", nil)
	if verified {
		t.Error("should return false with no DNSKEYs")
	}
}

// ── NSEC / NSEC3 ─────────────────────────────────────────────────────────────

func TestFindNSEC(t *testing.T) {
	nsec := &dns.NSEC{Hdr: dns.RR_Header{Name: "a.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET}}
	rrs := []dns.RR{nsec, &dns.A{Hdr: dns.RR_Header{Name: "a.com.", Rrtype: dns.TypeA, Class: dns.ClassINET}}}
	if len(findNSEC(rrs)) != 1 {
		t.Error("should find NSEC record")
	}
}

func TestFindNSEC3(t *testing.T) {
	nsec3 := &dns.NSEC3{Hdr: dns.RR_Header{Name: "abc.a.com.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET}}
	rrs := []dns.RR{nsec3}
	if len(findNSEC3(rrs)) != 1 {
		t.Error("should find NSEC3 record")
	}
}

func TestValidateResponse_NXDOMAIN(t *testing.T) {
	cv := NewCryptoValidator()
	zone := "signed.example.com"
	_, _ = genTestKey(zone, dns.SEP|dns.ZONE)
	zsk, zskPriv := genTestKey(zone, dns.ZONE)

	// Query for a name that doesn't exist. The NSEC range
	// [aaaa.signed.example.com., zzzz.signed.example.com.) covers
	// nonexistent.signed.example.com. in canonical ordering (aaaa < nonexistent < zzzz).
	qname := "nonexistent.signed.example.com."
	qtype := dns.TypeA

	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "aaaa.signed.example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "zzzz.signed.example.com.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
	}
	rrsig := signRRset([]dns.RR{nsec}, zone, zskPriv, zsk.KeyTag())

	response := &dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError},
		Ns:     []dns.RR{nsec, rrsig},
	}
	response.SetQuestion(dns.Fqdn(qname), qtype)
	verified, err := cv.ValidateResponse(response, zone, []*dns.DNSKEY{zsk})
	if err != nil {
		t.Errorf("NXDOMAIN with signed NSEC should pass: %v", err)
	}
	if !verified {
		t.Error("signed NSEC for NXDOMAIN should be verified")
	}
}

// ── Full chain: DS → DNSKEY → answer ────────────────────────────────────────

func TestFullDNSSECChain(t *testing.T) {
	cv := NewCryptoValidator()
	childZone := "child.example.net"

	// Parent has KSK, creates DS for child
	childKSK, _ := genTestKey(childZone, dns.SEP|dns.ZONE)
	childZSK, childZSKPriv := genTestKey(childZone, dns.ZONE)
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
		Hdr: dns.RR_Header{Name: dns.Fqdn(childZone), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   aRec(childZone, "198.51.100.1").A,
	}
	rrsig := signRRset([]dns.RR{aRec}, childZone, childZSKPriv, childZSK.KeyTag())
	response := &dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
		Answer: []dns.RR{aRec, rrsig},
	}

	verifiedKeys := cv.GetZoneKeys(childZone)
	if len(verifiedKeys) == 0 {
		t.Fatal("zone keys not cached")
	}
	validated, err := cv.ValidateResponse(response, childZone, verifiedKeys)
	if err != nil {
		t.Errorf("full chain validation should pass: %v", err)
	}
	if !validated {
		t.Error("full chain should produce validated=true")
	}
}

// ── Edge cases ────────────────────────────────────────────────────────────────

func TestDNSSEC_BogusDelegation(t *testing.T) {
	cv := NewCryptoValidator()
	childZone := "bogus.example.com"

	// Parent creates DS from one KSK
	realKSK, _ := genTestKey(childZone, dns.SEP|dns.ZONE)
	ds := realKSK.ToDS(dns.SHA256)

	// Child presents a DIFFERENT KSK (not matching the DS)
	fakeKSK, _ := genTestKey(childZone, dns.SEP|dns.ZONE)

	// DS→DNSKEY should FAIL — this is a bogus delegation
	_, err := cv.VerifyDelegationDS([]*dns.DS{ds}, []*dns.DNSKEY{fakeKSK})
	if err == nil {
		t.Error("bogus delegation: DS from parent must not match a different child KSK")
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────
