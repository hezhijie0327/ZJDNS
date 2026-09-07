package dnssec

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/emmansun/gmsm/sm2"
)

// sm2GenKey generates an SM2 key pair and the matching DNSKEY with the
// RFC 9563 §4.1 "x | y" public-key encoding.
func sm2GenKey(t *testing.T, zone string) (*dns.DNSKEY, *sm2.PrivateKey) {
	t.Helper()
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}
	// The DNSKEY carries the bare "x | y" (RFC 9563 §4.1). Raw X/Y access
	// is required here: PublicKey.Bytes() only supports the NIST curves.
	x := priv.PublicKey.X.FillBytes(make([]byte, sm2PublicKeyLen/2)) //nolint:staticcheck // SA1019: SM2 is not a NIST curve — Bytes() rejects it
	y := priv.PublicKey.Y.FillBytes(make([]byte, sm2PublicKeyLen/2)) //nolint:staticcheck // SA1019: SM2 is not a NIST curve — Bytes() rejects it
	return &dns.DNSKEY{
		Hdr:       dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 3600},
		Flags:     dns.FlagZONE,
		Protocol:  3,
		Algorithm: dns.SM2SM3,
		PublicKey: base64.StdEncoding.EncodeToString(append(append(make([]byte, 0, sm2PublicKeyLen), x...), y...)),
	}, priv
}

// sm2CaptureSignedData runs miekg's RRSIG.Verify with a recording VerifyFunc
// to obtain the exact RFC 4034 §3.1.8.1 signed data the library hands to
// verifySM2SM3.
func sm2CaptureSignedData(t *testing.T, rrsig *dns.RRSIG, dnskey *dns.DNSKEY, rrset []dns.RR) []byte {
	t.Helper()
	var captured []byte
	_ = rrsig.Verify(dnskey, rrset, &dns.SignOption{VerifyFunc: func(_ *dns.DNSKEY, message, _ []byte) bool {
		captured = append([]byte(nil), message...)
		return false
	}})
	if captured == nil {
		t.Fatal("VerifyFunc not invoked — signed data not captured")
	}
	return captured
}

// sm2SignWire signs the message per RFC 9563: standard SM2 with the default
// user ID (GM/T 0003.2 §6), DER converted to the fixed-width "r | s" wire
// form.  rrsig.Sign cannot be used — it passes the raw data to
// crypto.Signer as a precomputed digest, skipping the ZA/SM3 step and
// producing a non-compliant signature.
func sm2SignWire(t *testing.T, priv *sm2.PrivateKey, message []byte) []byte {
	t.Helper()
	der, err := priv.SignWithSM2(rand.Reader, nil, message)
	if err != nil {
		t.Fatalf("sign with SM2: %v", err)
	}
	parsed := sm2SigASN1{R: new(big.Int), S: new(big.Int)}
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		t.Fatalf("unmarshal DER signature: %v", err)
	}
	wire := make([]byte, sm2SignatureLen)
	parsed.R.FillBytes(wire[:sm2SignatureLen/2])
	parsed.S.FillBytes(wire[sm2SignatureLen/2:])
	return wire
}

// TestVerifyRRsetSM2SM3 signs an A RRset per RFC 9563 and drives it through
// the production VerifyRRset path.
func TestVerifyRRsetSM2SM3(t *testing.T) {
	cv := NewCryptoValidator(nil)
	zone := "sm2.example.com"
	dnskey, priv := sm2GenKey(t, zone)
	rrset := []dns.RR{&dns.A{
		Hdr:  dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 300},
		Addr: netip.MustParseAddr("192.0.2.1"),
	}}
	rrsig := &dns.RRSIG{
		Hdr:         dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 3600},
		TypeCovered: dns.TypeA,
		Algorithm:   dns.SM2SM3,
		Labels:      uint8(dnsutil.Labels(dnsutil.Fqdn(zone))), //nolint:gosec // G115: DNS label count — protocol-bounded byte
		OrigTTL:     300,
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()), //nolint:gosec // G115: DNSSEC timestamp — protocol-bounded uint32
		Inception:   uint32(time.Now().Add(-1 * time.Hour).Unix()), //nolint:gosec // G115: DNSSEC timestamp — protocol-bounded uint32
		KeyTag:      dnskey.KeyTag(),
		SignerName:  dnsutil.Fqdn(zone),
		Signature:   base64.StdEncoding.EncodeToString(make([]byte, sm2SignatureLen)),
	}

	message := sm2CaptureSignedData(t, rrsig, dnskey, rrset)
	rrsig.Signature = base64.StdEncoding.EncodeToString(sm2SignWire(t, priv, message))
	if err := cv.VerifyRRset(rrset, rrsig, dnskey); err != nil {
		t.Fatalf("valid SM2SM3 RRSIG rejected: %v", err)
	}

	// Flipped signature byte → bogus, not "unsupported algorithm".
	wire, err := base64.StdEncoding.DecodeString(rrsig.Signature)
	if err != nil {
		t.Fatal(err)
	}
	wire[10] ^= 0xFF
	rrsig.Signature = base64.StdEncoding.EncodeToString(wire)
	if err := cv.VerifyRRset(rrset, rrsig, dnskey); !errors.Is(err, ErrBogusSignature) {
		t.Fatalf("tampered SM2SM3 signature: want ErrBogusSignature, got %v", err)
	}
}

// TestVerifyRRsetSM2SM3DNSKEYSelfSignature signs the DNSKEY RRset itself — the shape
// every SM2SM3 zone bootstraps with (RFC 9563 §6 example), and the only
// RRset whose members are DNSKEYs.
func TestVerifyRRsetSM2SM3DNSKEYSelfSignature(t *testing.T) {
	cv := NewCryptoValidator(nil)
	zone := "sm2.example.com"
	dnskey, priv := sm2GenKey(t, zone)
	rrset := []dns.RR{dnskey}
	rrsig := &dns.RRSIG{
		Hdr:         dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 3600},
		TypeCovered: dns.TypeDNSKEY,
		Algorithm:   dns.SM2SM3,
		Labels:      uint8(dnsutil.Labels(dnsutil.Fqdn(zone))), //nolint:gosec // G115: DNS label count — protocol-bounded byte
		OrigTTL:     3600,
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()), //nolint:gosec // G115: DNSSEC timestamp — protocol-bounded uint32
		Inception:   uint32(time.Now().Add(-1 * time.Hour).Unix()), //nolint:gosec // G115: DNSSEC timestamp — protocol-bounded uint32
		KeyTag:      dnskey.KeyTag(),
		SignerName:  dnsutil.Fqdn(zone),
		Signature:   base64.StdEncoding.EncodeToString(make([]byte, sm2SignatureLen)),
	}
	message := sm2CaptureSignedData(t, rrsig, dnskey, rrset)
	rrsig.Signature = base64.StdEncoding.EncodeToString(sm2SignWire(t, priv, message))
	if err := cv.VerifyRRset(rrset, rrsig, dnskey); err != nil {
		t.Fatalf("valid SM2SM3 DNSKEY self-signature rejected: %v", err)
	}
}

// TestVerifyRRsetUnsupportedAlgorithmPreserved guards the EDE 1
// classification: with VerifyFunc wired, algorithms the validator cannot
// verify (GOST 23 here) must still surface ErrUnsupportedAlgorithm, not a
// generic bogus.
func TestVerifyRRsetUnsupportedAlgorithmPreserved(t *testing.T) {
	cv := NewCryptoValidator(nil)
	zone := "gost.example.com"
	dnskey := &dns.DNSKEY{
		Hdr:       dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 3600},
		Flags:     dns.FlagZONE,
		Protocol:  3,
		Algorithm: dns.ECCGOST12,
		PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 64)),
	}
	rrset := []dns.RR{&dns.A{
		Hdr:  dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 300},
		Addr: netip.MustParseAddr("192.0.2.1"),
	}}
	rrsig := &dns.RRSIG{
		Hdr:         dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 3600},
		TypeCovered: dns.TypeA,
		Algorithm:   dns.ECCGOST12,
		Labels:      uint8(dnsutil.Labels(dnsutil.Fqdn(zone))), //nolint:gosec // G115: DNS label count — protocol-bounded byte
		OrigTTL:     300,
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()), //nolint:gosec // G115: DNSSEC timestamp — protocol-bounded uint32
		Inception:   uint32(time.Now().Add(-1 * time.Hour).Unix()), //nolint:gosec // G115: DNSSEC timestamp — protocol-bounded uint32
		KeyTag:      dnskey.KeyTag(),
		SignerName:  dnsutil.Fqdn(zone),
		Signature:   base64.StdEncoding.EncodeToString(make([]byte, 8)),
	}
	if err := cv.VerifyRRset(rrset, rrsig, dnskey); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("unverifiable algorithm: want ErrUnsupportedAlgorithm, got %v", err)
	}
}

// TestVerifySM2SM3ShapeGuards covers the wire-shape rejections that never
// reach gmsm: wrong algorithm, wrong signature or public-key length, and a
// public key that is not a curve point.
func TestVerifySM2SM3ShapeGuards(t *testing.T) {
	zone := "sm2.example.com"
	dnskey, _ := sm2GenKey(t, zone)
	pub, err := base64.StdEncoding.DecodeString(dnskey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dummy := make([]byte, sm2SignatureLen)

	wrongAlg := *dnskey
	wrongAlg.Algorithm = dns.ED448
	if verifySM2SM3(&wrongAlg, dummy, dummy) {
		t.Fatal("non-SM2SM3 algorithm must be rejected")
	}
	if verifySM2SM3(dnskey, dummy[:sm2SignatureLen-1], dummy) {
		t.Fatal("short signature must be rejected")
	}

	shortPub := *dnskey
	shortPub.PublicKey = base64.StdEncoding.EncodeToString(pub[:sm2PublicKeyLen-1])
	if verifySM2SM3(&shortPub, dummy, dummy) {
		t.Fatal("63-octet public key must be rejected")
	}
	notAPoint := *dnskey
	notAPoint.PublicKey = base64.StdEncoding.EncodeToString(make([]byte, sm2PublicKeyLen))
	if verifySM2SM3(&notAPoint, dummy, dummy) {
		t.Fatal("all-zero public key must be rejected")
	}
}
