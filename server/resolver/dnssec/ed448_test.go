package dnssec

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/cloudflare/circl/sign/ed448"
)

// RFC 8080 §6.2 vectors as corrected by verified erratum 4935 (Tom
// Thorogood, 2017): the published §6 RRSIGs omitted the algorithm field
// and counted the root as a label (Labels=3). The erratum recomputed both
// Ed448 examples with Labels=2 — these are those corrected signatures.
const (
	rfc8080DNSKEY1 = "3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx1FYYUcJKm1MDpJtIA"
	rfc8080RRSIG1  = "3cPAHkmlnxcDHMyg7vFC34l0blBhuG1qpwLmjInI8w1CMB29FkEAIJUA0amxWndkmnBZ6SKiwZSAxGILn/NBtOXft0+Gj7FSvOKxE/07+4RQvE581N3Aj/JtIyaiYVdnYtyMWbSNyGEY2213WKsJlwEA"
	rfc8080DNSKEY2 = "kkreGWoccSDmUBGAe7+zsbG6ZAFQp+syPmYUurBRQc3tDjeMCJcVMRDmgcNLp5HlHAMy12VoISsA"
	rfc8080RRSIG2  = "E1/oLjSGIbmLny/4fcgM1z4oL6aqo+izT3urCyHyvEp4Sp8Syg1eI+lJ57CSnZqjJP41O/9l4m0AsQ4f7qI1gVnML8vWWiyW2KXhT9kuAICUSxv5OWbf81Rq7Yu60npabODB0QFPb/rkW3kUZmQ0YQUA"
)

// TestVerifyRRsetED448RFC8080Vector drives the erratum-4935 corrected §6.2
// vectors through the production crypto path. The validity window (2015)
// has lapsed, so VerifyRRset would reject it before the crypto —
// rrsig.Verify is the same call VerifyRRset makes after its date checks.
func TestVerifyRRsetED448RFC8080Vector(t *testing.T) {
	for _, tc := range []struct {
		name   string
		pubB64 string
		sigB64 string
		keyTag uint16
	}{
		{"keytag9713", rfc8080DNSKEY1, rfc8080RRSIG1, 9713},
		{"keytag38353", rfc8080DNSKEY2, rfc8080RRSIG2, 38353},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dnskey := &dns.DNSKEY{
				Hdr:       dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 3600},
				Flags:     dns.FlagSEP | dns.FlagZONE,
				Protocol:  3,
				Algorithm: dns.ED448,
				PublicKey: tc.pubB64,
			}
			if tag := dnskey.KeyTag(); tag != tc.keyTag {
				t.Fatalf("DNSKEY key tag = %d, want %d (RFC 8080 §6.2)", tag, tc.keyTag)
			}
			rrset := []dns.RR{&dns.MX{
				Hdr:        dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 3600},
				Preference: 10,
				Mx:         "mail.example.com.",
			}}
			rrsig := &dns.RRSIG{
				Hdr:         dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 3600},
				TypeCovered: dns.TypeMX,
				Algorithm:   dns.ED448,
				Labels:      2, // erratum 4935: example.com. has 2 labels — the RFC text wrongly shipped 3
				OrigTTL:     3600,
				Expiration:  1440021600,
				Inception:   1438207200,
				KeyTag:      tc.keyTag,
				SignerName:  "example.com.",
				Signature:   tc.sigB64,
			}
			if err := rrsig.Verify(dnskey, rrset, &dns.SignOption{VerifyFunc: verifyDelegated}); err != nil {
				t.Fatalf("RFC 8080 §6.2 Ed448 vector rejected: %v", err)
			}

			sig, err := base64.StdEncoding.DecodeString(rrsig.Signature)
			if err != nil {
				t.Fatal(err)
			}
			sig[10] ^= 0xFF
			rrsig.Signature = base64.StdEncoding.EncodeToString(sig)
			if err := rrsig.Verify(dnskey, rrset, &dns.SignOption{VerifyFunc: verifyDelegated}); err == nil {
				t.Fatal("tampered Ed448 signature accepted")
			}
		})
	}
}

// TestVerifyRRsetED448Roundtrip signs an A RRset with a fresh circl key and
// drives it through the production VerifyRRset path, including the
// expired-signature and tampered-signature classifications.
func TestVerifyRRsetED448Roundtrip(t *testing.T) {
	cv := NewCryptoValidator(nil)
	zone := "ed448.example.com"
	pub, priv, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed448 key: %v", err)
	}
	dnskey := &dns.DNSKEY{
		Hdr:       dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 3600},
		Flags:     dns.FlagZONE,
		Protocol:  3,
		Algorithm: dns.ED448,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	rrset := []dns.RR{&dns.A{
		Hdr:  dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 300},
		Addr: netip.MustParseAddr("192.0.2.1"),
	}}
	rrsig := &dns.RRSIG{
		Hdr:         dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 3600},
		TypeCovered: dns.TypeA,
		Algorithm:   dns.ED448,
		Labels:      uint8(dnsutil.Labels(dnsutil.Fqdn(zone))), //nolint:gosec // G115: DNS label count — protocol-bounded byte
		OrigTTL:     300,
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()), //nolint:gosec // G115: DNSSEC timestamp — protocol-bounded uint32
		Inception:   uint32(time.Now().Add(-1 * time.Hour).Unix()), //nolint:gosec // G115: DNSSEC timestamp — protocol-bounded uint32
		KeyTag:      dnskey.KeyTag(),
		SignerName:  dnsutil.Fqdn(zone),
		Signature:   base64.StdEncoding.EncodeToString(make([]byte, ed448SignatureLen)),
	}

	message := ed448CaptureSignedData(t, rrsig, dnskey, rrset)
	rrsig.Signature = base64.StdEncoding.EncodeToString(ed448.Sign(priv, message, ""))
	if err := cv.VerifyRRset(rrset, rrsig, dnskey); err != nil {
		t.Fatalf("valid Ed448 RRSIG rejected: %v", err)
	}

	// Expired window → ErrSignatureExpired (before any crypto).
	old := rrsig.Expiration
	rrsig.Expiration = uint32(time.Now().Add(-1 * time.Hour).Unix()) //nolint:gosec // G115: DNSSEC timestamp — protocol-bounded uint32
	if err := cv.VerifyRRset(rrset, rrsig, dnskey); !errors.Is(err, ErrSignatureExpired) {
		t.Fatalf("expired Ed448 RRSIG: want ErrSignatureExpired, got %v", err)
	}
	rrsig.Expiration = old

	// Tampered signature → ErrBogusSignature, not "unsupported algorithm".
	sig, err := base64.StdEncoding.DecodeString(rrsig.Signature)
	if err != nil {
		t.Fatal(err)
	}
	sig[5] ^= 0xFF
	rrsig.Signature = base64.StdEncoding.EncodeToString(sig)
	if err := cv.VerifyRRset(rrset, rrsig, dnskey); !errors.Is(err, ErrBogusSignature) {
		t.Fatalf("tampered Ed448 RRSIG: want ErrBogusSignature, got %v", err)
	}
}

// ed448CaptureSignedData records the exact RFC 4034 §3.1.8.1 signed data
// miekg hands to the VerifyFunc (same technique as sm2sm3_test.go).
func ed448CaptureSignedData(t *testing.T, rrsig *dns.RRSIG, dnskey *dns.DNSKEY, rrset []dns.RR) []byte {
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
