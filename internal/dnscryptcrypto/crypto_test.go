package dnscryptcrypto

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/ed25519"
)

func TestCertificate_SignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cert := buildTestCert()

	cert.Sign(priv)
	if !cert.VerifySignature(pub) {
		t.Fatal("signature verification failed")
	}

	// Tamper with serial — should invalidate signature.
	cert.Serial++
	if cert.VerifySignature(pub) {
		t.Fatal("signature should fail after tampering")
	}
}

func TestCertificate_MarshalRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cert := buildTestCert()
	cert.Sign(priv)

	serialized, err := cert.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	var cert2 Certificate
	if err := cert2.UnmarshalBinary(serialized); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}

	if cert2.Serial != cert.Serial {
		t.Errorf("Serial: got %d, want %d", cert2.Serial, cert.Serial)
	}
	if !cert2.VerifySignature(pub) {
		t.Fatal("signature verification failed after round-trip")
	}
}

func TestCertificate_IsDateValid(t *testing.T) {
	now := uint32(time.Now().Unix()) //nolint:gosec // G115: DNSCrypt certificate timestamp

	t.Run("valid", func(t *testing.T) {
		cert := buildTestCert()
		cert.NotBefore = now - 3600
		cert.NotAfter = now + 3600
		if !cert.IsDateValid() {
			t.Fatal("certificate should be valid")
		}
	})

	t.Run("expired", func(t *testing.T) {
		cert := buildTestCert()
		cert.NotBefore = now - 7200
		cert.NotAfter = now - 3600
		if cert.IsDateValid() {
			t.Fatal("expired certificate should be invalid")
		}
	})

	t.Run("not yet valid", func(t *testing.T) {
		cert := buildTestCert()
		cert.NotBefore = now + 3600
		cert.NotAfter = now + 7200
		if cert.IsDateValid() {
			t.Fatal("future certificate should be invalid")
		}
	})
}

func buildTestCert() *Certificate {
	now := uint32(time.Now().Unix()) //nolint:gosec // G115: DNSCrypt certificate timestamp
	cert := &Certificate{
		Serial:      1,
		ESVersion:   XChacha20Poly1305,
		NotBefore:   now,
		NotAfter:    now + 86400,
		ClientMagic: [ClientMagicSize]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}
	if _, err := rand.Read(cert.ResolverPk[:]); err != nil {
		panic(err)
	}
	return cert
}
