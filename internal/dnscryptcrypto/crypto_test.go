package dnscryptcrypto

import (
	"crypto/rand"
	"errors"
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

func TestMinResponseOverhead(t *testing.T) {
	if got := MinResponseOverhead(XChacha20Poly1305); got != 49 {
		t.Errorf("classical: want 49, got %d", got)
	}
	if got := MinResponseOverhead(XWingPQ); got != 51 {
		t.Errorf("PQ: want 51, got %d", got)
	}
}

func TestPadResponse_Deterministic(t *testing.T) {
	// Same inputs → same padding.
	var sk [SharedKeySize]byte
	copy(sk[:], "test-shared-key-32-bytes!!!!!!!")
	cn := []byte("client-nonce12")

	packet := []byte{0x12, 0x34, 0x01, 0x00} // fake DNS header

	r1, _ := PadResponse(packet, &sk, cn, 0)
	r2, _ := PadResponse(packet, &sk, cn, 0)

	if len(r1) != len(r2) {
		t.Fatalf("deterministic padding: lengths differ (%d vs %d)", len(r1), len(r2))
	}
	for i := range r1 {
		if r1[i] != r2[i] {
			t.Fatalf("deterministic padding: byte %d differs", i)
		}
	}
	// Must start with original packet + 0x80 delimiter.
	if r1[len(packet)] != 0x80 {
		t.Error("padding delimiter not 0x80")
	}
	// Must be multiple of 64.
	if len(r1)&63 != 0 {
		t.Errorf("padded length %d not multiple of 64", len(r1))
	}
	t.Logf("PadResponse: %d → %d bytes (pad=%d)", len(packet), len(r1), len(r1)-len(packet))
}

func TestPadResponse_DifferentInputs(t *testing.T) {
	// Different sharedKey → different padding.
	var sk1, sk2 [SharedKeySize]byte
	copy(sk1[:], "key-aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	copy(sk2[:], "key-bbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	cn := []byte("client-nonce12")
	packet := []byte{0x12, 0x34, 0x01, 0x00}

	r1, _ := PadResponse(packet, &sk1, cn, 0)
	r2, _ := PadResponse(packet, &sk2, cn, 0)

	// Different keys SHOULD produce different padding (with overwhelming probability).
	same := len(r1) == len(r2)
	if same {
		for i := range r1 {
			if i >= len(r2) || r1[i] != r2[i] {
				same = false
				break
			}
		}
	}
	if same {
		t.Error("different shared keys produced identical padding (1/256 chance)")
	}
}

func TestPadResponse_Budget(t *testing.T) {
	var sk [SharedKeySize]byte
	cn := []byte("client-nonce12")
	packet := make([]byte, 100)

	// Budget > preferred padding → full padding.
	r, err := PadResponse(packet, &sk, cn, 500)
	if err != nil {
		t.Fatalf("PadResponseWithin: %v", err)
	}
	if len(r)&63 != 0 {
		t.Errorf("within budget: len %d not multiple of 64", len(r))
	}
	if len(r) > 500 {
		t.Errorf("within budget: len %d exceeds max 500", len(r))
	}
}

func TestPadResponse_Clamped(t *testing.T) {
	var sk [SharedKeySize]byte
	cn := []byte("client-nonce12")
	packet := make([]byte, 120)

	// Tight budget → padding shrinks.
	r, err := PadResponse(packet, &sk, cn, 125)
	if err != nil {
		t.Fatalf("PadResponseWithin clamped: %v", err)
	}
	if len(r) > 125 {
		t.Errorf("clamped: len %d exceeds max 125", len(r))
	}
	if r[len(packet)] != 0x80 {
		t.Error("clamped: missing 0x80 delimiter")
	}
}

func TestPadResponse_NoRoom(t *testing.T) {
	var sk [SharedKeySize]byte
	cn := []byte("client-nonce12")
	packet := make([]byte, 100)

	_, err := PadResponse(packet, &sk, cn, 100)
	if !errors.Is(err, ErrNoRoomForPadding) {
		t.Errorf("want ErrNoRoomForPadding, got %v", err)
	}
}
