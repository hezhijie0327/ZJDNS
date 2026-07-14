package dnscrypt

import (
	"testing"
	"time"
	"zjdns/config"
)

func TestKeyRotation(t *testing.T) {
	cfg := &config.DNSCryptSettings{
		Port:         "0", // Don't bind
		ProviderName: "2.dnscrypt-cert.example.com",
		ESVersion:    "xwingpq",
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// After startup: one key.
	if len(srv.keys) != 1 {
		t.Fatalf("after New: want 1 key, got %d", len(srv.keys))
	}
	initialSerial := srv.current().cert.Serial
	initialTXT := srv.allCertTXT()

	// Simulate a 24h rotation.
	srv.rotateKeys()

	// After rotation: two keys (current + previous).
	if len(srv.keys) != 2 {
		t.Fatalf("after rotateKeys: want 2 keys, got %d", len(srv.keys))
	}

	// Current has newer (higher) serial than previous.
	curr := srv.current().cert
	// Serial = unix timestamp — in tests they may land in the same second.
	if curr.Serial < initialSerial {
		t.Errorf("new serial (%d) should be >= old serial (%d)", curr.Serial, initialSerial)
	}

	// allCertTXT returns chunks from both certs.
	afterTXT := srv.allCertTXT()
	if len(afterTXT) <= len(initialTXT) {
		t.Errorf("allCertTXT after rotation (%d chunks) should be > before (%d chunks)",
			len(afterTXT), len(initialTXT))
	}

	// Verify the previous entry's cert is still valid (NotAfter check).
	if srv.keys[1].cert.NotAfter < uint32(time.Now().Unix()) { //nolint:gosec // G115: timestamp within int32 range until 2038
		t.Error("previous cert NotAfter is in the past")
	}

	// Simulate another rotation — should purge the oldest entry after overlap.
	srv.keys[0].createdAt = time.Now().Add(-config.DefaultDNSCryptCertTTL - config.DefaultDNSCryptKeyOverlap - time.Hour)
	srv.rotateKeys()
	if len(srv.keys) < 2 {
		t.Errorf("after purge rotation: want >= 2 keys, got %d", len(srv.keys))
	}
}

func TestKeyRotationClassical(t *testing.T) {
	cfg := &config.DNSCryptSettings{
		Port:         "0",
		ProviderName: "2.dnscrypt-cert.example.com",
		ESVersion:    "xchacha20poly1305",
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(srv.keys) != 1 {
		t.Fatalf("after New: want 1 key, got %d", len(srv.keys))
	}

	srv.rotateKeys()
	if len(srv.keys) != 2 {
		t.Fatalf("after rotateKeys: want 2 keys, got %d", len(srv.keys))
	}
	// Classical: ResolverSk must not be zero.
	if srv.keys[0].cert.ResolverSk == [KeySize]byte{} {
		t.Error("current classical cert has zero ResolverSk")
	}
	if srv.keys[1].cert.ResolverSk == [KeySize]byte{} {
		t.Error("previous classical cert has zero ResolverSk")
	}
}

func TestAllCertTXTServesAllActiveCerts(t *testing.T) {
	cfg := &config.DNSCryptSettings{
		Port:         "0",
		ProviderName: "2.dnscrypt-cert.example.com",
		ESVersion:    "xwingpq",
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	chunksBefore := len(srv.allCertTXT())
	srv.rotateKeys()
	chunksAfter := len(srv.allCertTXT())

	// PQ cert is 1320 bytes → 6 chunks per cert (1320 / 255 = 5.17 → 6).
	if chunksBefore < 6 {
		t.Errorf("single cert should be at least 6 TXT chunks, got %d", chunksBefore)
	}
	if chunksAfter < 12 {
		t.Errorf("two certs should be at least 12 TXT chunks, got %d", chunksAfter)
	}
}
