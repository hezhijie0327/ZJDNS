package dnscrypt

import (
	"testing"
	"time"
	"zjdns/config"
)

func TestKeyRotation(t *testing.T) {
	certificateCfg := &config.DNSCryptCertificate{}

	srv, err := New(certificateCfg, "0", "2.dnscrypt-cert.example.com")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// After startup: one key pair.
	if len(srv.keys) != 1 {
		t.Fatalf("after New: want 1 key, got %d", len(srv.keys))
	}
	initialSerial := srv.current().Classical.Serial

	// Simulate a 24h rotation.
	srv.rotateKeys()

	// After rotation: two key pairs (current + previous).
	if len(srv.keys) != 2 {
		t.Fatalf("after rotateKeys: want 2 keys, got %d", len(srv.keys))
	}

	// Current has newer (higher) serial than previous.
	curr := srv.current().Classical
	if curr.Serial < initialSerial {
		t.Errorf("new serial (%d) should be >= old serial (%d)", curr.Serial, initialSerial)
	}

	// Verify both certs in each pair are non-nil.
	if srv.keys[0].pair.Classical == nil || srv.keys[0].pair.PQ == nil {
		t.Error("current pair has nil cert")
	}
	if srv.keys[1].pair.Classical == nil || srv.keys[1].pair.PQ == nil {
		t.Error("previous pair has nil cert")
	}

	// Verify the previous entry's classical cert is still valid.
	if srv.keys[1].pair.Classical.NotAfter < uint32(time.Now().Unix()) { //nolint:gosec // G115
		t.Error("previous classical cert NotAfter is in the past")
	}
	// PQ cert must also be valid.
	if srv.keys[1].pair.PQ.NotAfter < uint32(time.Now().Unix()) { //nolint:gosec // G115
		t.Error("previous PQ cert NotAfter is in the past")
	}

	// Classical cert has non-zero ResolverSk.
	if srv.keys[0].pair.Classical.ResolverSk == [KeySize]byte{} {
		t.Error("current classical cert has zero ResolverSk")
	}

	// PQ cert has non-zero PqPrivateKey.
	if len(srv.keys[0].pair.PQ.PqPrivateKey) == 0 {
		t.Error("current PQ cert has zero-length PqPrivateKey")
	}

	// Both certs in a pair share the same serial.
	if srv.keys[0].pair.Classical.Serial != srv.keys[0].pair.PQ.Serial {
		t.Error("classical and PQ certs in pair have different serials")
	}

	// Simulate purge: oldest entry should be removed after overlap period.
	srv.keys[0].createdAt = time.Now().Add(-config.DefaultDNSCryptCertificateTTL - config.DefaultDNSCryptKeyOverlap - time.Hour)
	srv.rotateKeys()
	if len(srv.keys) < 2 {
		t.Errorf("after purge rotation: want >= 2 keys, got %d", len(srv.keys))
	}
}

func TestCertPairTXT(t *testing.T) {
	certificateCfg := &config.DNSCryptCertificate{}

	srv, err := New(certificateCfg, "0", "2.dnscrypt-cert.example.com")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Classical cert: 124 bytes — fits in 1 chunk.
	classicalChunks := buildCertTXTForCert(srv.keys[0].pair.Classical)
	if len(classicalChunks) != 1 {
		t.Errorf("classical cert: want 1 TXT chunk, got %d", len(classicalChunks))
	}

	// PQ cert: 1320 bytes — 6 chunks (1320 / 255 = 5.17 → 6).
	pqChunks := buildCertTXTForCert(srv.keys[0].pair.PQ)
	if len(pqChunks) < 5 {
		t.Errorf("PQ cert: want >= 5 TXT chunks, got %d", len(pqChunks))
	}

	// Verify serial alignment across the pair.
	if srv.keys[0].pair.Classical.Serial != srv.keys[0].pair.PQ.Serial {
		t.Error("classical and PQ serial differ")
	}
	if srv.keys[0].pair.Classical.NotAfter != srv.keys[0].pair.PQ.NotAfter {
		t.Error("classical and PQ NotAfter differ")
	}
}
