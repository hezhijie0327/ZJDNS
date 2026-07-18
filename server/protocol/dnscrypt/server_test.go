package dnscrypt

import (
	"testing"
	"time"
	"zjdns/config"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"

	"codeberg.org/miekg/dns"
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
	if srv.keys[0].pair.Classical.ResolverSk == [dnscryptcrypto.KeySize]byte{} {
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

func TestHandshakeTTL(t *testing.T) {
	certificateCfg := &config.DNSCryptCertificate{}

	srv, err := New(certificateCfg, "0", "2.dnscrypt-cert.example.com")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Build a valid handshake TXT query.
	m := new(dns.Msg)
	txtRR := new(dns.TXT)
	txtRR.Hdr = dns.Header{Name: "2.dnscrypt-cert.example.com.", Class: dns.ClassINET}
	m.Question = []dns.RR{txtRR}
	if err := m.Pack(); err != nil {
		t.Fatalf("pack query: %v", err)
	}
	query := m.Data

	certValiditySec := uint32((config.DefaultDNSCryptCertificateTTL + config.DefaultDNSCryptKeyOverlap).Seconds())

	// Case 1: single fresh window → 2 certs (Classical + PQ), TTL ≈ 25h.
	// Proves TTL is certificate-validity-based, not the old static DefaultTTL=10.
	res, err := srv.handleHandshake(query)
	if err != nil {
		t.Fatalf("handleHandshake: %v", err)
	}

	reply := new(dns.Msg)
	reply.Data = res
	if err := reply.Unpack(); err != nil {
		t.Fatalf("unpack reply: %v", err)
	}
	if len(reply.Answer) != 2 {
		t.Fatalf("single window: want 2 answer records, got %d", len(reply.Answer))
	}

	for _, rr := range reply.Answer {
		ttl := rr.Header().TTL
		if ttl <= config.DefaultTTL {
			t.Errorf("fresh key: TTL = %d; expected > %d (cert-validity-based, not static DefaultTTL)", ttl, config.DefaultTTL)
		}
		if ttl > certValiditySec {
			t.Errorf("fresh key: TTL = %d; expected <= %d (certValidity)", ttl, certValiditySec)
		}
	}

	// Case 2: rotate + age the old key to 23h → 4 certs (2 windows × 2 certs).
	// New window TTL ≈ 25h, old window TTL ≈ 2h.
	srv.rotateKeys()
	srv.mu.Lock()
	srv.keys[1].createdAt = time.Now().Add(-23 * time.Hour)
	srv.mu.Unlock()

	res, err = srv.handleHandshake(query)
	if err != nil {
		t.Fatalf("handleHandshake multi-window: %v", err)
	}

	reply = new(dns.Msg)
	reply.Data = res
	if err := reply.Unpack(); err != nil {
		t.Fatalf("unpack reply multi-window: %v", err)
	}

	if len(reply.Answer) != 4 {
		t.Fatalf("multi-window: want 4 answer records (2 windows × 2 certs), got %d", len(reply.Answer))
	}

	// First two records (keys[0]): Classical + PQ, fresh → ≈25h.
	for i := range 2 {
		ttl := reply.Answer[i].Header().TTL
		if ttl <= config.DefaultTTL {
			t.Errorf("multi-window fresh[%d]: TTL = %d; expected > %d", i, ttl, config.DefaultTTL)
		}
		if ttl > certValiditySec {
			t.Errorf("multi-window fresh[%d]: TTL = %d; expected <= %d", i, ttl, certValiditySec)
		}
	}

	// Last two records (keys[1]): Classical + PQ, aged 23h → ≈2h = 7200s.
	for i := range 2 {
		j := i + 2
		ttl := reply.Answer[j].Header().TTL
		if ttl < 7080 || ttl > 7320 {
			t.Errorf("multi-window aged[%d]: TTL = %d; expected ~7200 (±120)", j, ttl)
		}
	}

	// Case 3: old key > 25h → purged. Simulate by removing keys[1]:
	// back to 2 certs from the single remaining window.
	srv.mu.Lock()
	srv.keys = srv.keys[:1]
	srv.mu.Unlock()

	res, err = srv.handleHandshake(query)
	if err != nil {
		t.Fatalf("handleHandshake after purge: %v", err)
	}

	reply = new(dns.Msg)
	reply.Data = res
	if err := reply.Unpack(); err != nil {
		t.Fatalf("unpack reply after purge: %v", err)
	}

	if len(reply.Answer) != 2 {
		t.Fatalf("after purge: want 2 answer records, got %d", len(reply.Answer))
	}

	for _, rr := range reply.Answer {
		ttl := rr.Header().TTL
		if ttl <= config.DefaultTTL || ttl > certValiditySec {
			t.Errorf("after purge: TTL = %d; expected <= %d", ttl, certValiditySec)
		}
	}
}
