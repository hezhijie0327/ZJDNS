package dnscrypt

import (
	"bytes"
	"strings"
	"testing"
	"time"
	"zjdns/config"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"

	"codeberg.org/miekg/dns"
)

// ageWindow shifts a key window's NotBefore/NotAfter back by d, simulating
// the passage of time without invalidating the cert (NotAfter stays ahead).
func ageWindow(srv *Server, idx int, d time.Duration) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	k := &srv.keys[idx]
	nb := k.pair.Classical.NotBefore - uint32(d/time.Second) //nolint:gosec // G115: test window shift — protocol-bounded uint32
	na := nb + uint32(config.DefaultDNSCryptCertificateTTL/time.Second)
	k.pair.Classical.NotBefore = nb
	k.pair.Classical.NotAfter = na
	k.pair.PQ.NotBefore = nb
	k.pair.PQ.NotAfter = na
}

// extractCert decodes the TXT chunks of a handshake answer back into the raw
// certificate bytes.  The codeberg.org/miekg/dns fork encodes non-printable
// bytes as \DDD in TXT rdata on pack and does NOT decode them on unpack, so
// the raw wire form is recovered here (\\ stays \\ — the escapeBackslash
// doubling of a literal backslash — and \DDD becomes the byte).
func extractCert(t *testing.T, rr dns.RR) []byte {
	t.Helper()
	txt, ok := rr.(*dns.TXT)
	if !ok {
		t.Fatalf("expected TXT record, got %T", rr)
	}
	s := strings.Join(txt.Txt, "")
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			out = append(out, s[i])
			continue
		}
		// \\ (escapeBackslash doubling of a literal backslash, passed through
		// verbatim) must be folded before \DDD — matching order matters.
		if i+1 < len(s) && s[i+1] == '\\' {
			out = append(out, '\\')
			i++
			continue
		}
		if i+3 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' &&
			s[i+2] >= '0' && s[i+2] <= '9' && s[i+3] >= '0' && s[i+3] <= '9' {
			out = append(out, (s[i+1]-'0')*100+(s[i+2]-'0')*10+s[i+3]-'0')
			i += 3
		}
	}
	return out
}

func TestKeyRotation(t *testing.T) {
	certificateCfg := testCfg()

	srv, err := New(certificateCfg, "0", "2.dnscrypt-cert.example.com", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// After startup: one key pair.
	if len(srv.keys) != 1 {
		t.Fatalf("after New: want 1 key, got %d", len(srv.keys))
	}

	// Serial is always 1 (matching encrypted-dns-server).
	if srv.current().Classical.Serial != 1 {
		t.Errorf("serial: want 1, got %d", srv.current().Classical.Serial)
	}

	// Age the initial window 8h → the next renewal mints a second window
	// from the seed chain.
	ageWindow(srv, 0, 8*time.Hour)
	srv.updateKeys()

	if len(srv.keys) != 2 {
		t.Fatalf("after updateKeys: want 2 keys, got %d", len(srv.keys))
	}

	// Both certs in each pair are non-nil and serial stays 1.
	for _, k := range srv.keys {
		if k.pair.Classical == nil || k.pair.PQ == nil {
			t.Error("cert pair has a nil cert")
		}
		if k.pair.Classical.Serial != 1 || k.pair.PQ.Serial != 1 {
			t.Error("cert serial must be 1")
		}
	}

	// Classical cert has non-zero ResolverSk.
	if srv.keys[0].pair.Classical.ResolverSk == [dnscryptcrypto.KeySize]byte{} {
		t.Error("current classical cert has zero ResolverSk")
	}

	// PQ cert has non-zero PqPrivateKey.
	if len(srv.keys[0].pair.PQ.PqPrivateKey) == 0 {
		t.Error("current PQ cert has zero-length PqPrivateKey")
	}

	// Seed chain: the newest window's PK derives from the previous SK.
	seed := srv.keys[1].pair.Classical.ResolverSk
	_, wantPk, err := dnscryptcrypto.X25519KeyPairFromSeed(seed)
	if err != nil {
		t.Fatalf("X25519KeyPairFromSeed: %v", err)
	}
	if !bytes.Equal(srv.keys[0].pair.Classical.ResolverPk[:], wantPk[:]) {
		t.Error("seed chain: new window PK does not derive from previous SK")
	}

	// Age the oldest window past NotAfter → the next renewal purges it,
	// leaving only the newest window.
	ageWindow(srv, 1, 24*time.Hour)
	srv.updateKeys()
	if len(srv.keys) != 1 {
		t.Errorf("after purge renewal: want 1 key (expired window dropped), got %d", len(srv.keys))
	}
}

func TestCertPairTXT(t *testing.T) {
	certificateCfg := testCfg()

	srv, err := New(certificateCfg, "0", "2.dnscrypt-cert.example.com", nil)
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
	certificateCfg := testCfg()

	srv, err := New(certificateCfg, "0", "2.dnscrypt-cert.example.com", nil)
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

	staticTTL := uint32(config.DefaultDNSCryptCertificateRenewal / time.Second) // 8h

	// Case 1: single fresh window → 2 certs (Classical + PQ), static TTL = 8h
	// (the renewal interval, matching encrypted-dns-server).
	res, err := srv.handleHandshake(query, false)
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
		if rr.Header().TTL != staticTTL {
			t.Errorf("TTL: want %d (static renewal interval), got %d", staticTTL, rr.Header().TTL)
		}
	}

	// Case 2: multiple internal windows (seed chain) — the handshake still
	// returns ONLY the newest window's 2 certs, with the same static TTL.
	ageWindow(srv, 0, 16*time.Hour)
	srv.updateKeys()
	if len(srv.keys) < 2 {
		t.Fatalf("multi-window setup: want >= 2 keys, got %d", len(srv.keys))
	}

	res, err = srv.handleHandshake(query, false)
	if err != nil {
		t.Fatalf("handleHandshake multi-window: %v", err)
	}

	reply = new(dns.Msg)
	reply.Data = res
	if err := reply.Unpack(); err != nil {
		t.Fatalf("unpack reply multi-window: %v", err)
	}

	if len(reply.Answer) != 2 {
		t.Fatalf("multi-window: want 2 answer records (newest window only), got %d", len(reply.Answer))
	}
	for _, rr := range reply.Answer {
		if rr.Header().TTL != staticTTL {
			t.Errorf("multi-window TTL: want %d, got %d", staticTTL, rr.Header().TTL)
		}
	}

	// The returned classical cert must be the NEWEST window's cert.
	wantClassical, err := srv.keys[0].pair.Classical.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal newest classical cert: %v", err)
	}
	gotClassical := extractCert(t, reply.Answer[0])
	if !bytes.Equal(gotClassical, wantClassical) {
		t.Error("handshake returned a stale window's classical cert")
	}

	// The returned PQ cert must be the NEWEST window's PQ cert.
	wantPQ, err := srv.keys[0].pair.PQ.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal newest PQ cert: %v", err)
	}
	gotPQ := extractCert(t, reply.Answer[1])
	if !bytes.Equal(gotPQ, wantPQ) {
		t.Error("handshake returned a stale window's PQ cert")
	}
}

func TestSeedChain(t *testing.T) {
	certificateCfg := testCfg()
	srv, err := New(certificateCfg, "0", "2.dnscrypt-cert.example.com", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// 16h of age → 2 missed renewals (8h, 16h) are caught up on the next
	// updateKeys: 2 new windows + the original = 3.
	ageWindow(srv, 0, 16*time.Hour)
	srv.updateKeys()
	if len(srv.keys) != 3 {
		t.Fatalf("16h catch-up: want 3 windows, got %d", len(srv.keys))
	}

	// Chain: each window's PK derives from the previous window's SK, and
	// windows are ordered newest-first (NotBefore strictly decreasing).
	for i := 0; i+1 < len(srv.keys); i++ {
		seed := srv.keys[i+1].pair.Classical.ResolverSk
		_, wantPk, err := dnscryptcrypto.X25519KeyPairFromSeed(seed)
		if err != nil {
			t.Fatalf("X25519KeyPairFromSeed: %v", err)
		}
		if !bytes.Equal(srv.keys[i].pair.Classical.ResolverPk[:], wantPk[:]) {
			t.Errorf("window %d PK not derived from window %d SK (chain broken)", i, i+1)
		}
		if srv.keys[i].pair.Classical.NotBefore <= srv.keys[i+1].pair.Classical.NotBefore {
			t.Errorf("windows not ordered newest-first (%d vs %d)",
				srv.keys[i].pair.Classical.NotBefore, srv.keys[i+1].pair.Classical.NotBefore)
		}
	}

	// Windows are spaced exactly one renewal apart.
	if srv.keys[0].pair.Classical.NotBefore-srv.keys[1].pair.Classical.NotBefore !=
		uint32(config.DefaultDNSCryptCertificateRenewal/time.Second) {
		t.Error("adjacent windows must be exactly one renewal interval apart")
	}
}

func TestPurgeExpiredKeys(t *testing.T) {
	certificateCfg := testCfg()
	srv, err := New(certificateCfg, "0", "2.dnscrypt-cert.example.com", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Two windows.
	ageWindow(srv, 0, 8*time.Hour)
	srv.updateKeys()
	if len(srv.keys) != 2 {
		t.Fatalf("setup: want 2 keys, got %d", len(srv.keys))
	}

	// Expire the older window → purged promptly (no overlap grace).
	past := dnscryptcrypto.NowUnix32() - 1
	srv.mu.Lock()
	srv.keys[1].pair.Classical.NotAfter = past
	srv.keys[1].pair.PQ.NotAfter = past
	srv.mu.Unlock()
	srv.purgeExpiredKeys()
	if len(srv.keys) != 1 {
		t.Fatalf("after purge: want 1 key, got %d", len(srv.keys))
	}

	// The newest entry is never purged even when itself expired — the key
	// list must never become empty (renewal mints the fresh window).
	srv.mu.Lock()
	srv.keys[0].pair.Classical.NotAfter = past
	srv.keys[0].pair.PQ.NotAfter = past
	srv.mu.Unlock()
	srv.purgeExpiredKeys()
	if len(srv.keys) != 1 {
		t.Fatalf("purge must keep the newest key: want 1 key, got %d", len(srv.keys))
	}
}

func TestHandshakeTC_ClassicalPreserved(t *testing.T) {
	// When the UDP cert query is too small for the PQ cert, the response
	// must have TC=true with the classical cert preserved (§5.5/§10.3).
	certificateCfg := testCfg()
	srv, err := New(certificateCfg, "0", "2.dnscrypt-cert.example.com", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Build a handshake query that is large enough for the classical cert
	// but too small for the classical+PQ pair.  Classical cert is ~124 bytes
	// TXT-wire (~140 bytes).  PQ is ~1320 bytes TXT-wire (~1350 bytes).
	// Together ~1500 bytes.  Query of 200 bytes → PQ omitted, TC=true.
	m := new(dns.Msg)
	txtRR := new(dns.TXT)
	txtRR.Hdr = dns.Header{Name: "2.dnscrypt-cert.example.com.", Class: dns.ClassINET}
	m.Question = []dns.RR{txtRR}
	if err := m.Pack(); err != nil {
		t.Fatalf("pack query: %v", err)
	}
	query := m.Data
	t.Logf("cert query size: %d bytes", len(query))

	res, err := srv.handleHandshake(query, true) // isUDP=true
	if err != nil {
		t.Fatalf("handleHandshake: %v", err)
	}

	reply := new(dns.Msg)
	reply.Data = res
	if err := reply.Unpack(); err != nil {
		t.Fatalf("unpack reply: %v", err)
	}

	// Must have TC=true because PQ cert doesn't fit.
	if !reply.Truncated {
		t.Error("UDP cert response must have TC=true when PQ cert omitted")
	}
	// Must include the classical cert (at least 1 TXT record).
	if len(reply.Answer) == 0 {
		t.Fatal("TC cert response must preserve classical cert (≥1 TXT record)")
	}
	for _, rr := range reply.Answer {
		if _, ok := rr.(*dns.TXT); !ok {
			t.Errorf("expected TXT record, got %T", rr)
		}
	}
	t.Logf("TC response: %d TXT records, TC=%v", len(reply.Answer), reply.Truncated)
}

func TestHandshakeTC_AllFit_NoTC(t *testing.T) {
	// TCP query → no anti-amplification → both certs fit → TC=false.
	certificateCfg := testCfg()
	srv, err := New(certificateCfg, "0", "2.dnscrypt-cert.example.com", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	m := new(dns.Msg)
	txtRR := new(dns.TXT)
	txtRR.Hdr = dns.Header{Name: "2.dnscrypt-cert.example.com.", Class: dns.ClassINET}
	m.Question = []dns.RR{txtRR}
	if err := m.Pack(); err != nil {
		t.Fatalf("pack query: %v", err)
	}

	// TCP → no anti-amplification budget → both certs always included.
	res, err := srv.handleHandshake(m.Data, false) // isUDP=false
	if err != nil {
		t.Fatalf("handleHandshake: %v", err)
	}

	reply := new(dns.Msg)
	reply.Data = res
	if err := reply.Unpack(); err != nil {
		t.Fatalf("unpack reply: %v", err)
	}

	if reply.Truncated {
		t.Error("TCP cert query must have TC=false (both certs fit, no anti-amplification)")
	}
	if len(reply.Answer) < 2 {
		t.Errorf("want ≥2 TXT records (classical+PQ), got %d", len(reply.Answer))
	}
	t.Logf("TCP response: %d TXT records, TC=%v", len(reply.Answer), reply.Truncated)
}
