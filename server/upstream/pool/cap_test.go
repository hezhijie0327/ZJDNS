package pool

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// testALPN is the DoQ ALPN used by the loopback QUIC pair.
const testALPN = "doq"

// selfSignedTLS generates a throwaway self-signed certificate for the
// loopback QUIC listener.
func selfSignedTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "zjdns-test.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"zjdns-test.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{testALPN},
	}
}

// startFakeQUICServer listens for QUIC connections without serving any
// streams — the pool only needs completed handshakes for its lifecycle
// tracking.
func startFakeQUICServer(t *testing.T) string {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	ln, err := quic.Listen(udpConn, selfSignedTLS(t), nil)
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func(c *quic.Conn) {
				// Hold the connection open; drain streams when a client
				// eventually opens one.
				for {
					stream, err := c.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go func(s *quic.Stream) {
						defer func() { _ = s.Close() }()
						buf := make([]byte, 4096)
						for {
							if _, err := s.Read(buf); err != nil {
								return
							}
						}
					}(stream)
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// TestConnPool_GlobalCapEvictsLRU verifies the global live-connection cap:
// dialing a third key over maxTotal evicts the least-recently-used
// connection (H1).
func TestConnPool_GlobalCapEvictsLRU(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	p := NewConnPool(4, 16, 2) // maxTotal = 2

	dialFunc := func(ctx context.Context, a string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", a)
	}

	c1, err := p.Acquire(context.Background(), "key1", l.Addr().String(), dialFunc)
	if err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	c2, err := p.Acquire(context.Background(), "key2", l.Addr().String(), dialFunc)
	if err != nil {
		t.Fatalf("acquire 2: %v", err)
	}
	// Deterministic LRU order — dials all land in the same NowUnix() second.
	c1.lastUsed.Store(100)
	c2.lastUsed.Store(200)

	c3, err := p.Acquire(context.Background(), "key3", l.Addr().String(), dialFunc)
	if err != nil {
		t.Fatalf("acquire 3: %v", err)
	}
	if c3 == nil {
		t.Fatal("acquire 3 returned nil connection")
	}

	if !c1.IsDead() {
		t.Error("LRU connection (c1) must be evicted at the global cap")
	}
	if c2.IsDead() {
		t.Error("c2 must survive — it is not the LRU")
	}

	p.mu.Lock()
	total, keys := p.total, len(p.conns)
	_, key1Present := p.conns["key1"]
	p.mu.Unlock()
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	if keys != 2 {
		t.Errorf("keys = %d, want 2", keys)
	}
	if key1Present {
		t.Error("evicted key's empty entry must be deleted")
	}
}

// TestRawPool_GlobalCapEvictsLRU verifies the raw-frame pool enforces the
// same global cap.
func TestRawPool_GlobalCapEvictsLRU(t *testing.T) {
	_, addr := startFakeRawServer(t, 0)
	p := NewRawPool(4, 16, 2, rawTestExtractor)

	dialFunc := func(ctx context.Context, a string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", a)
	}

	c1, err := p.Acquire(context.Background(), "key1", addr, dialFunc)
	if err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	c2, err := p.Acquire(context.Background(), "key2", addr, dialFunc)
	if err != nil {
		t.Fatalf("acquire 2: %v", err)
	}
	c1.lastUsed.Store(100)
	c2.lastUsed.Store(200)

	c3, err := p.Acquire(context.Background(), "key3", addr, dialFunc)
	if err != nil {
		t.Fatalf("acquire 3: %v", err)
	}
	if c3 == nil {
		t.Fatal("acquire 3 returned nil connection")
	}

	if !c1.IsDead() {
		t.Error("LRU connection (c1) must be evicted at the global cap")
	}
	if c2.IsDead() {
		t.Error("c2 must survive — it is not the LRU")
	}

	p.mu.Lock()
	total, keys := p.total, len(p.conns)
	p.mu.Unlock()
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	if keys != 2 {
		t.Errorf("keys = %d, want 2", keys)
	}
}

// TestConnPool_GlobalCapBusyOvershoot verifies the soft-cap contract for the
// TCP pool: with every connection busy at maxTotal, a new dial overshoots
// the cap instead of evicting an in-flight connection and failing its
// waiters (the dial-churn loop).
func TestConnPool_GlobalCapBusyOvershoot(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	p := NewConnPool(4, 16, 2) // maxTotal = 2

	dialFunc := func(ctx context.Context, a string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", a)
	}

	c1, err := p.Acquire(context.Background(), "key1", l.Addr().String(), dialFunc)
	if err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	c2, err := p.Acquire(context.Background(), "key2", l.Addr().String(), dialFunc)
	if err != nil {
		t.Fatalf("acquire 2: %v", err)
	}
	c1.inFlight.Add(1)
	c2.inFlight.Add(1)
	defer c1.inFlight.Add(-1)
	defer c2.inFlight.Add(-1)

	c3, err := p.Acquire(context.Background(), "key3", l.Addr().String(), dialFunc)
	if err != nil {
		t.Fatalf("acquire 3: %v", err)
	}
	if c3 == nil {
		t.Fatal("acquire 3 returned nil connection")
	}
	if c1.IsDead() || c2.IsDead() {
		t.Error("busy connections must never be evicted at the global cap")
	}
	p.mu.Lock()
	total := p.total
	p.mu.Unlock()
	if total != 3 {
		t.Errorf("total = %d, want 3 (soft-cap overshoot)", total)
	}
}

// TestRawPool_GlobalCapBusyOvershoot verifies the raw-frame pool enforces
// the same soft-cap contract.
func TestRawPool_GlobalCapBusyOvershoot(t *testing.T) {
	_, addr := startFakeRawServer(t, 0)
	p := NewRawPool(4, 16, 2, rawTestExtractor)

	dialFunc := func(ctx context.Context, a string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", a)
	}

	c1, err := p.Acquire(context.Background(), "key1", addr, dialFunc)
	if err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	c2, err := p.Acquire(context.Background(), "key2", addr, dialFunc)
	if err != nil {
		t.Fatalf("acquire 2: %v", err)
	}
	c1.inFlight.Add(1)
	c2.inFlight.Add(1)
	defer c1.inFlight.Add(-1)
	defer c2.inFlight.Add(-1)

	c3, err := p.Acquire(context.Background(), "key3", addr, dialFunc)
	if err != nil {
		t.Fatalf("acquire 3: %v", err)
	}
	if c3 == nil {
		t.Fatal("acquire 3 returned nil connection")
	}
	if c1.IsDead() || c2.IsDead() {
		t.Error("busy connections must never be evicted at the global cap")
	}
	p.mu.Lock()
	total := p.total
	p.mu.Unlock()
	if total != 3 {
		t.Errorf("total = %d, want 3 (soft-cap overshoot)", total)
	}
}

// TestQUIC_GlobalCapEvictsLRU verifies the QUIC pool enforces the same
// global cap against a real loopback QUIC pair.
func TestQUIC_GlobalCapEvictsLRU(t *testing.T) {
	addr := startFakeQUICServer(t)
	p := NewQUIC(4, 2) // maxTotal = 2

	clientTLS := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // G402: loopback test — self-signed cert
		NextProtos:         []string{testALPN},
	}
	dialFunc := func(ctx context.Context, key string) (*quic.Conn, error) {
		return quic.DialAddr(ctx, addr, clientTLS, nil)
	}

	pc1, err := p.Acquire(context.Background(), "key1", dialFunc)
	if err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	pc2, err := p.Acquire(context.Background(), "key2", dialFunc)
	if err != nil {
		t.Fatalf("acquire 2: %v", err)
	}
	pc1.lastUsed.Store(100)
	pc2.lastUsed.Store(200)

	pc3, err := p.Acquire(context.Background(), "key3", dialFunc)
	if err != nil {
		t.Fatalf("acquire 3: %v", err)
	}
	if pc3 == nil {
		t.Fatal("acquire 3 returned nil connection")
	}

	if !pc1.closed.Load() {
		t.Error("LRU connection (pc1) must be evicted at the global cap")
	}
	if pc2.closed.Load() {
		t.Error("pc2 must survive — it is not the LRU")
	}

	p.mu.Lock()
	total, keys := p.total, len(p.conns)
	p.mu.Unlock()
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	if keys != 2 {
		t.Errorf("keys = %d, want 2", keys)
	}
}
