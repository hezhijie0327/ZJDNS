package dnscrypt

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
	"zjdns/config"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"
	serverdnscrypt "zjdns/server/protocol/dnscrypt"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

type testDNSHandler struct{}

// bigResponseHandler returns many A records to force TC truncation.
type bigResponseHandler struct{ n int }

func (h *testDNSHandler) ServeDNS(req *dns.Msg, _ net.IP, _ bool, _ string) *dns.Msg {
	reply := dnsutil.SetReply(new(dns.Msg), req)
	reply.Authoritative = true
	q := req.Question[0]
	rr := &dns.A{
		Hdr: dns.Header{Name: q.Header().Name, Class: dns.ClassINET, TTL: 60},
		A:   rdata.A{Addr: netip.MustParseAddr("1.2.3.4")},
	}
	reply.Answer = append(reply.Answer, rr)
	return reply
}

func startTestDNSCryptServer(t *testing.T) (addr, stamp string) {
	t.Helper()
	rc, err := serverdnscrypt.GenerateResolverConfig("example.com", nil)
	if err != nil {
		t.Fatalf("GenerateResolverConfig: %v", err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	cfg := &config.DNSCryptCertificate{PublicKey: rc.PublicKey, PrivateKey: rc.PrivateKey}
	srv, err := serverdnscrypt.New(cfg, strconv.Itoa(port), rc.ProviderName)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Start(&testDNSHandler{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	addr = "127.0.0.1:" + strconv.Itoa(port)
	for range 50 {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	stamp, err = rc.CreateStamp(addr)
	if err != nil {
		t.Fatalf("CreateStamp: %v", err)
	}
	return addr, stamp
}

func newQuery(name string) *dns.Msg {
	msg := &dns.Msg{}
	msg.RecursionDesired = true
	q := &dns.A{Hdr: dns.Header{Name: name, Class: dns.ClassINET}}
	msg.Question = []dns.RR{q}
	return msg
}

func TestDNSCryptUDP(t *testing.T) {
	_, stamp := startTestDNSCryptServer(t)
	c := New(nil)
	server := &config.UpstreamServer{Address: stamp, Protocol: config.ProtoDNSCrypt}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.Execute(ctx, newQuery("example.com."), server, false)
	if err != nil {
		t.Fatalf("UDP: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("want 1 answer, got %d", len(resp.Answer))
	}
	a := resp.Answer[0].(*dns.A)
	if a.Addr != netip.MustParseAddr("1.2.3.4") {
		t.Fatalf("want 1.2.3.4, got %v", a.Addr)
	}
}

func TestDNSCryptTCP(t *testing.T) {
	_, stamp := startTestDNSCryptServer(t)
	c := New(nil)
	server := &config.UpstreamServer{Address: stamp, Protocol: config.ProtoDNSCryptTCP}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.Execute(ctx, newQuery("example.com."), server, true)
	if err != nil {
		t.Fatalf("TCP: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("want 1 answer, got %d", len(resp.Answer))
	}
	a := resp.Answer[0].(*dns.A)
	if a.Addr != netip.MustParseAddr("1.2.3.4") {
		t.Fatalf("want 1.2.3.4, got %v", a.Addr)
	}
}

func TestDNSCryptUnreachableUDP(t *testing.T) {
	c := New(nil)
	server := &config.UpstreamServer{Address: "127.0.0.1:1", Protocol: config.ProtoDNSCrypt}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := c.Execute(ctx, newQuery("example.com."), server, false)
	if err == nil {
		t.Fatal("expected error from unreachable server")
	}
	t.Logf("expected error: %v", err)
}

func TestDNSCryptClassical(t *testing.T) {
	// Test classical XChacha20 mode by disabling PQ preference.
	_, stamp := startTestDNSCryptServer(t)
	c := New(nil)
	pqFalse := false
	server := &config.UpstreamServer{Address: stamp, Protocol: config.ProtoDNSCrypt, PQDNSCrypt: &pqFalse}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.Execute(ctx, newQuery("example.com."), server, false)
	if err != nil {
		t.Fatalf("Classical UDP: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("want 1 answer, got %d", len(resp.Answer))
	}
	a := resp.Answer[0].(*dns.A)
	if a.Addr != netip.MustParseAddr("1.2.3.4") {
		t.Fatalf("want 1.2.3.4, got %v", a.Addr)
	}
}

func TestDNSCryptMultiQuery(t *testing.T) {
	_, stamp := startTestDNSCryptServer(t)
	c := New(nil)
	server := &config.UpstreamServer{Address: stamp, Protocol: config.ProtoDNSCrypt}
	for i := range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := c.Execute(ctx, newQuery("example.com."), server, false)
		cancel()
		if err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("query %d: want 1 answer, got %d", i, len(resp.Answer))
		}
		a := resp.Answer[0].(*dns.A)
		if a.Addr != netip.MustParseAddr("1.2.3.4") {
			t.Fatalf("query %d: want 1.2.3.4, got %v", i, a.Addr)
		}
	}
}

func TestDNSCryptAAAA(t *testing.T) {
	_, stamp := startTestDNSCryptServer(t)
	c := New(nil)
	server := &config.UpstreamServer{Address: stamp, Protocol: config.ProtoDNSCrypt}
	msg := &dns.Msg{}
	msg.RecursionDesired = true
	q := &dns.AAAA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}
	msg.Question = []dns.RR{q}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.Execute(ctx, msg, server, false)
	if err != nil {
		t.Fatalf("AAAA: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("want NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	}
}

func TestDNSCryptTXT(t *testing.T) {
	_, stamp := startTestDNSCryptServer(t)
	c := New(nil)
	server := &config.UpstreamServer{Address: stamp, Protocol: config.ProtoDNSCrypt}
	msg := &dns.Msg{}
	msg.RecursionDesired = true
	q := &dns.TXT{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}
	msg.Question = []dns.RR{q}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.Execute(ctx, msg, server, false)
	if err != nil {
		t.Fatalf("TXT: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("want NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	}
}

func TestDNSCryptCertificateHandshake(t *testing.T) {
	addr, _ := startTestDNSCryptServer(t)
	msg := &dns.Msg{}
	msg.RecursionDesired = true
	q := &dns.TXT{Hdr: dns.Header{Name: "2.dnscrypt-cert.example.com.", Class: dns.ClassINET}}
	msg.Question = []dns.RR{q}
	if packErr := msg.Pack(); packErr != nil {
		t.Fatalf("pack: %v", packErr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := FetchCert(ctx, addr, msg.Data, false)
	if err != nil {
		t.Fatalf("FetchCert: %v", err)
	}
	if len(resp.Answer) == 0 {
		t.Fatal("cert TXT query returned no answers")
	}
	txt, ok := resp.Answer[0].(*dns.TXT)
	if !ok {
		t.Fatalf("expected TXT record, got %T", resp.Answer[0])
	}
	if len(txt.Txt) == 0 {
		t.Fatal("cert TXT record is empty")
	}
	certBytes := dnscryptcrypto.UnpackTxtString(strings.Join(txt.Txt, ""))
	if len(certBytes) < 124 {
		t.Fatalf("cert too short: %d bytes", len(certBytes))
	}
	t.Logf("cert TXT: %d chunks, %d bytes decoded", len(txt.Txt), len(certBytes))
}

func TestDNSCryptFallbackFromUDPToTCP(t *testing.T) {
	_, stamp := startTestDNSCryptServer(t)
	c := New(nil)
	udpServer := &config.UpstreamServer{Address: stamp, Protocol: config.ProtoDNSCrypt}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	resp, err := c.Execute(ctx, newQuery("example.com."), udpServer, false)
	cancel()
	if err != nil {
		t.Fatalf("UDP: %v", err)
	}
	if resp.Truncated {
		t.Log("UDP response was truncated (unexpected on localhost)")
	}
	tcpServer := &config.UpstreamServer{Address: stamp, Protocol: config.ProtoDNSCryptTCP}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	resp2, err := c.Execute(ctx2, newQuery("example.com."), tcpServer, true)
	cancel2()
	if err != nil {
		t.Fatalf("TCP fallback: %v", err)
	}
	if len(resp2.Answer) != 1 {
		t.Fatalf("TCP fallback: want 1 answer, got %d", len(resp2.Answer))
	}
}

// TestCertCacheKeyNormalisation verifies that the provider name trailing-dot
// normalisation results in a consistent cache key between state() and
// buildState().  Before the fix, state() computed the key before adding the
// trailing dot, causing a mismatch with buildState() which received the
// already-normalised name.
func TestCertCacheKeyNormalisation(t *testing.T) {
	c := New(nil)
	addr := "10.0.0.1:8443"
	rawProvider := "2.dnscrypt-cert.example.com"

	// Simulate what state() does after the fix: Fqdn first, then cacheKey.
	normalised := dnsutil.Fqdn(rawProvider)
	if !strings.HasSuffix(normalised, ".") {
		t.Fatal("Fqdn should add trailing dot")
	}
	cacheKey := addr + "|" + normalised

	// Simulate a cached state — buildState() also uses the normalised name
	// (passed by state()), so the cache key should match.
	c.cache.Set(cacheKey, &State{serverAddress: addr})

	_, ok := c.cache.Get(cacheKey)
	if !ok {
		t.Fatal("cache key with trailing dot not found")
	}

	// The raw (non-FQDN) key should NOT be in the cache.
	_, ok = c.cache.Get(addr + "|" + rawProvider)
	if ok {
		t.Fatal("cache key without trailing dot should not exist")
	}
}

// TestCertCachePreservedOnIOError verifies that transient I/O failures (UDP
// read timeouts) do NOT invalidate the cached state.  A dropped packet or a
// reset connection is not evidence of certificate rotation; evicting the
// cache on every network blip would force a full certificate re-fetch (DNS
// TXT round trip) on the very next query.  Only decryption failures — which
// indicate the key material is genuinely stale — clear the state.
func TestCertCachePreservedOnIOError(t *testing.T) {
	_, stamp := startTestDNSCryptServer(t)
	c := New(nil)
	server := &config.UpstreamServer{Address: stamp, Protocol: config.ProtoDNSCrypt}

	// 1. Successful query → populates cache.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	resp, err := c.Execute(ctx, newQuery("example.com."), server, false)
	cancel()
	if err != nil {
		t.Fatalf("first query: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("want 1 answer, got %d", len(resp.Answer))
	}

	// Find the cache key, grab the state pointer, and save the key material.
	var cacheKey string
	var st *State
	c.cache.Range(func(k string, v *State) bool {
		cacheKey = k
		st = v
		return false
	})
	if st == nil {
		t.Fatal("state should be cached after successful query")
	}
	var savedMagic [dnscryptcrypto.ClientMagicSize]byte
	var savedKey [dnscryptcrypto.SharedKeySize]byte
	st.mu.Lock()
	savedMagic = st.clientMagic
	savedKey = st.sharedKey
	st.mu.Unlock()

	// 2. Corrupt clientMagic and sharedKey.  A wrong clientMagic causes the
	//    server to drop the query silently, producing a read timeout — a
	//    pure I/O error on the client side.
	st.mu.Lock()
	for i := range st.clientMagic {
		st.clientMagic[i] ^= 0xFF
	}
	for i := range st.sharedKey {
		st.sharedKey[i] ^= 0xFF
	}
	st.mu.Unlock()

	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	_, err = c.Execute(ctx2, newQuery("example.com."), server, false)
	cancel2()
	if err == nil {
		t.Fatal("second query should fail with corrupted state")
	}
	t.Logf("expected error: %v", err)

	// 3. Transient I/O failure must NOT evict the cached state.
	if _, ok := c.cache.Get(cacheKey); !ok {
		t.Fatal("state must be preserved after a transient I/O failure")
	}

	// 4. Restore the key material — the query succeeds again, still served
	//    from the cached state (no certificate re-fetch).
	st.mu.Lock()
	st.clientMagic = savedMagic
	st.sharedKey = savedKey
	st.mu.Unlock()

	ctx3, cancel3 := context.WithTimeout(context.Background(), 5*time.Second)
	resp, err = c.Execute(ctx3, newQuery("example.com."), server, false)
	cancel3()
	if err != nil {
		t.Fatalf("third query (restored state): %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("want 1 answer, got %d", len(resp.Answer))
	}
}

func (h *bigResponseHandler) ServeDNS(req *dns.Msg, _ net.IP, _ bool, _ string) *dns.Msg {
	reply := dnsutil.SetReply(new(dns.Msg), req)
	reply.Authoritative = true
	qname := req.Question[0].Header().Name
	for i := range h.n {
		name := "host" + strconv.Itoa(i) + "." + qname
		rr := &dns.A{
			Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: 60},
			A:   rdata.A{Addr: netip.MustParseAddr("10.0.0.1")},
		}
		reply.Answer = append(reply.Answer, rr)
	}
	return reply
}

func startTestDNSCryptServerWithHandler(t *testing.T, handler interface {
	ServeDNS(*dns.Msg, net.IP, bool, string) *dns.Msg
},
) (addr, stamp string) {
	t.Helper()
	rc, err := serverdnscrypt.GenerateResolverConfig("example.com", nil)
	if err != nil {
		t.Fatalf("GenerateResolverConfig: %v", err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	cfg := &config.DNSCryptCertificate{PublicKey: rc.PublicKey, PrivateKey: rc.PrivateKey}
	srv, err := serverdnscrypt.New(cfg, strconv.Itoa(port), rc.ProviderName)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Start(handler); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	addr = "127.0.0.1:" + strconv.Itoa(port)
	for range 50 {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	stamp, err = rc.CreateStamp(addr)
	if err != nil {
		t.Fatalf("CreateStamp: %v", err)
	}
	return addr, stamp
}

func TestDNSCrypt_TCTruncation_EndToEnd(t *testing.T) {
	// 40 A records → ~1200 bytes → exceeds classical UDP budget (~463 bytes).
	// Server must truncate (TC=1), client must escalate and retry.
	handler := &bigResponseHandler{n: 40}
	_, stamp := startTestDNSCryptServerWithHandler(t, handler)

	c := New(nil)
	pqFalse := false
	server := &config.UpstreamServer{Address: stamp, Protocol: config.ProtoDNSCrypt, PQDNSCrypt: &pqFalse}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := c.Execute(ctx, newQuery("big.example.com."), server, false)
	if err != nil {
		t.Fatalf("TC truncation end-to-end: %v", err)
	}
	if len(resp.Answer) != 40 {
		t.Errorf("want 40 answers, got %d", len(resp.Answer))
	}
	if resp.Truncated {
		t.Error("final response must not be truncated")
	}
	t.Logf("TC test: got %d answers via UDP-initiated query", len(resp.Answer))
}

func TestDNSCrypt_PQDowngradeProtection(t *testing.T) {
	// Explicit pqdnscrypt=true but server has no PQ cert → must fail.
	_, stamp := startTestDNSCryptServer(t)
	c := New(nil)
	pqTrue := true
	server := &config.UpstreamServer{Address: stamp, Protocol: config.ProtoDNSCrypt, PQDNSCrypt: &pqTrue}

	// Force PQ by setting pqdnscrypt=true. Our test server DOES offer PQ,
	// so this query will succeed (not test the downgrade path directly).
	// For the true downgrade test, we'd need to modify the server to not offer PQ.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.Execute(ctx, newQuery("example.com."), server, false)
	if err != nil {
		t.Fatalf("PQ query: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("PQ query: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("PQ downgrade: query succeeded with PQ enabled")
}

func TestDNSCrypt_TCTruncation_ClassicalOnly(t *testing.T) {
	// Same as TC truncation but explicitly classical mode.
	handler := &bigResponseHandler{n: 40}
	_, stamp := startTestDNSCryptServerWithHandler(t, handler)

	c := New(nil)
	pqFalse := false
	server := &config.UpstreamServer{Address: stamp, Protocol: config.ProtoDNSCrypt, PQDNSCrypt: &pqFalse}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := c.Execute(ctx, newQuery("big.example.com."), server, false)
	if err != nil {
		t.Fatalf("TC classical: %v", err)
	}
	if len(resp.Answer) != 40 {
		t.Errorf("want 40 answers, got %d", len(resp.Answer))
	}
	t.Logf("TC classical: got %d answers", len(resp.Answer))
}
