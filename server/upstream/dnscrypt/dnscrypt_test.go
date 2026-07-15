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
	serverdnscrypt "zjdns/server/protocol/dnscrypt"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

type testDNSHandler struct{}

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

func startTestDNSCryptServerWithVersion(t *testing.T, esVersionStr string) (addr, stamp string) {
	t.Helper()
	if esVersionStr == "" {
		esVersionStr = "xwingpq"
	}
	esVersion, _ := serverdnscrypt.ParseESVersion(esVersionStr)
	rc, err := serverdnscrypt.GenerateResolverConfig("example.com", nil, esVersion)
	if err != nil {
		t.Fatalf("GenerateResolverConfig: %v", err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	cfg := &config.DNSCryptCertificate{PublicKey: rc.PublicKey, PrivateKey: rc.PrivateKey, ESVersion: esVersionStr}
	srv, err := serverdnscrypt.New(cfg, strconv.Itoa(port), rc.ProviderName)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Start(&testDNSHandler{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	time.Sleep(100 * time.Millisecond)
	addr = "127.0.0.1:" + strconv.Itoa(port)
	stamp, err = rc.CreateStamp(addr)
	if err != nil {
		t.Fatalf("CreateStamp: %v", err)
	}
	return addr, stamp
}

func startTestDNSCryptServer(t *testing.T) (addr, stamp string) {
	return startTestDNSCryptServerWithVersion(t, "xwingpq")
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

func TestDNSCryptXChacha20(t *testing.T) {
	_, stamp := startTestDNSCryptServerWithVersion(t, "xchacha20poly1305")
	c := New(nil)
	server := &config.UpstreamServer{Address: stamp, Protocol: config.ProtoDNSCrypt}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.Execute(ctx, newQuery("example.com."), server, false)
	if err != nil {
		t.Fatalf("XChacha20 UDP: %v", err)
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
	if err := msg.Pack(); err != nil {
		t.Fatalf("pack: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := FetchCert(ctx, addr, msg.Data)
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
	certBytes := serverdnscrypt.UnpackTxtString(strings.Join(txt.Txt, ""))
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
