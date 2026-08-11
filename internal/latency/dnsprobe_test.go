package latency

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func TestProbeDNSQuery_UDP(t *testing.T) {
	port, stop := startTestDNSServer(t, false)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := probeDNSQuery(ctx, net.ParseIP("127.0.0.1"), port, false); err != nil {
		t.Fatalf("UDP DNS probe should succeed: %v", err)
	}
}

func TestProbeDNSQuery_TCP(t *testing.T) {
	port, stop := startTestDNSServer(t, true)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := probeDNSQuery(ctx, net.ParseIP("127.0.0.1"), port, true); err != nil {
		t.Fatalf("TCP DNS probe should succeed: %v", err)
	}
}

func TestProbeDNSQuery_UDPIgnoresGarbage(t *testing.T) {
	// Reply with an unpackable datagram first, then a valid matching response.
	// The probe must skip the garbage and succeed on the real response.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = pc.Close() }()
	port := pc.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, probeUDPReadBufSize)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo([]byte{0xde, 0xad, 0xbe, 0xef}, addr)

		req := new(dns.Msg)
		req.Data = buf[:n]
		if err := req.Unpack(); err != nil {
			return
		}
		m := new(dns.Msg)
		dnsutil.SetReply(m, req)
		m.Rcode = dns.RcodeRefused
		if err := m.Pack(); err != nil {
			return
		}
		_, _ = pc.WriteTo(m.Data, addr)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := probeDNSQuery(ctx, net.ParseIP("127.0.0.1"), port, false); err != nil {
		t.Fatalf("UDP DNS probe should succeed despite garbage datagram: %v", err)
	}
}

func TestProbeDNSQuery_UDPIgnoresQueryEcho(t *testing.T) {
	// A QR=0 message with a matching ID is not a response (RFC 5452 §4.2) —
	// the probe must skip it and accept the real response that follows.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = pc.Close() }()
	port := pc.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, probeUDPReadBufSize)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(buf[:n], addr) // echo the query verbatim (QR=0, same ID)

		req := new(dns.Msg)
		req.Data = buf[:n]
		if err := req.Unpack(); err != nil {
			return
		}
		m := new(dns.Msg)
		dnsutil.SetReply(m, req)
		m.Rcode = dns.RcodeRefused
		if err := m.Pack(); err != nil {
			return
		}
		_, _ = pc.WriteTo(m.Data, addr)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := probeDNSQuery(ctx, net.ParseIP("127.0.0.1"), port, false); err != nil {
		t.Fatalf("UDP DNS probe should succeed despite QR=0 echo: %v", err)
	}
}

func TestProbeDNSQuery_NoServer(t *testing.T) {
	// Grab an ephemeral port, then close it — nothing listens there.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := probeDNSQuery(ctx, net.ParseIP("127.0.0.1"), port, false); err == nil {
		t.Fatal("DNS probe to a closed port should fail")
	}
}

func TestProbeDNSQuery_TimeoutNoLeak(t *testing.T) {
	// Silent UDP listener: accepts datagrams, never responds. Every probe
	// must hit the read deadline, close its socket via defer, and leave no
	// goroutines or heap objects behind.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = pc.Close() }()
	go func() {
		buf := make([]byte, probeUDPReadBufSize)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	port := pc.LocalAddr().(*net.UDPAddr).Port
	ip := net.ParseIP("127.0.0.1")

	runtime.GC()
	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)
	g0 := runtime.NumGoroutine()

	for range 100 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		err := probeDNSQuery(ctx, ip, port, false)
		cancel()
		if err == nil {
			t.Fatal("DNS probe to a silent server should time out")
		}
	}

	time.Sleep(200 * time.Millisecond) // stray cleanup settles
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	g1 := runtime.NumGoroutine()

	if g1 > g0+5 {
		t.Errorf("goroutine leak: %d → %d", g0, g1)
	}
	if m1.HeapObjects > m0.HeapObjects+5000 {
		t.Errorf("heap object leak: %d → %d", m0.HeapObjects, m1.HeapObjects)
	}
}

// startTestDNSServer starts an in-process DNS server answering REFUSED and
// returns its port plus a shutdown function.
func startTestDNSServer(t *testing.T, tcp bool) (port int, stop func()) {
	t.Helper()
	handler := dns.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		dnsutil.SetReply(m, req)
		m.Rcode = dns.RcodeRefused
		_, _ = m.WriteTo(w)
	})
	srv := &dns.Server{Handler: handler}
	if tcp {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen tcp: %v", err)
		}
		srv.Listener = ln
		port = ln.Addr().(*net.TCPAddr).Port
	} else {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		srv.PacketConn = pc
		port = pc.LocalAddr().(*net.UDPAddr).Port
	}
	go func() { _ = srv.ListenAndServe() }()
	return port, func() { srv.Shutdown(context.Background()) }
}
