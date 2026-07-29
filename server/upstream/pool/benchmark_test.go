package pool

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// ---------------------------------------------------------------------------
// Fake DNS connection (net.Pipe based — no real TCP, measures pool overhead)
// ---------------------------------------------------------------------------

// newFakeDNSConnPair creates a pair of connected net.Conn via net.Pipe.
// The "server" side runs a goroutine that responds to DNS queries with a
// static NOERROR A record.  The "client" side is returned for use with
// ConnPool. The caller MUST call closeFn when done to stop the server
// goroutine.
func newFakeDNSConnPair() (client net.Conn, closeFn func()) {
	server, client := net.Pipe()

	done := make(chan struct{})
	go handleFakePipeConn(server, done)

	return client, func() {
		_ = server.Close()
		_ = client.Close()
		<-done
	}
}

// handleFakePipeConn reads RFC 1035 TCP DNS frames from the pipe and writes
// back NOERROR responses.
func handleFakePipeConn(conn net.Conn, done chan struct{}) {
	defer close(done)
	defer func() { _ = conn.Close() }()

	var lengthBuf [zdnsutil.DNSFramePrefixLen]byte

	for {
		if _, err := io.ReadFull(conn, lengthBuf[:]); err != nil {
			return
		}
		msgLen := binary.BigEndian.Uint16(lengthBuf[:])
		if msgLen == 0 {
			return
		}
		body := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}

		req := new(dns.Msg)
		req.Data = body
		if err := req.Unpack(); err != nil {
			return
		}
		req.Data = nil

		resp := dnsutil.SetReply(new(dns.Msg), req)
		resp.Authoritative = true
		if len(req.Question) > 0 {
			qtype := dns.RRToType(req.Question[0])
			switch qtype {
			case dns.TypeA:
				resp.Answer = []dns.RR{&dns.A{
					Hdr: dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 60},
					A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
				}}
			case dns.TypeAAAA:
				resp.Answer = []dns.RR{&dns.AAAA{
					Hdr:  dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 60},
					AAAA: rdata.AAAA{Addr: netip.MustParseAddr("::1")},
				}}
			}
		}

		if err := resp.Pack(); err != nil {
			return
		}

		respLen := make([]byte, zdnsutil.DNSFramePrefixLen)
		binary.BigEndian.PutUint16(respLen, uint16(len(resp.Data))) //nolint:gosec // G115: protocol-bounded value
		if _, err := conn.Write(respLen); err != nil {
			return
		}
		if _, err := conn.Write(resp.Data); err != nil {
			return
		}
	}
}

// fakeDialer returns a dialFunc that creates a new fake DNS connection pair
// for every call. Used by benchmarks that need real dial semantics.
func fakeDialer() func(context.Context, string) (net.Conn, error) {
	return func(_ context.Context, _ string) (net.Conn, error) {
		client, _ := newFakeDNSConnPair()
		return client, nil
	}
}

// ---------------------------------------------------------------------------
// Pool Acquire benchmarks
// ---------------------------------------------------------------------------

func BenchmarkPoolAcquire(b *testing.B) {
	const key = "fake"

	dialFn := fakeDialer()

	b.Run("Warm", func(b *testing.B) {
		pool := NewConnPool(4, 16)
		defer pool.Shutdown()

		// Pre-warm.
		conn, err := pool.Acquire(context.Background(), key, key, dialFn)
		if err != nil {
			b.Fatalf("warm acquire: %v", err)
		}

		b.ResetTimer()
		for b.Loop() {
			c, err := pool.Acquire(context.Background(), key, key, dialFn)
			if err != nil {
				b.Fatalf("acquire: %v", err)
			}
			if c != conn {
				b.Fatal("expected same connection")
			}
		}
	})

	b.Run("Cold", func(b *testing.B) {
		for b.Loop() {
			pool := NewConnPool(4, 16)

			conn, err := pool.Acquire(context.Background(), key, key, dialFn)
			if err != nil {
				pool.Shutdown()
				b.Fatalf("acquire: %v", err)
			}
			_ = conn
			pool.Shutdown()
		}
	})
}

// ---------------------------------------------------------------------------
// Pool Exchange benchmarks
// ---------------------------------------------------------------------------

func BenchmarkPoolExchange(b *testing.B) {
	const key = "fake"

	pool := NewConnPool(4, 16)
	defer pool.Shutdown()

	conn, err := pool.Acquire(context.Background(), key, key, fakeDialer())
	if err != nil {
		b.Fatalf("acquire: %v", err)
	}

	msg := new(dns.Msg)
	dnsutil.SetQuestion(msg, "example.com.", dns.TypeA)
	msg.RecursionDesired = true

	b.ResetTimer()
	for b.Loop() {
		msg.ID = 0
		resp, err := conn.Exchange(context.Background(), msg)
		if err != nil {
			b.Fatalf("exchange: %v", err)
		}
		if resp == nil {
			b.Fatal("nil response")
		}
	}
}
