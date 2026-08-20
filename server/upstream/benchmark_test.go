package upstream

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"zjdns/config"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func init() { log.Default.SetLevel(log.Error) }

// ---------------------------------------------------------------------------
// Fake UDP DNS server
// ---------------------------------------------------------------------------

// startFakeUDPServer starts a loopback UDP server that responds to DNS queries
// with a static NOERROR A record response.
func startFakeUDPServer(tb testing.TB) (addr string, shutdown func()) {
	tb.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		tb.Fatalf("fake UDP server: listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}

			req := new(dns.Msg)
			req.Data = buf[:n]
			if err := req.Unpack(); err != nil {
				continue
			}
			req.Data = nil

			resp := dnsutil.SetReply(new(dns.Msg), req)
			resp.Authoritative = true
			if len(req.Question) > 0 {
				qtype := dns.RRToType(req.Question[0])
				switch qtype {
				case dns.TypeA:
					resp.Answer = []dns.RR{&dns.A{
						Hdr:  dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 60},
						Addr: netip.MustParseAddr("192.0.2.1"),
					}}
				case dns.TypeAAAA:
					resp.Answer = []dns.RR{&dns.AAAA{
						Hdr:  dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 60},
						Addr: netip.MustParseAddr("::1"),
					}}
				}
			}

			if err := resp.Pack(); err != nil {
				continue
			}
			if _, err := conn.WriteToUDP(resp.Data, remote); err != nil {
				return
			}
		}
	}()

	shutdown = func() {
		_ = conn.Close()
		<-done
	}

	return conn.LocalAddr().String(), shutdown
}

// ---------------------------------------------------------------------------
// Client ExecuteQuery benchmarks
// ---------------------------------------------------------------------------

func BenchmarkClientExecuteQuery(b *testing.B) {
	b.Run("UDP", func(b *testing.B) {
		addr, shutdown := startFakeUDPServer(b)
		defer shutdown()

		client := New()
		defer client.Close()

		server := &config.UpstreamServer{
			Address:  addr,
			Protocol: config.ProtoUDP,
		}

		msg := new(dns.Msg)
		dnsutil.SetQuestion(msg, "example.com.", dns.TypeA)
		msg.RecursionDesired = true
		ctx := context.Background()

		b.ResetTimer()
		for b.Loop() {
			result := client.ExecuteQuery(ctx, msg, server)
			if result.Error != nil {
				b.Fatalf("ExecuteQuery UDP: %v", result.Error)
			}
			if result.Response == nil {
				b.Fatal("nil response")
			}
			if len(result.Response.Answer) == 0 {
				b.Fatal("no answer records")
			}
		}
	})

	b.Run("TCP", func(b *testing.B) {
		addr, shutdown := startFakeTCPServer(b)
		defer shutdown()

		client := New()
		defer client.Close()

		server := &config.UpstreamServer{
			Address:  addr,
			Protocol: config.ProtoTCP,
		}

		msg := new(dns.Msg)
		dnsutil.SetQuestion(msg, "example.com.", dns.TypeA)
		msg.RecursionDesired = true
		ctx := context.Background()

		b.ResetTimer()
		for b.Loop() {
			result := client.ExecuteQuery(ctx, msg, server)
			if result.Error != nil {
				b.Fatalf("ExecuteQuery TCP: %v", result.Error)
			}
			if result.Response == nil {
				b.Fatal("nil response")
			}
			if len(result.Response.Answer) == 0 {
				b.Fatal("no answer records")
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Fake TCP DNS server (reused from pool benchmark — local copy to avoid
// cross-package test dependency)
// ---------------------------------------------------------------------------

// startFakeTCPServer starts a loopback TCP DNS server.
func startFakeTCPServer(tb testing.TB) (addr string, shutdown func()) {
	tb.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("fake TCP server: listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go handleFakeTCPConn(conn)
		}
	}()

	shutdown = func() {
		_ = l.Close()
		<-done
	}

	return l.Addr().String(), shutdown
}

// handleFakeTCPConn handles a single RFC 1035 TCP DNS connection.
func handleFakeTCPConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	var lengthBuf [2]byte
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
					Hdr:  dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 60},
					Addr: netip.MustParseAddr("192.0.2.1"),
				}}
			case dns.TypeAAAA:
				resp.Answer = []dns.RR{&dns.AAAA{
					Hdr:  dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 60},
					Addr: netip.MustParseAddr("::1"),
				}}
			}
		}

		if err := resp.Pack(); err != nil {
			return
		}

		respLen := make([]byte, 2)
		binary.BigEndian.PutUint16(respLen, uint16(len(resp.Data))) //nolint:gosec // G115: DNS length prefix — max 65535 fits uint16
		if _, err := conn.Write(respLen); err != nil {
			return
		}
		if _, err := conn.Write(resp.Data); err != nil {
			return
		}
	}
}
