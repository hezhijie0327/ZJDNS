package plain

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

type idMismatchError struct{ want, got uint16 }

type nopGroup struct{}

func (e idMismatchError) Error() string { return "id mismatch" }

func (nopGroup) Go(f func() error) { go func() { _ = f() }() }

// replyHandler answers every accepted query with a single A record.
func replyHandler() dns.Handler {
	return dns.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr:  dns.Header{Name: "example.com.", TTL: 60, Class: dns.ClassINET},
			Addr: netip.MustParseAddr("1.2.3.4"),
		})
		_, _ = resp.WriteTo(w)
	})
}

// startTestListener builds a single-socket udpListener on an ephemeral
// loopback port and returns it with a connected client socket.
func startTestListener(t *testing.T, handler dns.Handler) (*udpListener, *net.UDPConn) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	lc := net.ListenConfig{}
	pc, err := lc.ListenPacket(ctx, "udp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatalf("listen: %v", err)
	}
	conn := pc.(*net.UDPConn)
	client, err := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		cancel()
		t.Fatalf("dial: %v", err)
	}
	l := &udpListener{
		handler: handler,
		ctx:     ctx,
		work:    make(chan udpDatagram, 64),
		conns:   []*net.UDPConn{conn},
	}
	l.start(nopGroup{})
	t.Cleanup(func() {
		cancel()
		l.stop()
		_ = client.Close()
	})
	return l, client
}

// query builds the wire for a standard A query with a fixed ID.
func query(id uint16) []byte {
	req := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	req.ID = id
	if err := req.Pack(); err != nil {
		panic(err)
	}
	return req.Data
}

// exchange sends wire and reads one reply (ok=false on read timeout).
func exchange(t *testing.T, client *net.UDPConn, wire []byte, wantReply bool) (*dns.Msg, bool) {
	t.Helper()
	if _, err := client.Write(wire); err != nil {
		t.Fatalf("send: %v", err)
	}
	buf := make([]byte, 1500)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := client.Read(buf)
	if err != nil {
		if wantReply {
			t.Fatalf("read reply: %v", err)
		}
		return nil, false
	}
	reply := new(dns.Msg)
	reply.Data = buf[:n]
	if err := reply.Unpack(); err != nil {
		t.Fatalf("unpack reply: %v", err)
	}
	return reply, true
}

func TestUDPServesValidQuery(t *testing.T) {
	_, client := startTestListener(t, replyHandler())
	reply, ok := exchange(t, client, query(0x1234), true)
	if !ok {
		t.Fatal("no reply")
	}
	if reply.ID != 0x1234 || len(reply.Answer) != 1 || !reply.Response {
		t.Fatalf("unexpected reply: id=%x answers=%d qr=%v", reply.ID, len(reply.Answer), reply.Response)
	}
}

func TestUDPAcceptSemantics(t *testing.T) {
	_, client := startTestListener(t, replyHandler())
	buf := make([]byte, 1500)

	// QR=1 — silently ignored.
	qr := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	qr.ID = 0x21
	qr.Response = true
	if _, ok := exchange(t, client, qr.Data, false); ok {
		t.Fatal("QR=1 must not be answered")
	}

	// QD=0 — FORMERR with the same ID.
	noQ := new(dns.Msg)
	noQ.ID = 0x22
	if err := noQ.Pack(); err != nil {
		t.Fatalf("pack: %v", err)
	}
	reply, ok := exchange(t, client, noQ.Data, true)
	if reply.ID != 0x22 || reply.Rcode != dns.RcodeFormatError {
		t.Fatalf("want FORMERR for QD=0, got id=%x rcode=%d (ok=%v)", reply.ID, reply.Rcode, ok)
	}

	// Unassigned opcode — NOTIMP.
	badOp := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	badOp.ID = 0x23
	badOp.Opcode = 15
	if err := badOp.Pack(); err != nil {
		t.Fatalf("pack: %v", err)
	}
	reply, _ = exchange(t, client, badOp.Data, true)
	if reply.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("want NOTIMP for opcode 15, got %d", reply.Rcode)
	}

	// RRSIG query — REFUSED.
	rrsig := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeRRSIG)
	rrsig.ID = 0x24
	if err := rrsig.Pack(); err != nil {
		t.Fatalf("pack: %v", err)
	}
	reply, _ = exchange(t, client, rrsig.Data, true)
	if reply.Rcode != dns.RcodeRefused {
		t.Fatalf("want REFUSED for RRSIG query, got %d", reply.Rcode)
	}

	// Truncated garbage — silently dropped.
	if _, err := client.Write([]byte{0x25, 0x00, 0x01}); err != nil {
		t.Fatalf("send: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := client.Read(buf); err == nil {
		t.Fatalf("garbage must not be answered, got %d bytes", n)
	}
}

func TestUDPWireRecyclesCleanly(t *testing.T) {
	_, client := startTestListener(t, replyHandler())
	for i := range 64 {
		reply, ok := exchange(t, client, query(uint16(i+1)), true)
		if !ok {
			t.Fatalf("query %d: no reply", i)
		}
		if reply.ID != uint16(i+1) || len(reply.Answer) != 1 {
			t.Fatalf("query %d: corrupted reply id=%x answers=%d", i, reply.ID, len(reply.Answer))
		}
	}
}

func TestUDPConcurrentQueries(t *testing.T) {
	l, _ := startTestListener(t, replyHandler())
	addr := l.conns[0].LocalAddr().(*net.UDPAddr)
	done := make(chan error, 16)
	for g := range 16 {
		go func(id uint16) {
			client, err := net.DialUDP("udp", nil, addr)
			if err != nil {
				done <- err
				return
			}
			defer func() { _ = client.Close() }()
			for i := range 8 {
				req := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
				req.ID = id*100 + uint16(i)
				if err := req.Pack(); err != nil {
					done <- err
					return
				}
				if _, err := client.Write(req.Data); err != nil {
					done <- err
					return
				}
				buf := make([]byte, 1500)
				_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, err := client.Read(buf)
				if err != nil {
					done <- err
					return
				}
				reply := new(dns.Msg)
				reply.Data = buf[:n]
				if err := reply.Unpack(); err != nil {
					done <- err
					return
				}
				if reply.ID != req.ID {
					done <- idMismatchError{want: req.ID, got: reply.ID}
					return
				}
			}
			done <- nil
		}(uint16(g))
	}
	for range 16 {
		if err := <-done; err != nil {
			t.Fatalf("client: %v", err)
		}
	}
}
