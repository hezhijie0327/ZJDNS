package plain

import (
	"context"
	"net"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// TestExchangeOneShotUDP drives the per-query-dial fallback against a local
// responder that first sends a stale-ID datagram — the exchange must skip it
// and return the first ID-matching response.
func TestExchangeOneShotUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	responder := pc.(*net.UDPConn)
	defer func() { _ = responder.Close() }()

	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := responder.ReadFrom(buf)
			if err != nil {
				return
			}
			req := new(dns.Msg)
			req.Data = append(req.Data[:0], buf[:n]...)
			if err := req.Unpack(); err != nil {
				continue
			}
			reply := new(dns.Msg)
			dnsutil.SetReply(reply, req)
			if err := reply.Pack(); err != nil {
				continue
			}
			// First a stale reply with a mismatched ID, then the real one.
			stale := append([]byte(nil), reply.Data...)
			stale[0], stale[1] = 0xDE, 0xAD
			_, _ = responder.WriteTo(stale, addr)
			_, _ = responder.WriteTo(reply.Data, addr)
		}
	}()

	c := &Client{timeout: 2 * time.Second}
	msg := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	msg.ID = 0x4242
	resp, err := c.exchangeOneShotUDP(context.Background(), msg, responder.LocalAddr().String())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.ID != 0x4242 || !resp.Response {
		t.Fatalf("unexpected response: id=%x qr=%v", resp.ID, resp.Response)
	}
}
