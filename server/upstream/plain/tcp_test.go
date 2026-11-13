package plain

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// startTCPResponder starts a loopback TCP DNS server that echoes each framed
// query back as a reply after applying mutate.
func startTCPResponder(t *testing.T, mutate func(reply, req *dns.Msg)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				var lenBuf [2]byte
				r := bufio.NewReader(conn)
				if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
					return
				}
				line := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
				if _, err := io.ReadFull(r, line); err != nil {
					return
				}
				req := new(dns.Msg)
				req.Data = line
				if err := req.Unpack(); err != nil {
					return
				}
				reply := dnsutil.SetReply(new(dns.Msg), req)
				mutate(reply, req)
				if err := reply.Pack(); err != nil {
					return
				}
				frame := make([]byte, 2+len(reply.Data))
				binary.BigEndian.PutUint16(frame[:2], uint16(len(reply.Data))) //nolint:gosec // G115: DNS length prefix — reply ≤ 65535 by construction
				copy(frame[2:], reply.Data)
				_, _ = conn.Write(frame)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// TestExchangeSegmentedRejectsQuestionMismatch pins RFC 7766 §7 on the
// one-shot plain-TCP path: a reply with a matching ID but a mismatched
// question section must be rejected, like the pooled path already does.
func TestExchangeSegmentedRejectsQuestionMismatch(t *testing.T) {
	addr := startTCPResponder(t, func(reply, _ *dns.Msg) {
		// Same ID, different question — a forged or misrouted segment.
		reply.Question = dnsutil.SetQuestion(new(dns.Msg), "evil.example.", dns.TypeA).Question
	})

	c := &Client{timeout: 2 * time.Second}
	msg := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := c.exchangeSegmented(ctx, msg, addr, nil, 0)
	if !errors.Is(err, errTCPQuestionMismatch) {
		t.Fatalf("exchangeSegmented error = %v, want errTCPQuestionMismatch", err)
	}
}

// TestExchangeSegmentedAcceptsEchoedQuestion guards the other direction: a
// well-formed reply echoing the query's question must still pass the check.
func TestExchangeSegmentedAcceptsEchoedQuestion(t *testing.T) {
	addr := startTCPResponder(t, func(_, _ *dns.Msg) {})

	c := &Client{timeout: 2 * time.Second}
	msg := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := c.exchangeSegmented(ctx, msg, addr, nil, 0)
	if err != nil {
		t.Fatalf("exchangeSegmented: %v", err)
	}
	if resp.ID != msg.ID {
		t.Fatalf("response ID = %d, want %d", resp.ID, msg.ID)
	}
}
