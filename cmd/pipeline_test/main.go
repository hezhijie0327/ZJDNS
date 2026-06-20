// Pipeline test tool — verifies RFC 7766 TCP/DoT pipelining and out-of-order responses.
//
// Usage:
//
//	go run ./cmd/pipeline_test/ [-tls] [-skip-verify] <server:port>
//
// Examples:
//
//	go run ./cmd/pipeline_test/ 127.0.0.1:53            # plain TCP
//	go run ./cmd/pipeline_test/ -tls -skip-verify 127.0.0.1:853  # DoT (self-signed cert)
//
// The test opens ONE connection, sends N pipelined queries back-to-back
// without waiting for responses, then reads responses matched by DNS message ID.
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func main() {
	useTLS := flag.Bool("tls", false, "Use DNS-over-TLS (DoT)")
	skipVerify := flag.Bool("skip-verify", false, "Skip TLS certificate verification")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: go run ./cmd/pipeline_test/ [-tls] [-skip-verify] <server:port>\n")
		os.Exit(1)
	}
	addr := flag.Arg(0)
	proto := "TCP"
	if *useTLS {
		proto = "DoT"
	}

	// ── Dial ──
	fmt.Printf("Dialing %s (%s) ...\n", addr, proto)
	var conn net.Conn
	var err error

	if *useTLS {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: *skipVerify,
			MinVersion:         tls.VersionTLS12,
		}
		dialer := tls.Dialer{Config: tlsCfg}
		conn, err = dialer.DialContext(context.Background(), "tcp", addr)
	} else {
		conn, err = net.DialTimeout("tcp", addr, 3*time.Second)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: dial: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()
	fmt.Printf("Connected to %s\n\n", addr)

	// ── Prepare queries ──
	type query struct {
		name string
		typ  uint16
	}
	queries := []query{
		{"example.com.", dns.TypeA},
		{"google.com.", dns.TypeAAAA},
		{"github.com.", dns.TypeA},
		{"cloudflare.com.", dns.TypeA},
		{"ietf.org.", dns.TypeAAAA},
		{"reddit.com.", dns.TypeA},
		{"stackoverflow.com.", dns.TypeA},
		{"anthropic.com.", dns.TypeA},
		{"openai.com.", dns.TypeAAAA},
		{"arpa.", dns.TypePTR},
	}

	type pending struct {
		name string
		seq  int // send order: 0, 1, 2, ...
		sent time.Time
	}
	pendingMap := make(map[uint16]*pending)
	var mu sync.Mutex

	// ── Pipelined send: all queries, no waiting ──
	fmt.Printf("=== Pipelined send: %d %s queries on ONE connection ===\n", len(queries), proto)
	var nextID uint16
	for i, q := range queries {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(q.name), q.typ)
		msg.RecursionDesired = true
		// Assign sequential IDs so we own the ordering.
		nextID++
		msg.Id = nextID

		wire, err := msg.Pack()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: pack: %v\n", err)
			os.Exit(1)
		}
		buf := make([]byte, 2+len(wire))
		binary.BigEndian.PutUint16(buf[:2], uint16(len(wire)))
		copy(buf[2:], wire)

		if _, err := conn.Write(buf); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: write: %v\n", err)
			os.Exit(1)
		}
		mu.Lock()
		pendingMap[msg.Id] = &pending{name: q.name, seq: i, sent: time.Now()}
		mu.Unlock()
		fmt.Printf("  → #%-5d %-25s %s\n", msg.Id, q.name, dns.TypeToString[q.typ])
	}
	fmt.Printf("  Sent %d queries. Now reading responses...\n\n", len(queries))

	// ── Read responses (potentially out of order) ──
	fmt.Println("=== Responses ===")
	received := make([]uint16, 0, len(queries))
	responseTimes := make([]time.Duration, 0, len(queries))
	readTimeout := 5 * time.Second

	for i := 0; i < len(queries); i++ {
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))

		var msgLen uint16
		if err := binary.Read(conn, binary.BigEndian, &msgLen); err != nil {
			if err == io.EOF {
				fmt.Printf("  ⚠️  Server closed connection after %d/%d responses — no RFC 7766 reuse\n", i, len(queries))
			} else {
				fmt.Fprintf(os.Stderr, "ERROR: read length: %v\n", err)
			}
			break
		}
		if msgLen == 0 {
			fmt.Fprintf(os.Stderr, "ERROR: zero-length message\n")
			break
		}
		body := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: read body: %v\n", err)
			break
		}
		resp := new(dns.Msg)
		if err := resp.Unpack(body); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: unpack: %v\n", err)
			continue
		}

		mu.Lock()
		p, ok := pendingMap[resp.Id]
		mu.Unlock()

		if ok {
			elapsed := time.Since(p.sent)
			responseTimes = append(responseTimes, elapsed)
			fmt.Printf("  ← #%-5d %-25s rcode=%-10s rtt=%v\n",
				resp.Id, p.name, dns.RcodeToString[resp.Rcode], elapsed.Round(time.Microsecond))
		} else {
			fmt.Printf("  ← #%-5d (unknown)              rcode=%s\n",
				resp.Id, dns.RcodeToString[resp.Rcode])
		}
		received = append(received, resp.Id)
	}

	// ── Analysis ──
	fmt.Println()
	fmt.Println("=== Results ===")
	fmt.Printf("  Protocol: %s\n", proto)
	fmt.Printf("  Sent:     %d\n", len(queries))
	fmt.Printf("  Received: %d\n", len(received))

	if len(received) == 0 {
		fmt.Println("  ❌ No responses received")
		return
	}
	if len(received) < len(queries) {
		fmt.Println("  ❌ Server closed early — no pipelining support")
		fmt.Println("  (ZJDNS fallback: re-dial fresh connection for remaining queries)")
		return
	}

	// Check if responses arrived out of send order by comparing seq numbers.
	inOrder := true
	lastSeq := -1
	for _, id := range received {
		mu.Lock()
		p := pendingMap[id]
		mu.Unlock()
		if p == nil {
			continue
		}
		if p.seq < lastSeq {
			inOrder = false
			break
		}
		lastSeq = p.seq
	}
	if !inOrder {
		fmt.Println("  ✅ Responses OUT OF ORDER — pipelining confirmed!")
	} else {
		fmt.Println("  ℹ️  Responses in send order (server may still process concurrently)")
	}

	if len(responseTimes) > 1 {
		var minT, maxT, total time.Duration
		minT = responseTimes[0]
		for _, t := range responseTimes {
			total += t
			if t < minT {
				minT = t
			}
			if t > maxT {
				maxT = t
			}
		}
		avg := total / time.Duration(len(responseTimes))
		fmt.Printf("  Response times: min=%v max=%v avg=%v\n",
			minT.Round(time.Millisecond), maxT.Round(time.Millisecond), avg.Round(time.Millisecond))
		if maxT-minT > avg/2 {
			fmt.Println("  ✅ Large variance → concurrent server processing")
		}
	}

	fmt.Println("\nTest complete.")
}
