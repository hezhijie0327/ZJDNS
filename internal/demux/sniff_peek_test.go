//go:build linux || freebsd

package demux

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// runtimeGoroutineCPUTime samples the process user CPU time — the stalled
// sniff runs in this process, so a before/after delta bounds what the sniff
// loop burned (test-harness noise is microseconds against a hot spin's
// hundreds of milliseconds).
func runtimeGoroutineCPUTime(t *testing.T) time.Duration {
	t.Helper()
	var ru unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &ru); err != nil {
		t.Fatalf("getrusage: %v", err)
	}
	return time.Duration(ru.Utime.Sec)*time.Second + time.Duration(ru.Utime.Usec)*time.Microsecond
}

// TestDetectTCPProtocol_PeekKeepsRawConn is the KTLS contract: on the
// offload platforms the sniff must not consume bytes and must hand back the
// original *net.TCPConn — eTLS skips kernel TLS silently otherwise.
func TestDetectTCPProtocol_PeekKeepsRawConn(t *testing.T) {
	header := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 'A', 'B', 'C', 'D', 'E'}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()
	if _, err := client.Write(header); err != nil {
		t.Fatalf("write: %v", err)
	}

	server, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer func() { _ = server.Close() }()

	proto, detected, err := DetectTCPProtocol(server)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if proto != ProtoTLS {
		t.Fatalf("proto = %q, want %q", proto, ProtoTLS)
	}
	if detected != server {
		t.Fatalf("detected conn is a wrapper (%T) — sniff consumed bytes, KTLS contract broken", detected)
	}
	if _, ok := detected.(*net.TCPConn); !ok {
		t.Fatalf("detected conn type %T, want *net.TCPConn", detected)
	}

	// The header must still be readable from the conn (peek did not consume).
	buf := make([]byte, len(header))
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatalf("read after sniff: %v", err)
	}
	for i, b := range buf {
		if b != header[i] {
			t.Fatalf("byte %d: got 0x%02x, want 0x%02x — sniff leaked consumption", i, b, header[i])
		}
	}
}

// TestDetectTCPProtocol_PeekPartialHeader verifies the peek loop survives a
// TCP segment boundary inside the 5-byte record header.
func TestDetectTCPProtocol_PeekPartialHeader(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	server, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer func() { _ = server.Close() }()

	result := make(chan error, 1)
	go func() {
		proto, _, err := DetectTCPProtocol(server)
		if err == nil && proto != ProtoTLCP {
			err = &net.AddrError{Err: "wrong protocol", Addr: proto}
		}
		result <- err
	}()

	// Trickle: 2 bytes, then 2, then the last one.
	if _, err := client.Write([]byte{0x16, 0x01}); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := client.Write([]byte{0x01, 0x00}); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := client.Write([]byte{0x03}); err != nil {
		t.Fatalf("write 3: %v", err)
	}

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("detect over segmented header: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("detect did not complete for a segmented header")
	}
}

// TestDetectTCPProtocol_PeekPeerClosed verifies a client that connects and
// closes without sending anything errors out promptly (no 10s hang).
func TestDetectTCPProtocol_PeekPeerClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	server, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	_ = client.Close() // EOF before any byte

	done := make(chan error, 1)
	go func() {
		_, _, err := DetectTCPProtocol(server)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error for peer-closed conn, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("detect hung on peer-closed conn")
	}
	_ = server.Close()
}

// TestDetectTCPProtocol_PeekStalledPartialHeader pins the zero-progress
// backoff: a peer that sends a partial header and stalls must not spin the
// peek loop hot (level-triggered POLLIN over unconsumed PEEK bytes).  The
// probe measures CPU time burned by the sniff goroutine over a 400ms stall —
// a hot loop consumes hundreds of milliseconds; the backoff keeps it in the
// single-digit range.
func TestDetectTCPProtocol_PeekStalledPartialHeader(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()
	server, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	// Send 2 of the 5 header bytes, then stall: the sniff sees partial data
	// whose level-triggered POLLIN would wake poll immediately forever.
	if _, err := client.Write([]byte{0x16, 0x03}); err != nil {
		t.Fatalf("write partial header: %v", err)
	}

	before := runtimeGoroutineCPUTime(t)
	done := make(chan error, 1)
	go func() {
		_, _, err := DetectTCPProtocol(server)
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("detect returned early for a stalled header: %v", err)
	case <-time.After(400 * time.Millisecond):
	}
	// Close the client first: its RST unblocks recvfrom with ECONNRESET
	// (immediate fallback), while closing the server side alone would block
	// in close(2) until the sniff's fd reference is released — the full
	// sniff budget.
	_ = client.Close()
	_ = server.Close()
	<-done

	burned := runtimeGoroutineCPUTime(t) - before
	// A hot poll loop burns 100% of one core for its window (>300ms here).
	// The backoff budget is ~15 poll rounds ≈ a few hundred microseconds of
	// CPU; allow a generous 50ms headroom for scheduler noise.
	if burned > 50*time.Millisecond {
		t.Fatalf("stalled-header sniff burned %v CPU over 400ms — zero-progress backoff not effective", burned)
	}
}

// TestDetectTCPProtocol_PeekPartialThenClose verifies the POLLRDHUP path: a
// peer that sends a partial header and half-closes reports
// ErrUnexpectedEOF promptly instead of burning the full sniff budget.
func TestDetectTCPProtocol_PeekPartialThenClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	server, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, err := client.Write([]byte{0x16, 0x03, 0x01}); err != nil {
		t.Fatalf("write partial header: %v", err)
	}
	_ = client.Close()

	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, _, err := DetectTCPProtocol(server)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("detect error = %v, want io.ErrUnexpectedEOF", err)
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatalf("partial+close took %v — POLLRDHUP did not shortcut the wait", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("detect hung on partial header + close")
	}
	_ = server.Close()
}
