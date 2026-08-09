package dnsutil

import (
	"bytes"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	mdnsutil "codeberg.org/miekg/dns/dnsutil"
)

// recordingConn records each Write call's payload.  net.Pipe merges reads at
// arbitrary boundaries, so it cannot expose the segmentation structure —
// splitguard's invariants need the per-write slices.
type recordingConn struct {
	writes [][]byte
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, slices.Clone(p))
	return len(p), nil
}
func (c *recordingConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *recordingConn) Close() error                     { return nil }
func (c *recordingConn) LocalAddr() net.Addr              { return nil }
func (c *recordingConn) RemoteAddr() net.Addr             { return nil }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

// testGoogleQuery packs a realistic www.google.com A question (the same shape
// the splitguard POC segments).
func testGoogleQuery(t *testing.T) []byte {
	t.Helper()
	m := &dns.Msg{}
	mdnsutil.SetQuestion(m, "www.google.com.", dns.TypeA)
	if err := m.Pack(); err != nil {
		t.Fatalf("pack: %v", err)
	}
	return m.Data
}

// TestWriteTCPMsgSegmented_ReassemblyAndBounds verifies the splitguard
// invariants across random segment sizing: segments reassemble to the
// original message, the first write carries the 2-byte length prefix plus
// [1,segSize] payload bytes, and every later write is [1,segSize] bytes.
func TestWriteTCPMsgSegmented_ReassemblyAndBounds(t *testing.T) {
	msg := testGoogleQuery(t)
	const segSize = 4

	for range 20 {
		conn := &recordingConn{}
		n, err := WriteTCPMsgSegmented(conn, msg, segSize)
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		if n != len(msg) {
			t.Fatalf("total written = %d, want %d", n, len(msg))
		}
		if len(conn.writes) < 2 {
			t.Fatalf("expected multiple segments for segSize=%d, got %d write(s)", segSize, len(conn.writes))
		}

		// Reassembly invariant: concatenation equals the original message.
		var reassembled []byte
		for _, w := range conn.writes {
			reassembled = append(reassembled, w...)
		}
		if !bytes.Equal(reassembled, msg) {
			t.Fatal("segments must reassemble to the original message")
		}

		// Per-write size bounds and length-prefix placement.
		for i, w := range conn.writes {
			if i == 0 {
				if len(w) < 3 || len(w) > 2+segSize {
					t.Fatalf("first segment len=%d, want [3, %d]", len(w), 2+segSize)
				}
				if !bytes.Equal(w[:2], msg[:2]) {
					t.Fatal("first segment must start with the 2-byte length prefix")
				}
				continue
			}
			if len(w) < 1 || len(w) > segSize {
				t.Fatalf("segment %d len=%d, want [1, %d]", i, len(w), segSize)
			}
		}
	}
}

// TestWriteTCPMsgSegmented_NoCompleteLabel verifies the DPI-evasion property
// the splitguard POC demonstrates: with segSize smaller than the longest
// label, no single TCP write contains a complete domain label, so a DPI that
// inspects individual segments cannot match it.
func TestWriteTCPMsgSegmented_NoCompleteLabel(t *testing.T) {
	msg := testGoogleQuery(t)
	conn := &recordingConn{}
	if _, err := WriteTCPMsgSegmented(conn, msg, 4); err != nil {
		t.Fatalf("write: %v", err)
	}
	for i, w := range conn.writes {
		if bytes.Contains(w, []byte("google")) {
			t.Fatalf("segment %d contains the complete %q label: %v", i, "google", w)
		}
	}
}

func TestWriteTCPMsgSegmented_NoSegment(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	msg := []byte{0x00, 0x10, 0x01, 0x02, 0x03, 0x04}
	go func() {
		buf := make([]byte, 100)
		n, _ := server.Read(buf)
		if n != len(msg) {
			t.Errorf("expected %d bytes, got %d", len(msg), n)
		}
	}()

	n, err := WriteTCPMsgSegmented(client, msg, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(msg) {
		t.Errorf("expected %d bytes written, got %d", len(msg), n)
	}
}

func TestWriteTCPMsgSegmented_Segment(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	msg := []byte{0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD}
	go func() {
		buf := make([]byte, 100)
		var total int
		for total < len(msg) {
			n, err := server.Read(buf[total:])
			if err != nil {
				return
			}
			total += n
		}
		if total != len(msg) {
			t.Errorf("expected %d bytes total, got %d", len(msg), total)
		}
	}()

	n, err := WriteTCPMsgSegmented(client, msg, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(msg) {
		t.Errorf("expected %d bytes written, got %d", len(msg), n)
	}
}

func TestWriteTCPMsgSegmented_SegSizeLargerThanPayload(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	msg := []byte{0x00, 0x03, 0x01, 0x02, 0x03}
	go func() {
		buf := make([]byte, 100)
		n, _ := server.Read(buf)
		if n != len(msg) {
			t.Errorf("expected %d bytes, got %d", len(msg), n)
		}
	}()

	n, err := WriteTCPMsgSegmented(client, msg, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(msg) {
		t.Errorf("expected %d bytes written, got %d", len(msg), n)
	}
}
