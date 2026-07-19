package tcp

import (
	"bytes"
	"net"
	"testing"
	"zjdns/server/protocol/shared"
)

// mockConn implements net.Conn with a pre-set byte stream for testing.
type mockConn struct {
	net.Conn
	rd *bytes.Reader
}

func (m *mockConn) Read(b []byte) (int, error) { return m.rd.Read(b) }
func (m *mockConn) Close() error               { return nil }

func TestDetectConn_TLSHeader(t *testing.T) {
	// TLS 1.3 ClientHello: ContentType=22(0x16), Version=0x0303, Length=0x0100
	tlsHeader := []byte{0x16, 0x03, 0x03, 0x01, 0x00}
	mc := &mockConn{rd: bytes.NewReader(tlsHeader)}

	dc := &detectConn{Conn: mc}
	if err := dc.readHeader(); err != nil {
		t.Fatalf("readHeader failed: %v", err)
	}
	if dc.major != uint8(shared.VersionTLS) {
		t.Errorf("expected major=0x03 (TLS), got 0x%02x", dc.major)
	}
	if dc.minor != 0x03 {
		t.Errorf("expected minor=0x03, got 0x%02x", dc.minor)
	}
}

func TestDetectConn_TLCPHeader(t *testing.T) {
	// TLCP ClientHello: ContentType=22(0x16), Version=0x0101, Length=0x0100
	tlcpHeader := []byte{0x16, 0x01, 0x01, 0x01, 0x00}
	mc := &mockConn{rd: bytes.NewReader(tlcpHeader)}

	dc := &detectConn{Conn: mc}
	if err := dc.readHeader(); err != nil {
		t.Fatalf("readHeader failed: %v", err)
	}
	if dc.major != uint8(shared.VersionTLCP) {
		t.Errorf("expected major=0x01 (TLCP), got 0x%02x", dc.major)
	}
}

func TestDetectConn_ReplayHeader(t *testing.T) {
	// Verify that after readHeader, Read() replays the peeked bytes correctly.
	header := []byte{0x16, 0x03, 0x01, 0x00, 0x10}
	body := []byte("hello world")
	full := append(append([]byte{}, header...), body...)
	mc := &mockConn{rd: bytes.NewReader(full)}

	dc := &detectConn{Conn: mc}
	if err := dc.readHeader(); err != nil {
		t.Fatalf("readHeader failed: %v", err)
	}

	// Read should return header + body.
	buf := make([]byte, len(full))
	n, err := dc.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != len(full) {
		t.Errorf("expected %d bytes, got %d", len(full), n)
	}
	if !bytes.Equal(buf, full) {
		t.Errorf("replayed data mismatch")
	}
}

func TestDetectConn_ReplayPartial(t *testing.T) {
	// Verify partial reads work — caller's buffer smaller than header.
	header := []byte{0x16, 0x03, 0x01, 0x00, 0x10}
	body := []byte("hello")
	full := append(append([]byte{}, header...), body...)
	mc := &mockConn{rd: bytes.NewReader(full)}

	dc := &detectConn{Conn: mc}
	if err := dc.readHeader(); err != nil {
		t.Fatalf("readHeader failed: %v", err)
	}

	// Read 3 bytes at a time.
	buf := make([]byte, 3)
	n, err := dc.Read(buf)
	if err != nil {
		t.Fatalf("first Read failed: %v", err)
	}
	if n != 3 || !bytes.Equal(buf, header[:3]) {
		t.Errorf("first partial read: got %d bytes: %v", n, buf)
	}

	// Read remaining header + body.
	rest := make([]byte, len(full)-3)
	n, err = dc.Read(rest)
	if err != nil {
		t.Fatalf("second Read failed: %v", err)
	}
	expected := make([]byte, len(header[3:])+len(body))
	copy(expected, header[3:])
	copy(expected[len(header[3:]):], body)
	if n != len(expected) || !bytes.Equal(rest[:n], expected) {
		t.Errorf("second read: got %d bytes, expected %d", n, len(expected))
	}
}

func TestDetectConn_UnknownMajor(t *testing.T) {
	// An unknown major version (e.g. 0xFF) should not crash.
	unknownHeader := []byte{0x16, 0xFF, 0x01, 0x01, 0x00}
	mc := &mockConn{rd: bytes.NewReader(unknownHeader)}

	dc := &detectConn{Conn: mc}
	if err := dc.readHeader(); err != nil {
		t.Fatalf("readHeader failed: %v", err)
	}
	if dc.major != 0xFF {
		t.Errorf("expected major=0xFF, got 0x%02x", dc.major)
	}
}
