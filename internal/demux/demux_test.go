package demux

import (
	"io"
	"net"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// mockConn — minimal net.Conn for testing
// ---------------------------------------------------------------------------

type mockConn struct {
	data   []byte
	offset int
}

func (c *mockConn) Read(b []byte) (int, error) {
	if c.offset >= len(c.data) {
		return 0, io.EOF
	}
	n := copy(b, c.data[c.offset:])
	c.offset += n
	return n, nil
}

func (c *mockConn) Write(b []byte) (int, error) {
	c.data = append(c.data, b...)
	return len(b), nil
}

func (c *mockConn) Close() error                       { return nil }
func (c *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *mockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *mockConn) SetDeadline(_ time.Time) error      { return nil }
func (c *mockConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *mockConn) SetWriteDeadline(_ time.Time) error { return nil }

// ---------------------------------------------------------------------------
// DetectTCPProtocol
// ---------------------------------------------------------------------------

func TestDetectTCPProtocol_TLS(t *testing.T) {
	// TLS ClientHello record: type=0x16, version=0x0301, length=...
	header := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 'A', 'B', 'C', 'D', 'E'}
	conn := &mockConn{data: header}

	proto, detected, err := DetectTCPProtocol(conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proto != ProtoTLS {
		t.Errorf("got protocol %q, want %q", proto, ProtoTLS)
	}

	// Verify the buffered header is replayed.
	buf := make([]byte, len(header))
	n, err := io.ReadFull(detected, buf)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if n != len(header) {
		t.Errorf("read %d bytes, want %d", n, len(header))
	}
	for i, b := range buf {
		if b != header[i] {
			t.Errorf("byte %d: got 0x%02x, want 0x%02x", i, b, header[i])
		}
	}
}

func TestDetectTCPProtocol_TLCP(t *testing.T) {
	// TLCP record: type=0x16, version=0x0101, length=...
	header := []byte{0x16, 0x01, 0x01, 0x00, 0x03, 'X', 'Y', 'Z'}
	conn := &mockConn{data: header}

	proto, detected, err := DetectTCPProtocol(conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proto != ProtoTLCP {
		t.Errorf("got protocol %q, want %q", proto, ProtoTLCP)
	}

	buf := make([]byte, len(header))
	n, _ := io.ReadFull(detected, buf)
	if n != len(header) {
		t.Errorf("read %d bytes, want %d", n, len(header))
	}
}

func TestDetectTCPProtocol_Unknown(t *testing.T) {
	// Random bytes — not TLS or TLCP.
	header := []byte{0x16, 0x05, 0x00, 0x00, 0x01, 'Q'}
	conn := &mockConn{data: header}

	proto, _, err := DetectTCPProtocol(conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proto != "" {
		t.Errorf("got protocol %q, want empty", proto)
	}
}

func TestDetectTCPProtocol_ShortRead(t *testing.T) {
	// Less than 5 bytes — should fail.
	conn := &mockConn{data: []byte{0x16, 0x03}}

	_, _, err := DetectTCPProtocol(conn)
	if err == nil {
		t.Error("expected error for short read, got nil")
	}
}

// ---------------------------------------------------------------------------
// DetectUDPProtocol
// ---------------------------------------------------------------------------

func TestDetectUDPProtocol(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			// RFC 9000 §14: a client's first QUIC packet (Initial) is always
			// >= 1200 bytes — the size floor is part of the classification.
			name: "QUIC long header Initial",
			data: append([]byte{0xC0, 0x00, 0x00, 0x00, 0x01}, make([]byte, 1200)...),
			want: ProtoQUIC,
		},
		{
			name: "QUIC long header max",
			data: append([]byte{0xFF, 0x00, 0x00}, make([]byte, 1200)...),
			want: ProtoQUIC,
		},
		{
			// A short first byte >= 0xC0 is a plain DNS query's random ID
			// high byte far more often than QUIC — must NOT classify as QUIC.
			name: "short 0xC0-prefix datagram (plain DNS collision)",
			data: []byte{0xC0, 0x00, 0x00, 0x00, 0x01},
			want: "",
		},
		{
			name: "DTLS 1.2 handshake",
			data: []byte{0x16, 0xFE, 0xFD, 0x00, 0x00},
			want: ProtoDTLS,
		},
		{
			name: "DTLS 1.0 handshake",
			data: []byte{0x16, 0xFE, 0xFF, 0x00, 0x00},
			want: ProtoDTLS,
		},
		{
			name: "DTLCP handshake",
			data: []byte{0x16, 0x01, 0x01, 0x00, 0x00},
			want: ProtoDTLCP,
		},
		{
			name: "DTLCP change_cipher_spec",
			data: []byte{0x14, 0x01, 0x01, 0x00, 0x00},
			want: ProtoDTLCP,
		},
		{
			name: "DTLS alert",
			data: []byte{0x15, 0xFE, 0xFF, 0x00, 0x00},
			want: ProtoDTLS,
		},
		{
			name: "unknown content type",
			data: []byte{0x30, 0x03, 0x01, 0x00, 0x00},
			want: "",
		},
		{
			name: "too short",
			data: []byte{0x16, 0x03},
			want: "",
		},
		{
			name: "empty",
			data: []byte{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectUDPProtocol(tt.data)
			if got != tt.want {
				t.Errorf("DetectUDPProtocol(%v) = %q, want %q", tt.data, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// bufferedConn
// ---------------------------------------------------------------------------

func TestBufferedConn_ReplaysAndReadsMore(t *testing.T) {
	// Simulate DetectTCPProtocol: the underlying conn has already had its
	// first 5 bytes consumed (offset=5), and the bufferedConn holds them.
	underlying := &mockConn{data: []byte{0x16, 0x03, 0x01, 0x00, 0x05, 'A', 'B', 'C', 'D', 'E'}, offset: 5}
	bc := &bufferedConn{Conn: underlying, buf: []byte{0x16, 0x03, 0x01, 0x00, 0x05}}

	// Read exactly the buffer size.
	buf := make([]byte, 5)
	n, err := io.ReadFull(bc, buf)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if n != 5 {
		t.Errorf("read %d bytes, want 5", n)
	}

	// Next read should come from the underlying connection.
	buf2 := make([]byte, 5)
	n2, err := io.ReadFull(bc, buf2)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if n2 != 5 {
		t.Errorf("read %d bytes, want 5", n2)
	}
	want := []byte{'A', 'B', 'C', 'D', 'E'}
	for i, b := range buf2 {
		if b != want[i] {
			t.Errorf("byte %d: got %c, want %c", i, b, want[i])
		}
	}
}

func TestBufferedConn_SmallRead(t *testing.T) {
	bc := &bufferedConn{
		Conn: &mockConn{data: []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x42}, offset: 5},
		buf:  []byte{0x16, 0x03, 0x01, 0x00, 0x05},
	}

	// Read 2 bytes — should come entirely from the buffer.
	buf := make([]byte, 2)
	n, err := bc.Read(buf)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if n != 2 {
		t.Errorf("read %d bytes, want 2", n)
	}
	if buf[0] != 0x16 || buf[1] != 0x03 {
		t.Errorf("got %v, want [0x16 0x03]", buf)
	}
}

// ---------------------------------------------------------------------------
// TCPDemuxListener — end-to-end
// ---------------------------------------------------------------------------

func TestTCPDemuxListener(t *testing.T) {
	// Create a TCP listener on a random port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var tlsConns, tlcpConns int
	d := NewTCPDemux(TCPConfig{
		Inner: ln,
		Routes: map[string]func(net.Conn) net.Conn{
			ProtoTLS: func(c net.Conn) net.Conn {
				tlsConns++
				return c
			},
			ProtoTLCP: func(c net.Conn) net.Conn {
				tlcpConns++
				return c
			},
		},
	})
	defer func() { _ = d.Close() }()

	tlsListener := d.Listener(ProtoTLS)
	tlcpListener := d.Listener(ProtoTLCP)

	// Connect a TLS client.
	tlsClient, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Send a TLS record header.
	_, _ = tlsClient.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x00})

	// Accept the TLS connection.
	tlsAccepted := make(chan net.Conn, 1)
	go func() {
		c, err := tlsListener.Accept()
		if err == nil {
			tlsAccepted <- c
		}
	}()

	select {
	case c := <-tlsAccepted:
		_ = c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for TLS accept")
	}

	// Connect a TLCP client.
	tlcpClient, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _ = tlcpClient.Write([]byte{0x16, 0x01, 0x01, 0x00, 0x00})

	tlcpAccepted := make(chan net.Conn, 1)
	go func() {
		c, err := tlcpListener.Accept()
		if err == nil {
			tlcpAccepted <- c
		}
	}()

	select {
	case c := <-tlcpAccepted:
		_ = c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for TLCP accept")
	}

	_ = tlsClient.Close()
	_ = tlcpClient.Close()

	if tlsConns != 1 {
		t.Errorf("TLS route called %d times, want 1", tlsConns)
	}
	if tlcpConns != 1 {
		t.Errorf("TLCP route called %d times, want 1", tlcpConns)
	}
}

// TestTCPDemuxListener_SilentClientDoesNotStall verifies that a client which
// completes the TCP handshake but never sends its record header no longer
// blocks the shared port: the sniff used to run inline in the accept loop,
// so one silent peer (scanner, health check) head-of-line-blocked every
// subsequent connection on the port.
func TestTCPDemuxListener_SilentClientDoesNotStall(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	d := NewTCPDemux(TCPConfig{
		Inner:  ln,
		Routes: map[string]func(net.Conn) net.Conn{"tls": func(c net.Conn) net.Conn { return c }},
	})
	defer func() { _ = d.Close() }()
	tlsListener := d.Listener(ProtoTLS)

	// Silent client: handshake only, never sends a byte.
	silent, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = silent.Close() }()

	// A real TLS client behind the silent one must still be routed to the
	// virtual listener within a generous bound (well under the 10s sniff
	// deadline); before the fix this accept never happened at all.
	accCh := make(chan net.Conn, 1)
	go func() {
		c, err := tlsListener.Accept()
		if err == nil {
			accCh <- c
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// Minimal TLS ClientHello record header: handshake(0x16), TLS 1.0 version.
	if _, err := c.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x10}); err != nil {
		t.Fatal(err)
	}

	select {
	case <-accCh:
	case <-time.After(2 * time.Second):
		t.Fatal("second client stalled behind the silent client (head-of-line blocking)")
	}
}

// TestDetectUDPProtocol_PlainDNSNeverMisrouted exhaustively walks every
// query-ID high byte (0x00–0xFF) with a structurally valid plain DNS query:
// none may classify as QUIC or DTLS/DTLCP — the cert-fetch misroute lottery
// (~30% dropped, multi-second client stalls) must be closed for good.
func TestDetectUDPProtocol_PlainDNSNeverMisrouted(t *testing.T) {
	// A minimal valid query for "a.b." A IN.
	for idHigh := range 256 {
		q := []byte{
			byte(idHigh), 0x42, // ID
			0x01, 0x00, // flags: RD
			0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // counts
			0x01, 'a',
			0x01, 'b', 0x00,
			0x00, 0x01, // QTYPE A
			0x00, 0x01, // QCLASS IN
		}
		if got := DetectUDPProtocol(q); got != "" {
			t.Fatalf("plain DNS query with ID high byte %#x classified as %q", idHigh, got)
		}
	}
	// Same with a trailing OPT pseudo-record (EDNS) — the normal cert-fetch
	// shape: root(0x00) + TYPE 41 + class 1232 + TTL 0 + rdlen 0.
	for idHigh := range 256 {
		q := []byte{
			byte(idHigh), 0x42, 0x01, 0x00,
			0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			0x01, 'a', 0x01, 'b', 0x00,
			0x00, 0x01, 0x00, 0x01,
			0x00,
			0x00, 0x29, // OPT
			0x04, 0xD0, // class = 1232
			0x00, 0x00, 0x00, 0x00, // TTL
			0x00, 0x00, // rdlen
		}
		if got := DetectUDPProtocol(q); got != "" {
			t.Fatalf("EDNS plain DNS query with ID high byte %#x classified as %q", idHigh, got)
		}
	}
}

// TestLooksLikePlainDNSQuery_RejectsNoise verifies random/encrypted-shaped
// datagrams do NOT pass the structural plain-DNS check (they must stay
// classifiable by the QUIC/DTLS rules or the DNSCrypt fallback).
func TestLooksLikePlainDNSQuery_RejectsNoise(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		want bool
	}{
		{"valid minimal query", []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0x00, 0, 1, 0, 1}, true},
		{"QR set (response)", []byte{0x12, 0x34, 0x81, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0x00, 0, 1, 0, 1}, false},
		{"opcode set", []byte{0x12, 0x34, 0x09, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0x00, 0, 1, 0, 1}, false},
		{"RCODE set", []byte{0x12, 0x34, 0x01, 0x03, 0, 1, 0, 0, 0, 0, 0, 0, 0x00, 0, 1, 0, 1}, false},
		{"two questions", []byte{0x12, 0x34, 0x01, 0x00, 0, 2, 0, 0, 0, 0, 0, 0, 0x00, 0, 1, 0, 1}, false},
		{"truncated question", []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0x03, 'a'}, false},
		{"garbage", []byte{0xC3, 0x55, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikePlainDNSQuery(tc.data); got != tc.want {
				t.Fatalf("looksLikePlainDNSQuery(%v) = %t, want %t", tc.data, got, tc.want)
			}
		})
	}
}
