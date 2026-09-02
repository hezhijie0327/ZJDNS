// Package demux provides protocol multiplexing for TLS/TLCP (TCP) and
// QUIC/DTLS/DTLCP (UDP) on shared ports.  It detects the protocol from
// the first record-layer bytes of each connection or datagram and routes
// to the appropriate handler.
package demux

import (
	"io"
	"net"
	"time"
)

// bufferedConn wraps a net.Conn and replays a buffered prefix before
// reading from the underlying connection.  This is used by DetectTCPProtocol
// to return the already-consumed record header to the caller.
type bufferedConn struct {
	net.Conn
	buf []byte
}

// Protocol family identifiers returned by DetectTCPProtocol and DetectUDPProtocol.
const (
	ProtoTLS      = "tls"
	ProtoTLCP     = "tlcp"
	ProtoQUIC     = "quic"
	ProtoDTLS     = "dtls"
	ProtoDTLCP    = "dtlcp"
	ProtoDNSCrypt = "dnscrypt"
)

// sniffTimeout bounds the record-header read in DetectTCPProtocol.  It only
// needs to cover a client's first flight (TCP handshake + ClientHello);
// anything still silent after this is a scanner or a dead peer.
const sniffTimeout = 10 * time.Second

// tcpRecordHeaderLen is the TLS/TLCP record layer header length:
//
//	ContentType(1) + ProtocolVersion(2) + Length(2) = 5 bytes.
const tcpRecordHeaderLen = 5

func (c *bufferedConn) Read(b []byte) (int, error) {
	if len(c.buf) == 0 {
		return c.Conn.Read(b)
	}

	n := copy(b, c.buf)
	c.buf = c.buf[n:]
	if len(c.buf) > 0 {
		return n, nil
	}
	// Buffer exhausted — if the caller's buffer has room, read more
	// from the underlying connection in the same call.
	if n < len(b) {
		n2, err := c.Conn.Read(b[n:])
		n += n2
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// DetectTCPProtocol reads the first 5 bytes of a TCP connection's record
// layer header and returns the detected protocol family together with a
// wrapper connection that replays the buffered bytes on subsequent reads.
//
// Detection rules (first byte → content type vs length prefix):
//
//	0x14–0x17 → TLS record content type; inspect version byte (header[1]):
//	  0x03 → "tls"  (TLS 1.0–1.3, record version 0x0301–0x0304)
//	  0x01 → "tlcp" (TLCP, record version 0x0101)
//	0x00–0x04 → "dnscrypt" (DNSCrypt 2-byte length prefix; max query ~1260 B)
//	other     → "" (unknown)
//
// The read is bounded by sniffTimeout: a client that completes the TCP
// handshake but never sends the 5 header bytes (port scanners, health
// checks, half-open clients) must not pin its connection forever.
func DetectTCPProtocol(conn net.Conn) (protocol string, detected net.Conn, err error) {
	header := make([]byte, tcpRecordHeaderLen)
	if dl, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = dl.SetReadDeadline(time.Now().Add(sniffTimeout))
	}
	if _, err = io.ReadFull(conn, header); err != nil {
		return "", nil, err
	}
	if dl, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = dl.SetReadDeadline(time.Time{}) // clear — the protocol server owns deadlines now
	}

	first := header[0]
	switch {
	case first >= 0x14 && first <= 0x17:
		// TLS record content type range: handshake(0x16), CCS(0x14),
		// alert(0x15), application_data(0x17).
		switch header[1] {
		case 0x03:
			protocol = ProtoTLS
		case 0x01:
			protocol = ProtoTLCP
		}
	default:
		// DNSCrypt TCP frames begin with a 2-byte big-endian length prefix.
		// Queries are at most ~1260 bytes (MaxDNSUDPPacketSize), so the
		// high byte is 0x00–0x04 — no overlap with TLS content types.
		protocol = ProtoDNSCrypt
	}

	return protocol, &bufferedConn{Conn: conn, buf: header}, nil
}

// DetectUDPProtocol inspects the first bytes of a UDP datagram and returns
// the detected protocol family.
//
// Detection rules:
//
//	first byte >= 0xC0             → "quic"  (QUIC long header, RFC 9000 §17.2)
//	first byte 0x14–0x18,          → "dtls"  (DTLS 1.0/1.2, version 0xFEFF/0xFEFD)
//	  version bytes (bytes 1–2) >= 0x1000
//	first byte 0x14–0x18,          → "dtlcp" (DTLCP, version 0x0101)
//	  version bytes (bytes 1–2) < 0x1000
//	otherwise                      → ""      (unknown)
func DetectUDPProtocol(data []byte) string {
	if len(data) < 3 {
		return ""
	}

	first := data[0]

	// QUIC long header: Form (bit 7) = 1, Fixed (bit 6) = 1 → first byte >= 0xC0.
	if first >= 0xC0 {
		return ProtoQUIC
	}

	// TLS-family record types: change_cipher_spec(0x14), alert(0x15),
	// handshake(0x16), application_data(0x17), header(0x18).
	if first >= 0x14 && first <= 0x18 {
		// Version field occupies bytes 1–2 (big-endian uint16).
		version := uint16(data[1])<<8 | uint16(data[2])
		if version >= 0x1000 {
			return ProtoDTLS
		}
		return ProtoDTLCP
	}

	return ""
}
