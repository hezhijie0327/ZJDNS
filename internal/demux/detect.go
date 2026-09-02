// Package demux provides protocol multiplexing for TLS/TLCP (TCP) and
// QUIC/DTLS/DTLCP (UDP) on shared ports.  It detects the protocol from
// the first record-layer bytes of each connection or datagram and routes
// to the appropriate handler.
package demux

import (
	"encoding/binary"
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

// quicMinInitialSize is the RFC 9000 §14 minimum datagram size for QUIC
// Initial packets — a client's first QUIC packet on any 5-tuple.
const quicMinInitialSize = 1200

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
// Detection is deliberately conservative: a wrong POSITIVE steals the
// datagram from the DNSCrypt fallback (whose plain cert-fetch queries look
// random in their first bytes), so every rule must match the protocol's
// mandatory structure, not just a plausible first byte:
//
//	plain DNS query shape  → ""      (negative check first — see below)
//	first byte >= 0xC0 AND
//	  len >= 1200          → "quic"  (long header; a client's FIRST QUIC
//	                                packet is always an Initial, which RFC
//	                                9000 §14 requires to be >= 1200 bytes —
//	                                a plain DNS query's random ID high byte
//	                                lands >= 0xC0 with p≈25%)
//	first byte 0x14–0x18 AND
//	  version ∈ {0xFEFF, 0xFEFD, 0xFEFC}
//	                       → "dtls"  (DTLS 1.0/1.2/1.3 record version)
//	first byte 0x14–0x18 AND
//	  version == 0x0101    → "dtlcp" (TLCP record version)
//	otherwise              → ""      (unknown → DNSCrypt port fallback)
//
// The plain-DNS negative check comes first because a shared UDP port that
// carries DNSCrypt also carries the plaintext cert fetch (a plain DNS TXT
// query): its query-ID high byte is random, so without the structural check
// ~30% of fetches landed in the QUIC/DTLS buckets and were dropped, forcing
// clients into multi-second retransmit stalls.
func DetectUDPProtocol(data []byte) string {
	if len(data) < 3 {
		return ""
	}

	if looksLikePlainDNSQuery(data) {
		return ""
	}

	first := data[0]

	// QUIC long header: Form (bit 7) = 1, Fixed (bit 6) = 1 → first byte >= 0xC0.
	// The 1200-byte floor excludes random-ID collisions with plain DNS.
	if first >= 0xC0 && len(data) >= quicMinInitialSize {
		return ProtoQUIC
	}

	// TLS-family record types: change_cipher_spec(0x14), alert(0x15),
	// handshake(0x16), application_data(0x17), header(0x18).  The version
	// must be an exact known record version — the former ">= 0x1000"
	// heuristic matched almost any garbage.
	if first >= 0x14 && first <= 0x18 {
		// Version field occupies bytes 1–2 (big-endian uint16).
		switch uint16(data[1])<<8 | uint16(data[2]) {
		case 0xFEFF, 0xFEFD, 0xFEFC: // DTLS 1.0 / 1.2 / 1.3
			return ProtoDTLS
		case 0x0101: // DTLCP
			return ProtoDTLCP
		}
	}

	return ""
}

// looksLikePlainDNSQuery reports whether data has the exact structural shape
// of a plain DNS query: a 12-byte header with QR=0, opcode=0, AA=0, RA=0,
// Z=0, RCODE=0, QDCOUNT=1, ANCOUNT=NSCOUNT=0, ARCOUNT ∈ {0,1}, followed by
// one uncompressed question that terminates in-bounds, plus optionally a
// single well-formed OPT pseudo-record.  Random data (encrypted queries,
// QUIC/DTLS records) clears every gate with negligible probability, and even
// a miss only routes to the DNSCrypt fallback — where unclassifiable
// datagrams already go.
func looksLikePlainDNSQuery(data []byte) bool {
	if len(data) < 17 { // header(12) + root qname(1) + qtype/qclass(4)
		return false
	}
	// Byte 2: QR(0x80), Opcode(0x78) and AA(0x04) must be clear — only
	// TC(0x02) and RD(0x01) are legal query bits.  Byte 3: RA(0x80), Z(0x40)
	// and RCODE(0x0F) must be clear — AD(0x20) and CD(0x10) are legal.
	if data[2]&0xFC != 0 || data[3]&0xCF != 0 {
		return false
	}
	arcount := binary.BigEndian.Uint16(data[10:12])
	if binary.BigEndian.Uint16(data[4:6]) != 1 || // QDCOUNT
		binary.BigEndian.Uint16(data[6:8]) != 0 || // ANCOUNT
		binary.BigEndian.Uint16(data[8:10]) != 0 || // NSCOUNT
		arcount > 1 {
		return false
	}
	// Walk the single question name (compression pointers never appear in
	// question sections).
	pos := 12
	for {
		if pos >= len(data) {
			return false
		}
		if data[pos] == 0 {
			pos++
			break
		}
		l := int(data[pos])
		if l > 63 || pos+1+l > len(data) {
			return false
		}
		pos += 1 + l
	}
	if pos+4 > len(data) { // QTYPE + QCLASS must fit
		return false
	}
	if arcount == 0 {
		return pos+4 == len(data)
	}
	// One trailing OPT pseudo-record: root name(1) + TYPE=41(2) +
	// class(2) + TTL(4) + rdlength(2) + rdlength bytes of options.
	rest := len(data) - (pos + 4)
	if rest < 11 || data[pos+4] != 0 ||
		binary.BigEndian.Uint16(data[pos+5:pos+7]) != 41 {
		return false
	}
	return rest == 11+int(binary.BigEndian.Uint16(data[pos+9:pos+11]))
}
