package dnscrypt

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// normalize truncates the DNS response if it exceeds the client's EDNS buffer
// size.  Following RFC 2181 §9, truncated responses must have TC=1 and empty
// Answer/Ns/Extra sections — the client MUST retry over TCP.
func normalize(proto string, req, res *dns.Msg) {
	size := dnsSize(proto, req)
	size -= EDNSSize
	if res.Len() > size {
		dnsutil.Truncate(res)
	}
}

// dnsSize returns the buffer size advertised in the request's OPT record.
// The codeberg.org/miekg/dns fork stores the EDNS UDP payload size in
// Msg.UDPSize and generates the OPT pseudo-record during Pack().  After
// Unpack(), the OPT fields are merged back into the Msg header — Extra
// typically does not contain an explicit OPT record.  We read UDPSize
// first, falling back to the Extra scan for compatibility.
func dnsSize(proto string, r *dns.Msg) int {
	size := r.UDPSize
	if size == 0 {
		size = dns.MinMsgSize
	}
	for _, extra := range r.Extra {
		if opt, ok := extra.(*dns.OPT); ok {
			size = opt.Hdr.Class
			break
		}
	}
	if proto != "udp" {
		return dns.MaxMsgSize
	}
	if size < dns.MinMsgSize {
		return dns.MinMsgSize
	}
	return int(size)
}

// readPrefixed reads a DNS message with a 2-byte length prefix.
func readPrefixed(conn net.Conn) (b []byte, err error) {
	l := make([]byte, 2)
	_, err = io.ReadFull(conn, l)
	if err != nil {
		return nil, fmt.Errorf("reading msg len: %w", err)
	}
	packetLen := binary.BigEndian.Uint16(l)
	if packetLen > dns.MaxMsgSize {
		return nil, ErrQueryTooLarge
	}
	buf := make([]byte, packetLen)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, fmt.Errorf("reading full message: %w", err)
	}
	return buf, nil
}

// writePrefixed writes a DNS message with a 2-byte length prefix.
func writePrefixed(b []byte, conn net.Conn) (err error) {
	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(b))) //nolint:gosec // G115: DNS message length bounded by MaxMsgSize
	_, err = (&net.Buffers{l, b}).WriteTo(conn)
	if err != nil {
		return fmt.Errorf("writing to connection: %w", err)
	}
	return nil
}
