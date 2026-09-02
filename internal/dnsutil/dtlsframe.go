package dnsutil

import (
	"encoding/binary"
	"net"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
)

// TruncateWire shrinks a packed DNS response wire to its header + question
// section, setting the TC bit — the RFC 1035 §6.2 truncation used when a
// datagram response exceeds the transport budget.  A trailing OPT record is
// preserved (RFC 6891 §6.2.5): nil-ing the RR sections at the message level
// would destroy the OPT and leave EDNS clients without their option echo
// (including EDE diagnostics carried inside it).  Zero allocations on the
// typical wire (no OPT — the truncated slice shares the input's backing).
func TruncateWire(wire []byte) []byte {
	if len(wire) < dns.MsgHeaderSize {
		return wire
	}
	pos := dns.MsgHeaderSize
	questions := int(binary.BigEndian.Uint16(wire[4:6]))
	for range questions {
		off, ok := SkipWireName(wire, pos)
		if !ok || off+4 > len(wire) {
			// Malformed (or incomplete) question — keep only the header.
			return wire[:dns.MsgHeaderSize]
		}
		pos = off + 4 // QTYPE(2) + QCLASS(2)
	}
	questionEnd := pos

	// Scan the RR sections for a trailing OPT (type 41) to preserve.
	var opt []byte
	for pos+10 <= len(wire) {
		off, ok := SkipWireName(wire, pos)
		if !ok || off+10 > len(wire) {
			break
		}
		rrEnd := off + 10 + int(binary.BigEndian.Uint16(wire[off+8:]))
		if rrEnd > len(wire) {
			break
		}
		if binary.BigEndian.Uint16(wire[off:]) == dns.TypeOPT {
			opt = wire[pos:rrEnd] // include the owner name (root label)
		}
		pos = rrEnd
	}

	if questionEnd > len(wire) {
		// Unreachable with a well-formed question loop, but a malformed
		// wire must never panic the serve path.
		return wire[:dns.MsgHeaderSize]
	}
	truncated := wire[:questionEnd]
	truncated[2] |= 0x02
	truncated[6], truncated[7] = 0, 0 // ANCOUNT
	truncated[8], truncated[9] = 0, 0 // NSCOUNT
	if opt != nil {
		truncated = append(truncated, opt...)
		binary.BigEndian.PutUint16(truncated[10:12], 1) // ARCOUNT = the OPT
	}
	return truncated
}

// WriteDTLSFrame packs resp and writes it with a 2-byte length prefix
// (RFC 1035 §4.2.2) over a datagram-oriented secure transport (DTLS /
// DTLCP).  safeMax is the transport payload budget (PMTU minus overhead,
// computed by the caller from config); a response beyond it is truncated at
// the wire level via TruncateWire.  maxLen caps the 16-bit frame length.
// The frame buffer comes from the shared pool.  Returns false only on a
// write error (the connection is unusable); dropped responses return true
// so the connection keeps serving.
func WriteDTLSFrame(conn net.Conn, resp *dns.Msg, safeMax, maxLen int, label string) bool {
	if resp == nil {
		return true
	}
	wire := resp.Data
	if len(wire) == 0 {
		if err := resp.Pack(); err != nil {
			log.Debugf("%s pack error: %v", label, err)
			return true
		}
		wire = resp.Data
	}
	if len(wire) > safeMax {
		wire = TruncateWire(wire)
	}
	if len(wire) > maxLen {
		log.Debugf("%s response too large (%d bytes)", label, len(wire))
		return true
	}

	frameBuf := pool.DefaultBuffer.Get()
	frameOK := len(frameBuf) >= DNSFramePrefixLen+len(wire)
	var frame []byte
	if frameOK {
		frame = frameBuf[:DNSFramePrefixLen+len(wire)]
	} else {
		frame = make([]byte, DNSFramePrefixLen+len(wire))
		pool.DefaultBuffer.Put(frameBuf)
	}
	binary.BigEndian.PutUint16(frame[:DNSFramePrefixLen], uint16(len(wire))) //nolint:gosec // G115: bounded by maxLen
	copy(frame[DNSFramePrefixLen:], wire)
	_, err := conn.Write(frame)
	if frameOK {
		pool.DefaultBuffer.Put(frame)
	}
	if err != nil {
		log.Debugf("%s write error: %v", label, err)
		return false
	}
	return true
}
