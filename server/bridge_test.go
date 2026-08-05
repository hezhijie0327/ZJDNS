package server

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// TestTruncateWire verifies the RFC 2181 §9 wire-level truncation: TC bit set,
// RR counts zeroed, question preserved, OPT (when present) preserved.
func TestTruncateWire(t *testing.T) {
	req := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	req.ID = 0xBEEF

	msg := new(dns.Msg)
	dnsutil.SetReply(msg, req)
	msg.RecursionAvailable = true
	for range 10 {
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.Header{Name: "example.com.", TTL: 300, Class: dns.ClassINET},
			A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
		})
	}
	if err := msg.Pack(); err != nil {
		t.Fatal(err)
	}

	truncated := truncateWire(msg.Data)

	// TC bit set (flags byte 2, bit 0x02).
	if truncated[2]&0x02 == 0 {
		t.Error("TC bit not set")
	}
	// QR/opcode/flags otherwise preserved.
	if truncated[2]&0x80 == 0 {
		t.Error("QR bit lost")
	}
	// RR counts zeroed.
	if an, ns, ar := binary.BigEndian.Uint16(truncated[6:8]), binary.BigEndian.Uint16(truncated[8:10]), binary.BigEndian.Uint16(truncated[10:12]); an != 0 || ns != 0 || ar != 0 {
		t.Errorf("RR counts = %d/%d/%d, want 0/0/0", an, ns, ar)
	}
	// Question preserved.
	if qd := binary.BigEndian.Uint16(truncated[4:6]); qd != 1 {
		t.Errorf("QDCOUNT = %d, want 1", qd)
	}
	if len(truncated) < dns.MsgHeaderSize+len("example.com.")+4 {
		t.Error("question section missing from truncated wire")
	}
	// RD flag preserved (echoed from the request).
	if truncated[2]&0x01 == 0 {
		t.Error("RD bit lost")
	}
}

// TestTruncateWire_KeepsOPT verifies the OPT record survives truncation
// (RFC 6891 §6.2.5) with ARCOUNT adjusted.
func TestTruncateWire_KeepsOPT(t *testing.T) {
	req := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	req.ID = 0xBEEF

	msg := new(dns.Msg)
	dnsutil.SetReply(msg, req)
	msg.RecursionAvailable = true
	msg.UDPSize = 1232
	msg.Answer = []dns.RR{&dns.A{
		Hdr: dns.Header{Name: "example.com.", TTL: 300, Class: dns.ClassINET},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	}}
	// Force an OPT into the additional section via a pseudo option.
	msg.Pseudo = append(msg.Pseudo, &dns.EDE{InfoCode: dns.ExtendedErrorNetworkError})
	if err := msg.Pack(); err != nil {
		t.Fatal(err)
	}

	truncated := truncateWire(msg.Data)

	if ar := binary.BigEndian.Uint16(truncated[10:12]); ar != 1 {
		t.Errorf("ARCOUNT = %d, want 1 (OPT preserved)", ar)
	}
	// Walk the additional section: must contain exactly one OPT.
	pos := 12
	questions := int(binary.BigEndian.Uint16(truncated[4:6]))
	for range questions {
		off, ok := skipWireName(truncated, pos)
		if !ok {
			t.Fatal("malformed question in truncated wire")
		}
		pos = off + 4
	}
	foundOPT := false
	for pos+10 <= len(truncated) {
		off, ok := skipWireName(truncated, pos)
		if !ok {
			break
		}
		typ := binary.BigEndian.Uint16(truncated[off:])
		rrEnd := off + 10 + int(binary.BigEndian.Uint16(truncated[off+8:]))
		if typ == dns.TypeOPT {
			foundOPT = true
		}
		pos = rrEnd
	}
	if !foundOPT {
		t.Error("OPT record not preserved in truncated wire")
	}
}

// TestTruncateWire_Malformed verifies defensive handling of short wires.
func TestTruncateWire_Malformed(t *testing.T) {
	if got := truncateWire(nil); got != nil {
		t.Error("nil wire must stay nil")
	}
	short := []byte{0, 1, 2, 3}
	if got := truncateWire(short); len(got) != len(short) {
		t.Errorf("short wire changed length: %d → %d", len(short), len(got))
	}
}
