package dnsutil

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// buildTruncatable packs a NOERROR response with one A answer and optionally
// an EDNS OPT in Additional, returning the wire.
func buildTruncatable(t *testing.T, withOPT bool) []byte {
	t.Helper()
	resp := dnsutil.SetReply(new(dns.Msg), dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA))
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr:  dns.Header{Name: "example.com.", TTL: 60, Class: dns.ClassINET},
		Addr: netip.MustParseAddr("93.184.216.34"),
	})
	if withOPT {
		resp.Extra = append(resp.Extra, &dns.OPT{Hdr: dns.Header{Name: "."}})
	}
	if err := resp.Pack(); err != nil {
		t.Fatalf("pack: %v", err)
	}
	return resp.Data
}

// TestTruncateWire_NoOPT asserts the OPT-less truncation stays parseable:
// ARCOUNT must be zeroed, not left at the pre-truncation value.
func TestTruncateWire_NoOPT(t *testing.T) {
	wire := buildTruncatable(t, false)
	truncated := TruncateWire(wire)
	if len(truncated) >= len(wire) {
		t.Fatalf("wire was not truncated: %d -> %d", len(wire), len(truncated))
	}
	un := new(dns.Msg)
	un.Data = truncated
	if err := un.Unpack(); err != nil {
		t.Fatalf("truncated wire without OPT does not unpack: %v", err)
	}
	if !un.Truncated {
		t.Fatal("TC bit not set")
	}
	if len(un.Answer) != 0 || len(un.Ns) != 0 || len(un.Extra) != 0 {
		t.Fatalf("truncated response must carry no RRs, got %d/%d/%d",
			len(un.Answer), len(un.Ns), len(un.Extra))
	}
}

// TestTruncateWire_WithOPT asserts the trailing OPT survives with ARCOUNT=1.
func TestTruncateWire_WithOPT(t *testing.T) {
	wire := buildTruncatable(t, true)
	truncated := TruncateWire(wire)
	un := new(dns.Msg)
	un.Data = truncated
	if err := un.Unpack(); err != nil {
		t.Fatalf("truncated wire with OPT does not unpack: %v", err)
	}
	if !un.Truncated {
		t.Fatal("TC bit not set")
	}
	// Unpack consumes the OPT RR into UDPSize (max(advertised, MinMsgSize));
	// a non-zero UDPSize proves the preserved OPT parsed cleanly.
	if un.UDPSize == 0 {
		t.Fatal("preserved OPT was not parsed — UDPSize still zero")
	}
	if got := binary.BigEndian.Uint16(truncated[10:12]); got != 1 {
		t.Fatalf("ARCOUNT = %d, want 1 (the OPT)", got)
	}
}
