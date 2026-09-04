package cache

import (
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// Entry.WireRcode / WireAuthoritative read the rcode and AA bit from a
// pre-packed entry wire (extended rcodes via the OPT TTL high byte,
// RFC 6891 §6.1.3).

func TestEntryRcode_ExtendedRcode(t *testing.T) {
	msg := new(dns.Msg)
	dnsutil.SetQuestion(msg, "example.com.", dns.TypeA)
	msg.Rcode = dns.RcodeBadVers // 16 — extended rcode
	msg.UDPSize = 1232
	msg.Pseudo = append(msg.Pseudo, &dns.PADDING{}) // force OPT at pack
	if err := msg.Pack(); err != nil {
		t.Fatalf("pack: %v", err)
	}
	entry := &Entry{ResponseWire: msg.Data}
	if got := entry.WireRcode(); got != dns.RcodeBadVers {
		t.Errorf("entryRcode = %d, want %d (extended rcode via OPT)", got, dns.RcodeBadVers)
	}
}

func TestEntryRcode_LowRcode(t *testing.T) {
	msg := new(dns.Msg)
	dnsutil.SetQuestion(msg, "example.com.", dns.TypeA)
	msg.Rcode = dns.RcodeNameError // 3 — fits the header nibble
	if err := msg.Pack(); err != nil {
		t.Fatalf("pack: %v", err)
	}
	entry := &Entry{ResponseWire: msg.Data}
	if got := entry.WireRcode(); got != dns.RcodeNameError {
		t.Errorf("entryRcode = %d, want %d", got, dns.RcodeNameError)
	}
}

func TestEntryRcode_ShortWire(t *testing.T) {
	if got := (&Entry{}).WireRcode(); got != 0 {
		t.Errorf("entryRcode on empty wire = %d, want 0", got)
	}
}
