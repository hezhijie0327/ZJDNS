package middleware

import (
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
)

// TestHasUsableAAAA pins the RFC 6147 §5.1.4 default exclude entry: IPv4-
// mapped AAAA records (::ffff:0:0/96) are placeholders that must not stop
// synthesis; any real AAAA does.
func TestHasUsableAAAA(t *testing.T) {
	mapped := []dns.RR{&dns.AAAA{
		Hdr:  dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 60},
		Addr: netip.MustParseAddr("::ffff:101.91.42.232"),
	}}
	if hasUsableAAAA(mapped) {
		t.Error("IPv4-mapped-only answer must be treated as AAAA-less (synthesis proceeds)")
	}
	mixed := []dns.RR{mapped[0], &dns.AAAA{
		Hdr:  dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 60},
		Addr: netip.MustParseAddr("240e:b8f:39e1::1"),
	}}
	if !hasUsableAAAA(mixed) {
		t.Error("a real AAAA alongside mapped ones must stop synthesis")
	}
	if hasUsableAAAA(nil) {
		t.Error("empty answer has no usable AAAA")
	}
}
