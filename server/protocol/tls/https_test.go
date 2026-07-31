package tls

import (
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func TestDohCacheControl(t *testing.T) {
	if got := dohCacheControl(nil); got != "max-age=0" {
		t.Errorf("nil: got %q, want max-age=0", got)
	}
	empty := &dns.Msg{}
	if got := dohCacheControl(empty); got != "max-age=0" {
		t.Errorf("empty: got %q, want max-age=0", got)
	}
	msg := &dns.Msg{Answer: []dns.RR{
		&dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("1.2.3.4")}},
	}}
	if got := dohCacheControl(msg); got != "max-age=300" {
		t.Errorf("300s: got %q, want max-age=300", got)
	}
	msg2 := &dns.Msg{Answer: []dns.RR{
		&dns.A{Hdr: dns.Header{Name: "a.example.com.", Class: dns.ClassINET, TTL: 600}},
		&dns.A{Hdr: dns.Header{Name: "b.example.com.", Class: dns.ClassINET, TTL: 60}},
	}}
	if got := dohCacheControl(msg2); got != "max-age=60" {
		t.Errorf("min TTL: got %q, want max-age=60", got)
	}
}
