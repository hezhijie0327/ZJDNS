package tls

import (
	"net/netip"
	"testing"
	"time"
	"zjdns/config"

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

func TestLeafNotAfterClampedToCA(t *testing.T) {
	now := time.Now()
	caNotAfter := now.Add(10 * 24 * time.Hour) // CA expires sooner than the leaf's default

	// Leaf validity longer than the CA's remaining life: clamped to the CA.
	if got := leafNotAfter(now, caNotAfter); !got.Equal(caNotAfter) {
		t.Errorf("leafNotAfter = %v, want clamped to CA %v", got, caNotAfter)
	}

	// Normal case: CA outlives the leaf — leaf keeps its own validity.
	caLong := now.Add(365 * 24 * time.Hour)
	want := now.Add(config.DefaultServerCertValidity)
	if got := leafNotAfter(now, caLong); !got.Equal(want) {
		t.Errorf("leafNotAfter = %v, want %v", got, want)
	}
}
