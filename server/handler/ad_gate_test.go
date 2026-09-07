package handler

import (
	"testing"
	"time"
	"zjdns/cache"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// TestClientUnderstandsAD pins the RFC 6840 §5.8 gate: the response AD bit
// may only be asserted to a requester that signalled DNSSEC awareness via
// the DO bit or the AD bit of the query.
func TestClientUnderstandsAD(t *testing.T) {
	tests := []struct {
		name string
		req  *dns.Msg
		want bool
	}{
		{"nil", nil, false},
		{"plain", new(dns.Msg), false},
		{"do bit", &dns.Msg{Security: true}, true},
		{"ad bit", &dns.Msg{AuthenticatedData: true}, true},
	}
	for _, tc := range tests {
		if got := ClientUnderstandsAD(tc.req); got != tc.want {
			t.Errorf("%s: got %t, want %t", tc.name, got, tc.want)
		}
	}
}

// TestDNSSECIncluded pins the RFC 4035 §3.2.1 exemption: a DO=0 query for a
// DNSSEC type itself must not have its answer stripped.
func TestDNSSECIncluded(t *testing.T) {
	tests := []struct {
		name string
		qctx *QueryContext
		want bool
	}{
		{"do set", &QueryContext{ClientRequestedDNSSEC: true, Qtype: dns.TypeA}, true},
		{"dnskey", &QueryContext{Qtype: dns.TypeDNSKEY}, true},
		{"rrsig", &QueryContext{Qtype: dns.TypeRRSIG}, true},
		{"ds", &QueryContext{Qtype: dns.TypeDS}, true},
		{"plain a", &QueryContext{Qtype: dns.TypeA}, false},
	}
	for _, tc := range tests {
		if got := DNSSECIncluded(tc.qctx); got != tc.want {
			t.Errorf("%s: got %t, want %t", tc.name, got, tc.want)
		}
	}
}

// TestBuildCacheEntryResponseADGate drives the cache-hit path: a validated
// entry asserts AD only when the requester set DO or AD (RFC 6840 §5.8).
func TestBuildCacheEntryResponseADGate(t *testing.T) {
	entry := &cache.Entry{
		Timestamp:    time.Now().Unix(),
		TTL:          300,
		Validated:    true,
		ResponseWire: packedResponse(t),
		TTLOffsets:   nil,
		HasDNSSEC:    false,
	}

	doReq := new(dns.Msg)
	dnsutil.SetQuestion(doReq, "example.com.", dns.TypeA)
	doReq.Security = true
	msg := BuildCacheEntryResponse(doReq, entry, true, false)
	if !msg.AuthenticatedData {
		t.Error("DO requester must see AD on a validated entry")
	}

	plainReq := new(dns.Msg)
	dnsutil.SetQuestion(plainReq, "example.com.", dns.TypeA)
	msg = BuildCacheEntryResponse(plainReq, entry, true, false)
	if msg.AuthenticatedData {
		t.Error("plain requester must not see AD (RFC 6840 §5.8)")
	}
}

func packedResponse(t *testing.T) []byte {
	t.Helper()
	msg := new(dns.Msg)
	dnsutil.SetQuestion(msg, "example.com.", dns.TypeA)
	msg.Response = true
	if err := msg.Pack(); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), msg.Data...)
}
