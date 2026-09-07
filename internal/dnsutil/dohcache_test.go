package dnsutil

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func TestDOHCacheControl(t *testing.T) {
	tests := []struct {
		name string
		msg  *dns.Msg
		want string
	}{
		{"nil", nil, "max-age=0"},
		{"empty", &dns.Msg{}, "max-age=0"},
		{"single 300s", &dns.Msg{Answer: []dns.RR{
			&dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, Addr: netip.MustParseAddr("1.2.3.4")},
		}}, "max-age=300"},
		{"min of mixed", &dns.Msg{Answer: []dns.RR{
			&dns.A{Hdr: dns.Header{Name: "a.example.com.", Class: dns.ClassINET, TTL: 600}},
			&dns.A{Hdr: dns.Header{Name: "b.example.com.", Class: dns.ClassINET, TTL: 60}},
		}}, "max-age=60"},
		// RFC 8484 §5.1 MUST: the freshness lifetime may not exceed the
		// smallest TTL — a zero-TTL record clamps max-age to 0.
		{"zero among positives", &dns.Msg{Answer: []dns.RR{
			&dns.A{Hdr: dns.Header{Name: "a.example.com.", Class: dns.ClassINET, TTL: 300}},
			&dns.A{Hdr: dns.Header{Name: "b.example.com.", Class: dns.ClassINET, TTL: 0}},
		}}, "max-age=0"},
		{"all zero", &dns.Msg{Answer: []dns.RR{
			&dns.A{Hdr: dns.Header{Name: "a.example.com.", Class: dns.ClassINET, TTL: 0}},
		}}, "max-age=0"},
		// Empty Answer (NXDOMAIN/NODATA): RFC 2308 negative freshness from
		// the Authority SOA MINIMUM field.
		{"soa minimum", &dns.Msg{Ns: []dns.RR{
			&dns.SOA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 3600}, Minttl: 900},
		}}, "max-age=900"},
		{"soa minimum zero", &dns.Msg{Ns: []dns.RR{
			&dns.SOA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 3600}, Minttl: 0},
		}}, "max-age=0"},
	}
	for _, tc := range tests {
		if got := DOHCacheControl(tc.msg); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestExecuteDoHRequestAgeTTL verifies the RFC 8484 §5.1 client-side MUST:
// the Age header seconds are subtracted from record TTLs. The DO bit
// travels in the OPT TTL field on the wire, but this fork's Unpack promotes
// it to the message-level Security field and strips the OPT RR — the test
// pins that the decrement leaves EDNS metadata intact.
func TestExecuteDoHRequestAgeTTL(t *testing.T) {
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, new(dns.Msg))
	resp.Answer = []dns.RR{
		&dns.A{Hdr: dns.Header{Name: "cached.example.com.", Class: dns.ClassINET, TTL: 300}, Addr: netip.MustParseAddr("192.0.2.1")},
	}
	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(1232)
	opt.SetSecurity(true) // DO bit — lands in the OPT TTL field on the wire
	resp.Pseudo = append(resp.Pseudo, opt)
	if err := resp.Pack(); err != nil {
		t.Fatal(err)
	}
	wire := append([]byte(nil), resp.Data...)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Age", "60")
		_, _ = w.Write(wire)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "cached.example.com.", dns.TypeA)
	got, err := ExecuteDoHRequest(context.Background(), q, u, srv.Client(), http.MethodGet)
	if err != nil {
		t.Fatalf("ExecuteDoHRequest: %v", err)
	}
	if ttl := got.Answer[0].Header().TTL; ttl != 240 {
		t.Errorf("answer TTL after Age 60 = %d, want 240", ttl)
	}
	if !got.Security {
		t.Error("DO bit (message-level Security) lost — Age handling must not touch EDNS metadata")
	}
}
