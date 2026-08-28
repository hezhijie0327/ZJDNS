package resolver

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
	"zjdns/config"
	"zjdns/server/defense"
	"zjdns/server/upstream"

	"codeberg.org/miekg/dns"
)

// The flight's dedup semantics (leader-runs-once, follower-waits, bounded
// follower, per-key independence) are pending.ResultGroup semantics, covered
// by internal/pending tests; the resolver-level tests below cover the pieces
// the resolver contributes: address extraction and the in-flight cap.

// TestNSAddrsFromResult verifies the address reduction used by the flight
// leader: answer records matching qtype become "ip:port" addresses, and A
// queries additionally collect AAAA glue from the additional section.
func TestNSAddrsFromResult(t *testing.T) {
	nsName := "ns1.example.com."
	cases := []struct {
		desc       string
		answer     []dns.RR
		additional []dns.RR
		qtype      uint16
		want       []string
	}{
		{
			desc:   "A query extracts A records",
			answer: []dns.RR{aRec(nsName, "192.0.2.1"), aRec(nsName, "192.0.2.2")},
			qtype:  dns.TypeA,
			want:   []string{"192.0.2.1:53", "192.0.2.2:53"},
		},
		{
			desc:   "AAAA query extracts AAAA records",
			answer: []dns.RR{aaaaRec(nsName, "2001:db8::1")},
			qtype:  dns.TypeAAAA,
			want:   []string{"[2001:db8::1]:53"},
		},
		{
			desc:   "A query ignores AAAA records in the answer section",
			answer: []dns.RR{aRec(nsName, "192.0.2.1"), aaaaRec(nsName, "2001:db8::1")},
			qtype:  dns.TypeA,
			want:   []string{"192.0.2.1:53"},
		},
		{
			desc:   "AAAA query ignores A records in the answer section",
			answer: []dns.RR{aRec(nsName, "192.0.2.1"), aaaaRec(nsName, "2001:db8::1")},
			qtype:  dns.TypeAAAA,
			want:   []string{"[2001:db8::1]:53"},
		},
		{
			desc:       "A query collects AAAA glue from the additional section",
			answer:     []dns.RR{aRec(nsName, "192.0.2.1")},
			additional: []dns.RR{aaaaRec(nsName, "2001:db8::1")},
			qtype:      dns.TypeA,
			want:       []string{"192.0.2.1:53", "[2001:db8::1]:53"},
		},
		{
			desc:       "glue with a different owner is ignored",
			answer:     []dns.RR{aRec(nsName, "192.0.2.1")},
			additional: []dns.RR{aaaaRec("ns2.example.com.", "2001:db8::9")},
			qtype:      dns.TypeA,
			want:       []string{"192.0.2.1:53"},
		},
		{
			desc:       "glue name match is case-insensitive",
			answer:     nil,
			additional: []dns.RR{aaaaRec("NS1.EXAMPLE.COM.", "2001:db8::1")},
			qtype:      dns.TypeA,
			want:       []string{"[2001:db8::1]:53"},
		},
		{
			desc:       "AAAA query does not collect additional-section glue",
			answer:     nil,
			additional: []dns.RR{aaaaRec(nsName, "2001:db8::1")},
			qtype:      dns.TypeAAAA,
			want:       nil,
		},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			got := nsAddrsFromResult(c.answer, c.additional, nsName, c.qtype)
			if len(got.addrs) != len(c.want) {
				t.Fatalf("addrs = %v, want %v", got.addrs, c.want)
			}
			for i := range c.want {
				if got.addrs[i] != c.want[i] {
					t.Fatalf("addrs[%d] = %s, want %s", i, got.addrs[i], c.want[i])
				}
			}
		})
	}
}

// TestQueryNameservers_InflightCapDropsQueries verifies the global in-flight
// cap: at the cap every fan-out query is dropped (the level fails fast) and
// no upstream query fires — the last-line guard against query amplification.
func TestQueryNameservers_InflightCapDropsQueries(t *testing.T) {
	var calls atomic.Int64
	client := &fakeNSClient{handlers: map[string]nsScriptHandler{
		"10.0.0.1:53": func(ctx context.Context, msg *dns.Msg) *upstream.Result {
			calls.Add(1)
			return nsReply(msg, dns.RcodeSuccess)
		},
	}}
	r := newTestRecursiveNS(client)
	r.inFlightQueries.Add(config.DefaultMaxRecursiveInflightQueries)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, _, err := r.queryNameserversConcurrent(ctx, []string{"10.0.0.1:53"},
		Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		nil, false, "example.com.", defense.Detector{})

	if err == nil {
		t.Fatal("expected an error when the in-flight cap drops every query")
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("upstream calls = %d, want 0 (the cap must drop queries before they fire)", got)
	}
	if got := r.inFlightQueries.Load(); got != config.DefaultMaxRecursiveInflightQueries {
		t.Fatalf("in-flight counter = %d, want %d (dropped queries must not leak the counter)", got, config.DefaultMaxRecursiveInflightQueries)
	}
}
