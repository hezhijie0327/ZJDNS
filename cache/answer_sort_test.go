package cache

import (
	"testing"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func aRRs(ips ...string) []dns.RR {
	out := make([]dns.RR, len(ips))
	for i, ip := range ips {
		out[i] = aRR("x.example.com.", ip)
	}
	return out
}

func TestSortAnswerByLatency_FastestFirst(t *testing.T) {
	latencies := map[string]int{"192.0.2.1": 100, "192.0.2.2": 10, "192.0.2.3": 50}
	answer := aRRs("192.0.2.1", "192.0.2.2", "192.0.2.3")

	sortAnswerByLatency(answer, latencies)

	want := []string{"192.0.2.2", "192.0.2.3", "192.0.2.1"}
	for i, w := range want {
		if got := answer[i].(*dns.A).A.String(); got != w {
			t.Errorf("answer[%d] = %s, want %s", i, got, w)
		}
	}
}

func TestSortAnswerByLatency_UnprobedKeepOrder(t *testing.T) {
	// Only 192.0.2.2 is probed: it moves first, the rest keep relative order.
	latencies := map[string]int{"192.0.2.2": 10}
	answer := aRRs("192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4")

	sortAnswerByLatency(answer, latencies)

	want := []string{"192.0.2.2", "192.0.2.1", "192.0.2.3", "192.0.2.4"}
	for i, w := range want {
		if got := answer[i].(*dns.A).A.String(); got != w {
			t.Errorf("answer[%d] = %s, want %s", i, got, w)
		}
	}
}

func TestSortAnswerByLatency_NoLatencyUnchanged(t *testing.T) {
	answer := aRRs("192.0.2.1", "192.0.2.2", "192.0.2.3")
	orig := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}

	sortAnswerByLatency(answer, map[string]int{})
	sortAnswerByLatency(answer, nil)

	for i, w := range orig {
		if got := answer[i].(*dns.A).A.String(); got != w {
			t.Errorf("answer[%d] = %s, want %s (unchanged)", i, got, w)
		}
	}
}

func TestSortAnswerByLatency_Mixed(t *testing.T) {
	latencies := map[string]int{"192.0.2.1": 30, "192.0.2.2": 10, "192.0.2.3": 40}
	answer := aRRs("192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4")

	sortAnswerByLatency(answer, latencies)

	want := []string{"192.0.2.2", "192.0.2.1", "192.0.2.3", "192.0.2.4"}
	for i, w := range want {
		if got := answer[i].(*dns.A).A.String(); got != w {
			t.Errorf("answer[%d] = %s, want %s", i, got, w)
		}
	}
}

// ── Get integration ──────────────────────────────────────────────────────────

func TestGet_SortedByLatency(t *testing.T) {
	mc := New(0, "")
	defer func() { _ = mc.Close() }()

	mc.Set("x.example.com.", dns.TypeA, dns.ClassINET, nil, false,
		aRRs("192.0.2.1", "192.0.2.2", "192.0.2.3"), nil, nil, false, dns.RcodeSuccess)
	mc.UpdateLatency("192.0.2.1", 50)
	mc.UpdateLatency("192.0.2.2", 5)
	mc.UpdateLatency("192.0.2.3", 25)

	entry, found, _ := mc.Get("x.example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("entry not found")
	}
	want := []string{"192.0.2.2", "192.0.2.3", "192.0.2.1"}
	for i, w := range want {
		if got := entry.Answer[i].(*dns.A).A.String(); got != w {
			t.Errorf("answer[%d] = %s, want %s (latency order)", i, got, w)
		}
	}
}

func TestGet_NonIPTypeUnchanged(t *testing.T) {
	mc := New(0, "")
	defer func() { _ = mc.Close() }()

	txt := &dns.TXT{Hdr: dns.Header{Name: "x.example.com.", Class: dns.ClassINET, TTL: 300}, TXT: rdata.TXT{Txt: []string{"a", "b", "c"}}}
	mc.Set("x.example.com.", dns.TypeTXT, dns.ClassINET, nil, false, []dns.RR{txt}, nil, nil, false, dns.RcodeSuccess)
	mc.UpdateLatency("192.0.2.1", 5)

	entry, found, _ := mc.Get("x.example.com.", dns.TypeTXT, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("entry not found")
	}
	got, ok := entry.Answer[0].(*dns.TXT)
	if len(entry.Answer) != 1 || !ok || len(got.Txt) != 3 {
		t.Error("non-IP answer must be returned unchanged")
	}
}

func TestGet_ExpiredLatencyNotSorted(t *testing.T) {
	mc := New(0, "")
	defer func() { _ = mc.Close() }()

	mc.Set("x.example.com.", dns.TypeA, dns.ClassINET, nil, false,
		aRRs("192.0.2.1", "192.0.2.2"), nil, nil, false, dns.RcodeSuccess)
	// Expired latency: entry must be treated as unprobed, order unchanged.
	mc.latency.Set("192.0.2.2", latencyEntry{value: 5, expiresAt: log.NowUnix() - 1})

	entry, found, _ := mc.Get("x.example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("entry not found")
	}
	if got := entry.Answer[0].(*dns.A).A.String(); got != "192.0.2.1" {
		t.Errorf("answer[0] = %s, want 192.0.2.1 (expired latency must not sort)", got)
	}
}
