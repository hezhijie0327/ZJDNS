package stats

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/miekg/dns"

	"zjdns/cache"
	"zjdns/config"
)

func testConfig() *config.ServerConfig {
	return &config.ServerConfig{
		Server: config.ServerSettings{
			Features: config.FeatureFlags{
				Stats: &config.StatsSettings{Interval: 60},
			},
		},
	}
}

func TestRecordRequest_CounterIncrements(t *testing.T) {
	sc := New(testConfig(), nil)
	if sc == nil {
		t.Fatal("New returned nil")
	}

	tests := []struct {
		name          string
		cacheHit      bool
		hadError      bool
		protocol      string
		rewrote       bool
		hijackDetect  bool
		staleServed   bool
		fallbackUsed  bool
		prefetch      bool
		dnssecStatus  string
		wantCacheHit  uint64
		wantCacheMiss uint64
		wantError     uint64
		wantRewrite   uint64
		wantHijack    uint64
		wantStale     uint64
		wantFallback  uint64
		wantPrefetch  uint64
		wantSecure    uint64
		wantBogus     uint64
		wantInsecure  uint64
	}{
		{name: "cache hit", cacheHit: true, protocol: "UDP", wantCacheHit: 1},
		{name: "cache miss", cacheHit: false, protocol: "UDP", wantCacheMiss: 1},
		{name: "error", cacheHit: true, hadError: true, protocol: "UDP", wantCacheHit: 1, wantError: 1},
		{name: "rewrite", cacheHit: true, rewrote: true, protocol: "UDP", wantCacheHit: 1, wantRewrite: 1},
		{name: "hijack", cacheHit: true, hijackDetect: true, protocol: "UDP", wantCacheHit: 1, wantHijack: 1},
		{name: "stale", cacheHit: true, staleServed: true, protocol: "UDP", wantCacheHit: 1, wantStale: 1},
		{name: "fallback", cacheHit: true, fallbackUsed: true, protocol: "UDP", wantCacheHit: 1, wantFallback: 1},
		{name: "prefetch", cacheHit: true, prefetch: true, protocol: "UDP", wantCacheHit: 1, wantPrefetch: 1},
		{name: "dnssec secure", cacheHit: true, protocol: "UDP", dnssecStatus: "secure", wantCacheHit: 1, wantSecure: 1},
		{name: "dnssec bogus", cacheHit: true, protocol: "UDP", dnssecStatus: "bogus", wantCacheHit: 1, wantBogus: 1},
		{name: "dnssec insecure", cacheHit: true, protocol: "UDP", dnssecStatus: "insecure", wantCacheHit: 1, wantInsecure: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc.Reset()
			sc.RecordRequest(10*time.Millisecond, tt.cacheHit, tt.hadError,
				tt.protocol, tt.rewrote, tt.hijackDetect, tt.staleServed,
				tt.fallbackUsed, tt.prefetch, tt.dnssecStatus, dns.RcodeSuccess)

			snap := sc.Snapshot()
			if snap.TotalRequests != 1 {
				t.Errorf("TotalRequests = %d, want 1", snap.TotalRequests)
			}
			if snap.CacheHits != tt.wantCacheHit {
				t.Errorf("CacheHits = %d, want %d", snap.CacheHits, tt.wantCacheHit)
			}
			if snap.CacheMisses != tt.wantCacheMiss {
				t.Errorf("CacheMisses = %d, want %d", snap.CacheMisses, tt.wantCacheMiss)
			}
			if snap.ErrorResponses != tt.wantError {
				t.Errorf("ErrorResponses = %d, want %d", snap.ErrorResponses, tt.wantError)
			}
			if snap.DNSSECSecure != tt.wantSecure {
				t.Errorf("DNSSECSecure = %d, want %d", snap.DNSSECSecure, tt.wantSecure)
			}
		})
	}
}

func TestRecordRequest_Protocols(t *testing.T) {
	tests := []struct {
		protocol string
		wantKey  func(s Snapshot) uint64
	}{
		{"UDP", func(s Snapshot) uint64 { return s.UDPRequests }},
		{"TCP", func(s Snapshot) uint64 { return s.TCPRequests }},
		{"DOT", func(s Snapshot) uint64 { return s.DoTRequests }},
		{"DOQ", func(s Snapshot) uint64 { return s.DoQRequests }},
		{"DOH", func(s Snapshot) uint64 { return s.DoHRequests }},
		{"DOH3", func(s Snapshot) uint64 { return s.DoH3Requests }},
		{"unknown", func(s Snapshot) uint64 { return s.UDPRequests }},
		{"", func(s Snapshot) uint64 { return s.UDPRequests }},
	}

	for _, tt := range tests {
		t.Run(tt.protocol, func(t *testing.T) {
			sc := New(testConfig(), nil)
			sc.RecordRequest(1*time.Millisecond, false, false, tt.protocol,
				false, false, false, false, false, "", dns.RcodeSuccess)
			snap := sc.Snapshot()
			if got := tt.wantKey(snap); got != 1 {
				t.Errorf("protocol %q: got %d, want 1", tt.protocol, got)
			}
		})
	}
}

func TestSnapshot_Reset(t *testing.T) {
	sc := New(testConfig(), nil)
	sc.RecordRequest(5*time.Millisecond, true, false, "UDP",
		false, false, false, false, false, "secure", dns.RcodeSuccess)

	snap := sc.Snapshot()
	if snap.TotalRequests != 1 {
		t.Fatal("expected 1 request after RecordRequest")
	}

	sc.Reset()
	snap = sc.Snapshot()
	if snap.TotalRequests != 0 {
		t.Errorf("TotalRequests = %d after Reset, want 0", snap.TotalRequests)
	}
	if snap.DNSSECSecure != 0 {
		t.Errorf("DNSSECSecure = %d after Reset, want 0", snap.DNSSECSecure)
	}
}

func TestSnapshot_ResponseTime(t *testing.T) {
	sc := New(testConfig(), nil)
	sc.RecordRequest(123*time.Millisecond, false, false, "UDP",
		false, false, false, false, false, "", dns.RcodeSuccess)
	sc.RecordRequest(77*time.Millisecond, false, false, "UDP",
		false, false, false, false, false, "", dns.RcodeSuccess)

	snap := sc.Snapshot()
	if snap.TotalResponseTimeMs < 199 || snap.TotalResponseTimeMs > 201 {
		t.Errorf("TotalResponseTimeMs = %d, want ~200", snap.TotalResponseTimeMs)
	}
	if avg := snap.AverageResponseTimeMs(); avg < 99 || avg > 101 {
		t.Errorf("AverageResponseTimeMs = %f, want ~100", avg)
	}
}

func TestToCacheEntry_LoadFromCacheEntry_RoundTrip(t *testing.T) {
	sc := New(testConfig(), nil)
	sc.RecordRequest(10*time.Millisecond, true, false, "DoT",
		true, true, true, true, true, "bogus", dns.RcodeSuccess)

	entry, err := sc.ToCacheEntry()
	if err != nil {
		t.Fatalf("ToCacheEntry: %v", err)
	}
	if entry == nil {
		t.Fatal("ToCacheEntry returned nil")
	}

	sc2 := New(testConfig(), nil)
	if err := sc2.LoadFromCacheEntry(entry); err != nil {
		t.Fatalf("LoadFromCacheEntry: %v", err)
	}

	snap := sc2.Snapshot()
	if snap.TotalRequests != 1 {
		t.Errorf("TotalRequests = %d, want 1", snap.TotalRequests)
	}
	if snap.CacheHits != 1 {
		t.Errorf("CacheHits = %d, want 1", snap.CacheHits)
	}
	if snap.DoTRequests != 1 {
		t.Errorf("DoTRequests = %d, want 1", snap.DoTRequests)
	}
	if snap.RewriteRequests != 1 {
		t.Errorf("RewriteRequests = %d, want 1", snap.RewriteRequests)
	}
	if snap.DNSSECBogus != 1 {
		t.Errorf("DNSSECBogus = %d, want 1", snap.DNSSECBogus)
	}
}

func TestBuildStatsLogJSON(t *testing.T) {
	sc := New(testConfig(), nil)
	sc.RecordRequest(50*time.Millisecond, true, false, "DoQ",
		false, false, false, false, false, "secure", dns.RcodeSuccess)

	snap := sc.Snapshot()
	data, err := BuildStatsLogJSON(&snap)
	if err != nil {
		t.Fatalf("BuildStatsLogJSON: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	totals, ok := parsed["totals"].(map[string]any)
	if !ok {
		t.Fatal("missing 'totals' key")
	}
	if totals["cache_hits"].(float64) != 1 {
		t.Error("totals.cache_hits != 1")
	}

	protocols, ok := parsed["protocols"].(map[string]any)
	if !ok {
		t.Fatal("missing 'protocols' key")
	}
	if protocols["doq_requests"].(float64) != 1 {
		t.Error("protocols.doq_requests != 1")
	}

	dnssec, ok := parsed["dnssec"].(map[string]any)
	if !ok {
		t.Fatal("missing 'dnssec' key")
	}
	if dnssec["secure"].(float64) != 1 {
		t.Error("dnssec.secure != 1")
	}

	rates, ok := parsed["rates"].(map[string]any)
	if !ok {
		t.Fatal("missing 'rates' key")
	}
	if rates["dnssec_secure_rate"].(float64) != 1.0 {
		t.Error("dnssec_secure_rate != 1.0")
	}
}

func TestNew_RestoresFromCache(t *testing.T) {
	sc := New(testConfig(), nil)
	sc.RecordRequest(1*time.Millisecond, false, false, "UDP",
		false, false, false, false, false, "", dns.RcodeSuccess)

	entry, _ := sc.ToCacheEntry()
	// Use a simple in-memory store to simulate cache persistence
	mc := cache.New(config.CacheSettings{Size: config.DefaultCacheSize})
	mc.SetEntry(config.StatsPersistKey, entry)

	sc2 := New(testConfig(), mc)
	snap := sc2.Snapshot()
	if snap.TotalRequests != 1 {
		t.Errorf("restored TotalRequests = %d, want 1", snap.TotalRequests)
	}
}

func TestRecordRequest_NilCollector(t *testing.T) {
	var sc *Collector
	// Must not panic
	sc.RecordRequest(1*time.Millisecond, false, false, "UDP",
		false, false, false, false, false, "", dns.RcodeSuccess)
	if snap := sc.Snapshot(); snap.TotalRequests != 0 {
		t.Error("nil collector Snapshot should be empty")
	}
}

func TestFetchStats_Disabled(t *testing.T) {
	var sc *Collector
	_, err := sc.FetchStats()
	if err == nil {
		t.Error("FetchStats on nil should return error")
	}
}
