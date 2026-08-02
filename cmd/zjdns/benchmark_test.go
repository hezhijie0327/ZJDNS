package main

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

func disableLogging() { log.Default.SetLevel(log.Error) }

// ── DNS message-level benchmarks (need server.New) ───────────────────────────

func BenchmarkBuildQueryMessage(b *testing.B) {
	disableLogging()
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{Protocol: config.ProtocolSettings{UDP: "5353", TCP: "5353", TLS: "853"}},
	}
	srv, err := server.New(cfg)
	if err != nil {
		b.Fatalf("server.New: %v", err)
	}
	_ = srv
	q := &dns.A{Hdr: dns.Header{Name: "bench.example.com.", Class: dns.ClassINET}}
	ecs := &config.ECSOption{Family: 1, SourcePrefix: 24, Address: net.IPv4(192, 0, 2, 1)}

	b.ResetTimer()
	for b.Loop() {
		msg := new(dns.Msg)
		dnsutil.SetQuestion(msg, q.Header().Name, dns.RRToType(q))
		msg.RecursionDesired = true
		_ = ecs
	}
}

// ── DNS resolution benchmarks (requires network) ─────────────────────────────

func BenchmarkResolveRootServers(b *testing.B) {
	disableLogging()
	if testing.Short() {
		b.Skip("skipping network benchmark in short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := &dns.Client{
		Transport: &dns.Transport{
			Dialer:       &net.Dialer{Timeout: 2 * time.Second},
			ReadTimeout:  2 * time.Second,
			WriteTimeout: 2 * time.Second,
		},
	}
	q := &dns.NS{Hdr: dns.Header{Name: ".", Class: dns.ClassINET}}
	msg := new(dns.Msg)
	dnsutil.SetQuestion(msg, q.Header().Name, dns.RRToType(q))
	msg.RecursionDesired = false

	rootServers := []string{
		"198.41.0.4:53", "170.247.170.2:53", "192.33.4.12:53",
		"199.7.91.13:53", "192.203.230.10:53",
	}

	b.ResetTimer()
	for b.Loop() {
		for _, ns := range rootServers {
			resp, _, _ := client.Exchange(ctx, msg, "udp", ns)
			if resp != nil {
				break
			}
		}
	}
}

// ── Server builder helpers ───────────────────────────────────────────────────

func buildBenchServer(b *testing.B) *server.Server {
	disableLogging()
	b.Helper()

	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			LogLevel: "error",
			Protocol: config.ProtocolSettings{UDP: "15353", TCP: "15353", TLS: "853"},
			Features: config.FeatureFlags{
				DNSSECEnforce: false,
				Cache:         config.CacheSettings{},
			},
		},
		Zone: []config.ZoneRule{
			{
				Name: "bench.local",
				Answer: []config.ZoneRecord{
					{Type: dns.TypeA, TTL: 10, Content: "192.0.2.1"},
				},
			},
		},
	}

	srv, err := server.New(cfg)
	if err != nil {
		b.Fatalf("server.New: %v", err)
	}
	return srv
}

// buildCacheBenchServer creates a server WITHOUT zone rules so queries traverse
// the full middleware chain (EDNS → CacheLookup). The cache is pre-populated
// with test data so CacheLookup always hits.
func buildCacheBenchServer(b *testing.B) *server.Server {
	disableLogging()
	b.Helper()

	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			LogLevel: "error",
			Protocol: config.ProtocolSettings{UDP: "15353", TCP: "15353", TLS: "853"},
			Features: config.FeatureFlags{
				DNSSECEnforce: false,
				Cache:         config.CacheSettings{},
			},
		},
		// No zone rules — all queries fall through to EDNS → CacheLookup.
	}

	srv, err := server.New(cfg)
	if err != nil {
		b.Fatalf("server.New: %v", err)
	}

	// Pre-populate cache with A records so CacheLookup hits immediately.
	cacheStore := srv.Handler().CacheStore()
	rr := &dns.A{Hdr: dns.Header{Name: "cache-hit.local.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("10.0.0.1")}}
	cacheStore.Set("cache-hit.local.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false, dns.RcodeSuccess)

	return srv
}

// ── Zone-match QPS benchmarks (current baseline) ─────────────────────────────

func BenchmarkServerProcessQuery_ZoneMatch(b *testing.B) {
	srv := buildBenchServer(b)

	req := new(dns.Msg)
	dnsutil.SetQuestion(req, "bench.local.", dns.TypeA)
	req.RecursionDesired = true

	// Warm up cache.
	for range 100 {
		if resp := srv.ServeDNS(req, net.IPv4(127, 0, 0, 1), false, "UDP"); resp != nil {
			pool.DefaultMessage.Put(resp)
		}
	}

	b.ResetTimer()
	b.SetParallelism(8)
	b.RunParallel(func(pb *testing.PB) {
		clientIP := net.IPv4(127, 0, 0, 1)
		for pb.Next() {
			resp := srv.ServeDNS(req.Copy(), clientIP, false, "UDP")
			if resp != nil {
				pool.DefaultMessage.Put(resp)
			}
		}
	})
	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "qps")
}

func BenchmarkServerProcessQuery_ZoneMatch_Cold(b *testing.B) {
	srv := buildBenchServer(b)

	req := new(dns.Msg)
	dnsutil.SetQuestion(req, "bench.local.", dns.TypeA)
	req.RecursionDesired = true

	b.ResetTimer()
	b.SetParallelism(8)
	b.RunParallel(func(pb *testing.PB) {
		clientIP := net.IPv4(127, 0, 0, 1)
		for pb.Next() {
			resp := srv.ServeDNS(req.Copy(), clientIP, false, "UDP")
			if resp != nil {
				pool.DefaultMessage.Put(resp)
			}
		}
	})
	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "qps")
}

// ── Cache-hit QPS benchmarks (EDNS + CacheLookup path) ───────────────────────

func BenchmarkServerProcessQuery_CacheHit(b *testing.B) {
	srv := buildCacheBenchServer(b)

	req := new(dns.Msg)
	dnsutil.SetQuestion(req, "cache-hit.local.", dns.TypeA)
	req.RecursionDesired = true

	// Warm up: ensure cache entries are loaded and pools are warm.
	for range 100 {
		if resp := srv.ServeDNS(req, net.IPv4(127, 0, 0, 1), false, "UDP"); resp != nil {
			pool.DefaultMessage.Put(resp)
		}
	}

	b.ResetTimer()
	b.SetParallelism(8)
	b.RunParallel(func(pb *testing.PB) {
		clientIP := net.IPv4(127, 0, 0, 1)
		for pb.Next() {
			resp := srv.ServeDNS(req.Copy(), clientIP, false, "UDP")
			if resp != nil {
				pool.DefaultMessage.Put(resp)
			}
		}
	})
	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "qps")
}

func BenchmarkServerProcessQuery_CacheHit_Serial(b *testing.B) {
	srv := buildCacheBenchServer(b)

	req := new(dns.Msg)
	dnsutil.SetQuestion(req, "cache-hit.local.", dns.TypeA)
	req.RecursionDesired = true

	// Warm up.
	for range 100 {
		if resp := srv.ServeDNS(req, net.IPv4(127, 0, 0, 1), false, "UDP"); resp != nil {
			pool.DefaultMessage.Put(resp)
		}
	}

	b.ResetTimer()
	for b.Loop() {
		resp := srv.ServeDNS(req.Copy(), net.IPv4(127, 0, 0, 1), false, "UDP")
		if resp != nil {
			pool.DefaultMessage.Put(resp)
		}
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "qps")
}

// ── Raw cache Get benchmark (bypass middleware, measure BadgerDB directly) ────

func BenchmarkCacheStore_Get(b *testing.B) {
	disableLogging()
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			LogLevel: "error",
			Protocol: config.ProtocolSettings{UDP: "15353", TCP: "15353", TLS: "853"},
			Features: config.FeatureFlags{
				DNSSECEnforce: false,
				Cache:         config.CacheSettings{},
			},
		},
	}

	srv, err := server.New(cfg)
	if err != nil {
		b.Fatalf("server.New: %v", err)
	}

	cacheStore := srv.Handler().CacheStore()
	rr := &dns.A{Hdr: dns.Header{Name: "bench.local.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("10.0.0.1")}}
	cacheStore.Set("bench.local.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false, dns.RcodeSuccess)

	b.ResetTimer()
	for b.Loop() {
		cacheStore.Get("bench.local.", dns.TypeA, dns.ClassINET, nil, false)
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "qps")
}

func BenchmarkServerStartup(b *testing.B) {
	disableLogging()
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			LogLevel: "error",
			Protocol: config.ProtocolSettings{UDP: "0", TCP: "0", TLS: "853"},
			Features: config.FeatureFlags{},
		},
	}
	b.ResetTimer()
	for b.Loop() {
		srv, err := server.New(cfg)
		if err != nil {
			b.Fatalf("server.New: %v", err)
		}
		_ = srv
	}
}

// ── Server DNS request through full pipeline (multiple query types) ──────────

func BenchmarkServerDNSRequest_MultipleTypes(b *testing.B) {
	srv := buildBenchServer(b)

	types := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeTXT, dns.TypeNS}
	reqs := make([]*dns.Msg, len(types))
	for i, t := range types {
		reqs[i] = new(dns.Msg)
		dnsutil.SetQuestion(reqs[i], "bench.local.", t)
		reqs[i].RecursionDesired = true
	}

	// Warm cache.
	for range 10 {
		if resp := srv.ServeDNS(reqs[0], net.IPv4(127, 0, 0, 1), false, "UDP"); resp != nil {
			pool.DefaultMessage.Put(resp)
		}
	}

	b.ResetTimer()
	for b.Loop() {
		if resp := srv.ServeDNS(reqs[b.N%len(reqs)].Copy(), net.IPv4(127, 0, 0, 1), false, "UDP"); resp != nil {
			pool.DefaultMessage.Put(resp)
		}
	}
}
