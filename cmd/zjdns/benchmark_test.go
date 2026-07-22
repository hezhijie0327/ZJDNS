package main

import (
	"context"
	"net"
	"testing"
	"time"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
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

// ── Server QPS benchmarks ────────────────────────────────────────────────────

func buildBenchServer(b *testing.B) *server.Server {
	disableLogging()
	b.Helper()

	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			LogLevel: "error",
			Protocol: config.ProtocolSettings{UDP: "15353", TCP: "15353", TLS: "853"},
			Features: config.FeatureFlags{
				DNSSECEnforce: false,
				Cache: config.CacheSettings{
					MaxEntries: config.DefaultMaxCacheEntries,
					Memory: config.CacheMemorySettings{
						Zone:    config.DefaultMemoryCacheZone,
						DNSL1:   config.DefaultMemoryCacheDNSL1,
						Latency: config.DefaultMemoryCacheLatency,
						Ruleset: config.DefaultMemoryCacheRuleset,
					},
				},
			},
		},
		Zone: config.ZoneConfig{Rules: []config.ZoneRule{
			{
				Name: "bench.local",
				Answer: []config.ZoneRecord{
					{Type: dns.TypeA, TTL: 10, Content: "192.0.2.1"},
				},
			},
		}},
	}

	srv, err := server.New(cfg)
	if err != nil {
		b.Fatalf("server.New: %v", err)
	}
	return srv
}

func BenchmarkServerProcessQuery(b *testing.B) {
	srv := buildBenchServer(b)

	req := new(dns.Msg)
	dnsutil.SetQuestion(req, "bench.local.", dns.TypeA)
	req.RecursionDesired = true

	// Warm up cache.
	for range 100 {
		_ = srv.ServeDNS(req, net.IPv4(127, 0, 0, 1), false, "UDP")
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

func BenchmarkServerProcessQuery_Cold(b *testing.B) {
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
		_ = srv.ServeDNS(reqs[0], net.IPv4(127, 0, 0, 1), false, "UDP")
	}

	b.ResetTimer()
	for b.Loop() {
		_ = srv.ServeDNS(reqs[b.N%len(reqs)].Copy(), net.IPv4(127, 0, 0, 1), false, "UDP")
	}
}
