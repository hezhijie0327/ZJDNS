package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server"
	"zjdns/server/resolver"
	"zjdns/server/security"

	"codeberg.org/miekg/dns"
	dnsutilv2 "codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// disableLogging suppresses log output during benchmarks.
func disableLogging() { log.Default.SetLevel(log.Error) }

// ── Core type benchmarks ─────────────────────────────────────────────────

func BenchmarkPoolMessageGetPut(b *testing.B) {
	disableLogging()
	mp := pool.NewMessagePool()
	b.ResetTimer()
	for b.Loop() {
		msg := mp.Get()
		mp.Put(msg)
	}
}

func BenchmarkPoolBufferGetPut(b *testing.B) {
	disableLogging()
	bp := pool.NewBufferPool(pool.SecureBufferSize, 256)
	b.ResetTimer()
	for b.Loop() {
		buf := bp.Get()
		bp.Put(buf)
	}
}

func BenchmarkCacheSetGet(b *testing.B) {
	disableLogging()
	c, _ := cache.NewSQLiteCache("", config.DefaultMaxCacheEntries, 0, 0)
	defer func() { _ = c.Close() }()

	a := &dns.A{
		Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	}

	b.ResetTimer()
	for b.Loop() {
		c.Set("www.example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{a}, nil, nil, false)
		c.Get("www.example.com.", dns.TypeA, dns.ClassINET, nil, false)
	}
}

func BenchmarkCacheParallel(b *testing.B) {
	disableLogging()
	c, _ := cache.NewSQLiteCache("", config.DefaultMaxCacheEntries, 0, 0)
	defer func() { _ = c.Close() }()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			name := fmt.Sprintf("host%d.example.com.", i%1000)
			a := &dns.A{
				Hdr: dns.Header{Name: fmt.Sprintf("host%d.example.com.", i), Class: dns.ClassINET, TTL: 300},
				A:   rdata.A{Addr: netip.AddrFrom4([4]byte{192, 0, 2, byte(i % 256)})},
			}
			c.Set(name, dns.TypeA, dns.ClassINET, nil, false, []dns.RR{a}, nil, nil, false)
			c.Get(name, dns.TypeA, dns.ClassINET, nil, false)
			i++
		}
	})
}

// benchGenKey is an inline key generator for benchmarks.
func benchGenKey(zone string, flags uint16) (*dns.DNSKEY, *ecdsa.PrivateKey) {
	dnskey := &dns.DNSKEY{
		Hdr:    dns.Header{Name: dnsutilv2.Fqdn(zone), Class: dns.ClassINET, TTL: 3600},
		DNSKEY: rdata.DNSKEY{Flags: flags, Protocol: 3, Algorithm: dns.ECDSAP256SHA256},
	}
	priv, _ := dnskey.Generate(256)
	return dnskey, priv.(*ecdsa.PrivateKey)
}

func BenchmarkCryptoValidator_VerifyRRset(b *testing.B) {
	disableLogging()
	cv := security.NewCryptoValidator(nil)
	zone := "bench.example.com"
	ksk, priv := benchGenKey(zone, dns.FlagSEP|dns.FlagZONE)
	a := &dns.A{
		Hdr: dns.Header{Name: dnsutilv2.Fqdn(zone), Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	}
	rrsig := &dns.RRSIG{
		Hdr: dns.Header{Name: dnsutilv2.Fqdn(zone), Class: dns.ClassINET, TTL: 300},
		RRSIG: rdata.RRSIG{
			TypeCovered: dns.TypeA, Algorithm: dns.ECDSAP256SHA256, Labels: 3, OrigTTL: 300,
			Expiration: uint32(time.Now().Add(24 * time.Hour).Unix()), //nolint:gosec // G115: DNS TTL — protocol-bounded uint32
			Inception:  uint32(time.Now().Add(-1 * time.Hour).Unix()), //nolint:gosec // G115: DNS TTL — protocol-bounded uint32
			KeyTag:     ksk.KeyTag(), SignerName: dnsutilv2.Fqdn(zone),
		},
	}
	_ = rrsig.Sign(priv, []dns.RR{a}, &dns.SignOption{})

	b.ResetTimer()
	for b.Loop() {
		_ = cv.VerifyRRset([]dns.RR{a}, rrsig, ksk)
	}
}

func BenchmarkCryptoValidator_VerifyDelegationDS(b *testing.B) {
	disableLogging()
	cv := security.NewCryptoValidator(nil)
	childZone := "child.bench.example.com"
	ksk, _ := benchGenKey(childZone, dns.FlagSEP|dns.FlagZONE)
	ds := ksk.ToDS(dns.SHA256)

	b.ResetTimer()
	for b.Loop() {
		_, _ = cv.VerifyDelegationDS([]*dns.DS{ds}, []*dns.DNSKEY{ksk})
	}
}

func BenchmarkEDNSApplyToMessage(b *testing.B) {
	disableLogging()
	h, _ := edns.NewHandler(config.ECSConfig{})
	msg := new(dns.Msg)
	dnsutilv2.SetQuestion(msg, "bench.example.com.", dns.TypeA)
	ecs := &edns.ECSOption{Family: 1, SourcePrefix: 24, Address: net.IPv4(192, 0, 2, 1)}

	b.ResetTimer()
	for b.Loop() {
		m := msg.Copy()
		h.ApplyToMessage(m, ecs, false, "", nil, false, true, 0)
	}
}

func BenchmarkShuffleSlice(b *testing.B) {
	disableLogging()
	s := make([]string, 13)
	for i := range s {
		s[i] = fmt.Sprintf("ns%d.example.com:53", i)
	}
	b.ResetTimer()
	for b.Loop() {
		_ = resolver.ShuffleSlice(s)
	}
}

// ── DNS message-level benchmarks ──────────────────────────────────────────

func BenchmarkBuildQueryMessage(b *testing.B) {
	disableLogging()
	h, _ := edns.NewHandler(config.ECSConfig{})
	cfg := &config.ServerConfig{Server: config.ServerSettings{Port: "5353", TLS: config.TLSSettings{Port: "853"}}}
	srv, err := server.New(cfg)
	if err != nil {
		b.Fatalf("server.New: %v", err)
	}
	_ = h
	_ = srv
	q := &dns.A{Hdr: dns.Header{Name: "bench.example.com.", Class: dns.ClassINET}}
	ecs := &edns.ECSOption{Family: 1, SourcePrefix: 24, Address: net.IPv4(192, 0, 2, 1)}
	b.ResetTimer()
	for b.Loop() {
		msg := new(dns.Msg)
		dnsutilv2.SetQuestion(msg, q.Header().Name, dns.RRToType(q))
		msg.RecursionDesired = true
		h.ApplyToMessage(msg, ecs, false, "", nil, true, true, 0)
	}
}

// ── DNS resolution benchmarks (requires network) ──────────────────────────

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
	dnsutilv2.SetQuestion(msg, q.Header().Name, dns.RRToType(q))
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

// ── Server QPS benchmarks ─────────────────────────────────────────────────

// buildBenchServer creates a fully initialized (but not started) Server
// suitable for benchmarking the query processing pipeline directly.
func buildBenchServer(b *testing.B) *server.Server {
	disableLogging()
	b.Helper()

	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			Port:     "15353",
			LogLevel: "error",
			TLS:      config.TLSSettings{Port: "853"},
			Features: config.FeatureFlags{
				HijackProtection: false,
				DNSSECEnforce:    false,
				Cache:            config.CacheSettings{MaxEntries: config.DefaultMaxCacheEntries},
			},
		},
		Rewrite: []config.RewriteRule{
			{
				Name: "bench.local",
				Records: []config.DNSRecordConfig{
					{Type: "A", TTL: 10, Content: "192.0.2.1"},
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

// BenchmarkServerProcessQuery measures the pure query processing throughput
// (no network I/O). It benchmarks cache-hit responses through the full
// processDNSQuery pipeline by calling ServeDNS directly.
func BenchmarkServerProcessQuery(b *testing.B) {
	srv := buildBenchServer(b)

	req := new(dns.Msg)
	dnsutilv2.SetQuestion(req, "bench.local.", dns.TypeA)
	req.RecursionDesired = true

	// Warm up cache
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
				pool.DefaultMessagePool.Put(resp)
			}
		}
	})
	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "qps")
}

// BenchmarkServerProcessQuery_Cold measures cold-query throughput (no
// pre-warmed cache, rewrite rule responses only).
func BenchmarkServerProcessQuery_Cold(b *testing.B) {
	srv := buildBenchServer(b)

	req := new(dns.Msg)
	dnsutilv2.SetQuestion(req, "bench.local.", dns.TypeA)
	req.RecursionDesired = true

	b.ResetTimer()
	b.SetParallelism(8)
	b.RunParallel(func(pb *testing.PB) {
		clientIP := net.IPv4(127, 0, 0, 1)
		for pb.Next() {
			resp := srv.ServeDNS(req.Copy(), clientIP, false, "UDP")
			if resp != nil {
				pool.DefaultMessagePool.Put(resp)
			}
		}
	})
	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "qps")
}

// BenchmarkServerStartup measures cold-start time for the DNS server.
func BenchmarkServerStartup(b *testing.B) {
	disableLogging()
	cfg := &config.ServerConfig{
		Server: config.ServerSettings{
			Port:     "0", // ephemeral port
			LogLevel: "error",
			TLS:      config.TLSSettings{Port: "853"},
			Features: config.FeatureFlags{HijackProtection: false},
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
