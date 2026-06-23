package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server"
	"zjdns/server/resolver"
	"zjdns/server/security"
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
	cfg := config.CacheSettings{Size: config.DefaultCacheSize}
	c := cache.New(cfg)
	defer func() { _ = c.Close() }()

	a := &dns.A{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(192, 0, 2, 1)}
	cacheKey := "bench:www.example.com:1:1:nodnssec"

	b.ResetTimer()
	for b.Loop() {
		c.Set(cacheKey, []dns.RR{a}, nil, nil, false, nil)
		c.Get(cacheKey)
	}
}

func BenchmarkCacheParallel(b *testing.B) {
	disableLogging()
	cfg := config.CacheSettings{Size: config.DefaultCacheSize}
	c := cache.New(cfg)
	defer func() { _ = c.Close() }()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("bench:host%d.example.com:1:1:nodnssec", i%1000)
			a := &dns.A{Hdr: dns.RR_Header{Name: fmt.Sprintf("host%d.example.com.", i), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(192, 0, 2, byte(i%256))}
			c.Set(key, []dns.RR{a}, nil, nil, false, nil)
			c.Get(key)
			i++
		}
	})
}

// benchGenKey is an inline key generator for benchmarks (avoids import cycles).
func benchGenKey(zone string, flags uint16) (*dns.DNSKEY, *ecdsa.PrivateKey) {
	dnskey := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, _ := dnskey.Generate(256)
	return dnskey, priv.(*ecdsa.PrivateKey)
}

func BenchmarkCryptoValidator_VerifyRRset(b *testing.B) {
	disableLogging()
	cv := security.NewCryptoValidator(nil)
	zone := "bench.example.com"
	ksk, priv := benchGenKey(zone, dns.SEP|dns.ZONE)
	a := &dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(192, 0, 2, 1)}
	rrsig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: dns.TypeA, Algorithm: dns.ECDSAP256SHA256, Labels: 3, OrigTtl: 300,
		Expiration: uint32(time.Now().Add(24 * time.Hour).Unix()),
		Inception:  uint32(time.Now().Add(-1 * time.Hour).Unix()),
		KeyTag:     ksk.KeyTag(), SignerName: dns.Fqdn(zone),
	}
	_ = rrsig.Sign(priv, []dns.RR{a})

	b.ResetTimer()
	for b.Loop() {
		_ = cv.VerifyRRset([]dns.RR{a}, rrsig, ksk)
	}
}

func BenchmarkCryptoValidator_VerifyDelegationDS(b *testing.B) {
	disableLogging()
	cv := security.NewCryptoValidator(nil)
	childZone := "child.bench.example.com"
	ksk, _ := benchGenKey(childZone, dns.SEP|dns.ZONE)
	ds := ksk.ToDS(dns.SHA256)

	b.ResetTimer()
	for b.Loop() {
		_, _ = cv.VerifyDelegationDS([]*dns.DS{ds}, []*dns.DNSKEY{ksk})
	}
}

func BenchmarkEDNSApplyToMessage(b *testing.B) {
	disableLogging()
	h, _ := edns.NewHandler(edns.DefaultECSConfig{})
	msg := new(dns.Msg)
	msg.SetQuestion("bench.example.com.", dns.TypeA)
	ecs := &edns.ECSOption{Family: 1, SourcePrefix: 24, Address: net.IPv4(192, 0, 2, 1)}

	b.ResetTimer()
	for b.Loop() {
		m := msg.Copy()
		h.ApplyToMessage(m, ecs, true, false, "", nil)
	}
}

func BenchmarkShuffleSlice(b *testing.B) {
	disableLogging()
	servers := resolver.ShuffleSlice[[]string](nil)
	_ = servers
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
	h, _ := edns.NewHandler(edns.DefaultECSConfig{})
	cfg := &config.ServerConfig{Server: config.ServerSettings{Port: "5353", TLS: config.TLSSettings{Port: "853"}}}
	srv, err := server.New(cfg)
	if err != nil {
		b.Fatalf("server.New: %v", err)
	}
	_ = h
	_ = srv
	// Just benchmark message construction
	q := dns.Question{Name: "bench.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	ecs := &edns.ECSOption{Family: 1, SourcePrefix: 24, Address: net.IPv4(192, 0, 2, 1)}
	b.ResetTimer()
	for b.Loop() {
		msg := new(dns.Msg)
		msg.SetQuestion(q.Name, q.Qtype)
		msg.RecursionDesired = true
		h.ApplyToMessage(msg, ecs, true, false, "", nil)
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

	client := &dns.Client{Timeout: 2 * time.Second, Net: "udp", UDPSize: pool.UDPBufferSize}
	q := dns.Question{Name: ".", Qtype: dns.TypeNS, Qclass: dns.ClassINET}
	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	msg.RecursionDesired = false

	rootServers := []string{
		"198.41.0.4:53", "170.247.170.2:53", "192.33.4.12:53",
		"199.7.91.13:53", "192.203.230.10:53",
	}

	b.ResetTimer()
	for b.Loop() {
		for _, ns := range rootServers {
			resp, _, _ := client.ExchangeContext(ctx, msg, ns)
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
			Port:          "15353",
			LogLevel:      "error",
			MaxConcurrent: 0,
			TLS:           config.TLSSettings{Port: "853"},
			Features: config.FeatureFlags{
				HijackProtection: false,
				DNSSECEnforce:    false,
				Cache:            config.CacheSettings{Size: config.DefaultCacheSize},
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
	req.SetQuestion("bench.local.", dns.TypeA)
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
	req.SetQuestion("bench.local.", dns.TypeA)
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
		// Don't start, just measure construction time
		_ = srv
	}
}
