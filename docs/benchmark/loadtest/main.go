// benchclient is a multi-protocol DNS load generator for ZJDNS.
//
// It reuses the production upstream.Client — the same code path real
// forwarding/recursive traffic uses — and can drive every protocol the
// server listens on (UDP, TCP, TLS, QUIC, HTTPS, HTTP3, DTLS, TLCP,
// HTTP-TLCP, DTLCP, DNSCrypt).  It exposes its own pprof endpoint so
// client-side profiles (CPU, memory, goroutines, blocking) can be
// captured while the server is profiled on its own endpoint.
//
// Usage:
//
//	go build -o benchclient ./docs/benchmark/loadtest
//	./benchclient -proto quic -addr 127.0.0.1:10784 -workers 32 -seconds 30
//
// See docs/benchmark/LOADTEST.md for the full methodology (server config,
// per-protocol addresses, pprof capture and analysis).
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof" //nolint:gosec // G108: bench tool intentionally exposes pprof
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"zjdns/config"
	"zjdns/server/upstream"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

type counters struct {
	ok     atomic.Int64
	fail   atomic.Int64
	latSum atomic.Int64
	latMax atomic.Int64
	latMin atomic.Int64
}

func (c *counters) init() { c.latMin.Store(1 << 62) }

func main() {
	proto := flag.String("proto", "udp", "protocol: udp tcp tls quic https http3 dtls tlcp http-tlcp dtlcp dnscrypt dnscrypt-tcp")
	addr := flag.String("addr", "127.0.0.1:10533", "server address (full URL for https/http3/http-tlcp)")
	serverName := flag.String("servername", "zjdns-test.local", "TLS ServerName (DNSCrypt: provider name)")
	publicKey := flag.String("public-key", "", "DNSCrypt provider public key (hex)")
	workers := flag.Int("workers", 32, "concurrency")
	seconds := flag.Int("seconds", 30, "duration")
	qname := flag.String("qname", "www.bench.test.", "query name (must match a zone rule)")
	pprofAddr := flag.String("pprof", "127.0.0.1:6061", "client pprof listen address")
	flag.Parse()

	// Enable the block profile (off by default in Go) so
	// /debug/pprof/block shows where queries wait.
	runtime.SetBlockProfileRate(1)
	//nolint:gosec // G114: bench tool pprof endpoint; localhost-only diagnostics
	go func() { _ = http.ListenAndServe(*pprofAddr, nil) }()

	client := upstream.New()
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		<-sig
		cancel()
	}()

	var c counters
	c.init()
	server := &config.UpstreamServer{
		Address:       *addr,
		Protocol:      *proto,
		ServerName:    *serverName,
		SkipTLSVerify: true, // self-signed test certificates
		PublicKey:     *publicKey,
	}

	deadline := time.Now().Add(time.Duration(*seconds) * time.Second)
	var wg sync.WaitGroup
	for range *workers {
		wg.Go(func() {
			for {
				if ctx.Err() != nil || time.Now().After(deadline) {
					return
				}
				msg := new(dns.Msg)
				dnsutil.SetQuestion(msg, *qname, dns.TypeA)
				msg.UDPSize = 1232

				start := time.Now()
				result := client.ExecuteQuery(ctx, msg, server)
				lat := time.Since(start).Microseconds()
				c.latSum.Add(lat)
				for {
					cur := c.latMax.Load()
					if lat <= cur || c.latMax.CompareAndSwap(cur, lat) {
						break
					}
				}
				for {
					cur := c.latMin.Load()
					if lat >= cur || c.latMin.CompareAndSwap(cur, lat) {
						break
					}
				}
				if result.Error == nil && result.Response != nil {
					c.ok.Add(1)
				} else {
					c.fail.Add(1)
					if c.fail.Load() <= 3 {
						fmt.Printf("  ERR: %v\n", result.Error)
					}
				}
			}
		})
	}
	wg.Wait()

	ok := c.ok.Load()
	fail := c.fail.Load()
	elapsed := time.Since(time.Now().Add(-time.Duration(*seconds) * time.Second)).Seconds()
	fmt.Printf("proto=%-10s ok=%-8d fail=%-6d qps=%-10.1f avg=%-8.2fms min=%-8.2fms max=%-8.2fms\n",
		*proto, ok, fail, float64(ok)/elapsed,
		float64(c.latSum.Load())/float64(max(ok, 1))/1000.0,
		float64(c.latMin.Load())/1000.0, float64(c.latMax.Load())/1000.0)
}
