package resolver

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/server/defense"
	"zjdns/server/resolver/dnssec"
	"zjdns/server/upstream"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// fakeNSAuthority serves single-question UDP queries on a random local port,
// answering every name with an A record (and an AAAA record when asked).
// respondMQ simulates an RFC 10029-capable authority (§3.4): it echoes an
// MQTYPE-Response and merges AAAA into the A answer when includeAAAA is set.
// respondMQ=false simulates an authority that ignores the MQTYPE-Query option
// (RFC 6891 / §3.5 fallback).
type fakeNSAuthority struct {
	conn        *net.UDPConn
	addr        string
	respondMQ   bool
	includeAAAA bool
	aQueries    atomic.Int32
	aaaaQueries atomic.Int32
	mqQueries   atomic.Int32 // queries that carried an MQTYPE-Query option

	mu         sync.Mutex // guards gotMQTypes (written by the read-loop goroutine)
	gotMQTypes []uint16
}

// stubCache satisfies cache.Store with no-op methods: getRootServers refuses
// to run with a nil cache, and the NS-address cache must be read (miss) and
// written.  Root addresses come from rootCache, injected directly — A records
// cannot carry a non-53 port, so the root-cache path cannot point at a random
// local port.
type stubCache struct{}

func (s *stubCache) Get(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool) (*cache.Entry, bool, bool) {
	return nil, false, false
}

func (s *stubCache) GetTypes(qname string, qclass uint16, qtypes [2]uint16, dnssecOK bool) (entries [2]*cache.Entry, found, expired [2]bool) {
	return entries, found, expired
}

func (s *stubCache) Set(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool,
	answer, authority, additional []dns.RR, validated bool, rcode uint16,
) int64 {
	return 0
}

func (s *stubCache) LatencyLastProbe(ip string) (int64, bool)            { return 0, false }
func (s *stubCache) ReverseLookup(ip string) []cache.LookupResult        { return nil }
func (s *stubCache) RecordRequest(r *cache.RequestRecord)                {}
func (s *stubCache) UpdateLatency(ip string, latencyMS int)              {}
func (s *stubCache) FlushDB(target string) (int64, error)                { return 0, nil }
func (s *stubCache) Clear() (int64, error)                               { return 0, nil }
func (s *stubCache) PruneQueryJournal(retentionSec int64) (int64, error) { return 0, nil }
func (s *stubCache) Stats() []string                                     { return nil }
func (s *stubCache) Close() error                                        { return nil }

func startFakeNSAuthority(t *testing.T, respondMQ, includeAAAA bool) *fakeNSAuthority {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeNSAuthority{conn: conn, addr: conn.LocalAddr().String(), respondMQ: respondMQ, includeAAAA: includeAAAA}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req := new(dns.Msg)
			req.Data = buf[:n]
			if err := req.Unpack(); err != nil {
				continue
			}
			if len(req.Question) == 0 {
				continue
			}
			qt := dns.RRToType(req.Question[0])
			switch qt {
			case dns.TypeA:
				f.aQueries.Add(1)
			case dns.TypeAAAA:
				f.aaaaQueries.Add(1)
			}

			var mq *dns.MQQUERY
			for _, rr := range req.Pseudo {
				m, ok := rr.(*dns.MQQUERY)
				if !ok {
					continue
				}
				mq = m
				f.mqQueries.Add(1)
				f.mu.Lock()
				f.gotMQTypes = m.Types
				f.mu.Unlock()
			}

			resp := new(dns.Msg)
			dnsutil.SetReply(resp, req)
			resp.Authoritative = true
			name := req.Question[0].Header().Name
			switch qt {
			case dns.TypeA:
				resp.Answer = append(resp.Answer, testARecord(name, "1.2.3.4"))
				if mq != nil && f.respondMQ {
					types := []uint16{}
					if f.includeAAAA {
						resp.Answer = append(resp.Answer, testAAAARecord(name, "2001:db8::1"))
						types = []uint16{dns.TypeAAAA}
					}
					// §3.4: a conforming server returns MQTYPE-Response even
					// when the list is empty.
					resp.Pseudo = append(resp.Pseudo, &dns.MQRESPONSE{Types: types})
				}
			case dns.TypeAAAA:
				resp.Answer = append(resp.Answer, testAAAARecord(name, "2001:db8::1"))
			}
			if err := resp.Pack(); err != nil {
				continue
			}
			_, _ = conn.WriteToUDP(resp.Data, remote)
		}
	}()
	t.Cleanup(func() { _ = conn.Close() })
	return f
}

func testARecord(name, ip string) *dns.A {
	rr := new(dns.A)
	rr.Hdr = dns.Header{Name: dnsutil.Fqdn(name), Class: dns.ClassINET, TTL: 300}
	rr.Addr = netip.AddrFrom4([4]byte(net.ParseIP(ip).To4()))
	return rr
}

func testAAAARecord(name, ip string) *dns.AAAA {
	rr := new(dns.AAAA)
	rr.Hdr = dns.Header{Name: dnsutil.Fqdn(name), Class: dns.ClassINET, TTL: 300}
	rr.Addr = netip.MustParseAddr(ip)
	return rr
}

func newNSAddrTestRecursive(f *fakeNSAuthority) *Recursive {
	ednsHandler, _ := edns.NewHandler(config.ECSConfig{})
	r := &Resolver{
		queryClient: upstream.New(),
		edns:        ednsHandler,
		buildMsg: func(q Question, ecs *edns.ECSOption, rd, secure bool) *dns.Msg {
			msg := new(dns.Msg)
			dnsutil.SetQuestion(msg, dnsutil.Fqdn(q.Name), q.Qtype)
			return msg
		},
		validator: &Validator{
			Crypto:      dnssec.NewCryptoValidator(nil),
			Poisonguard: defense.Detector{},
		},
	}
	rec := &Recursive{resolver: r, cache: &stubCache{}, ctx: context.Background()}
	rec.rootCache = []string{f.addr}
	rec.rootCacheTime = log.NowUnix()
	return rec
}

func resolveNSAddrs(t *testing.T, rec *Recursive, f *fakeNSAuthority) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nsRecords := []*dns.NS{nsRecord("example.com", "ns1.example.com")}
	return rec.resolveNSAddressesConcurrent(ctx, nsRecords, "www.example.com.", 0, false)
}

// TestNSAddrResolution_MergedAAAA verifies the RFC 10029 bundle: the A walk
// carries MQTYPE-Query{AAAA}, the authority merges AAAA into the single
// response, and the AAAA walk is skipped — one authority query per NS name.
// In real networks the A walk's round trips (tens of ms) dwarf goroutine
// scheduling, so the short-circuit almost always wins; the local fake answers
// in microseconds, leaving a scheduling race where the AAAA walk may still
// start in parallel (its result is then dropped, never committed twice).
func TestNSAddrResolution_MergedAAAA(t *testing.T) {
	f := startFakeNSAuthority(t, true, true)
	rec := newNSAddrTestRecursive(f)

	addrs := resolveNSAddrs(t, rec, f)

	if got := f.aaaaQueries.Load(); got > 1 {
		t.Errorf("AAAA walk issued %d queries, want 0 or 1 (merged into A response)", got)
	}
	if got := f.aQueries.Load(); got != 1 {
		t.Errorf("A queries = %d, want 1", got)
	}
	f.mu.Lock()
	gotMQTypes := f.gotMQTypes
	f.mu.Unlock()
	if !slices.Equal(gotMQTypes, []uint16{dns.TypeAAAA}) {
		t.Errorf("MQTYPE-Query list = %v, want [AAAA]", gotMQTypes)
	}
	if !slices.Contains(addrs, net.JoinHostPort("1.2.3.4", config.DefaultUDPPort)) {
		t.Errorf("addrs = %v, missing A address", addrs)
	}
	if !slices.Contains(addrs, net.JoinHostPort("2001:db8::1", config.DefaultUDPPort)) {
		t.Errorf("addrs = %v, missing merged AAAA address", addrs)
	}
}

// TestNSAddrResolution_NoMQTYPEFallback verifies the §3.5 fallback: an
// authority without MQTYPE support ignores the option, so the AAAA walk
// proceeds as a standalone query (two queries, pre-MQTYPE behaviour).
func TestNSAddrResolution_NoMQTYPEFallback(t *testing.T) {
	f := startFakeNSAuthority(t, false, false)
	rec := newNSAddrTestRecursive(f)

	addrs := resolveNSAddrs(t, rec, f)

	if got := f.aQueries.Load(); got != 1 {
		t.Errorf("A queries = %d, want 1", got)
	}
	if got := f.aaaaQueries.Load(); got != 1 {
		t.Errorf("AAAA queries = %d, want 1 (fallback walk)", got)
	}
	if !slices.Contains(addrs, net.JoinHostPort("1.2.3.4", config.DefaultUDPPort)) {
		t.Errorf("addrs = %v, missing A address", addrs)
	}
	if !slices.Contains(addrs, net.JoinHostPort("2001:db8::1", config.DefaultUDPPort)) {
		t.Errorf("addrs = %v, missing fallback AAAA address", addrs)
	}
}

// TestNSAddrResolution_MQNoData verifies that a MQTYPE-capable authority
// reporting an empty list (AAAA absent — NODATA or omitted) skips the AAAA
// walk: the empty MQTYPE-Response is the §3.4 support signal.  Same
// scheduling-race allowance as the merged case above.
func TestNSAddrResolution_MQNoData(t *testing.T) {
	f := startFakeNSAuthority(t, true, false)
	rec := newNSAddrTestRecursive(f)

	addrs := resolveNSAddrs(t, rec, f)

	if got := f.aaaaQueries.Load(); got > 1 {
		t.Errorf("AAAA queries = %d, want 0 or 1 (empty MQTYPE-Response)", got)
	}
	if got := f.aQueries.Load(); got != 1 {
		t.Errorf("A queries = %d, want 1", got)
	}
	if !slices.Contains(addrs, net.JoinHostPort("1.2.3.4", config.DefaultUDPPort)) {
		t.Errorf("addrs = %v, missing A address", addrs)
	}
}
