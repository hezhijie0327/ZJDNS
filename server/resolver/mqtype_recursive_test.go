package resolver

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/server/defense"
	"zjdns/server/resolver/dnssec"
	"zjdns/server/upstream"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// extractChildNS is exercised via these tests: merged-response reuse (NS in
// Authority), dual-zone hosting (NS in Answer), and negative cases.

type fakeAuthoritativeUDP struct {
	conn       *net.UDPConn
	addr       string
	includeNS  bool
	queryCount int32

	mu         sync.Mutex // guards gotMQ/gotTypes/queryTypes (read-loop goroutine vs test)
	gotMQ      bool
	gotTypes   []uint16
	queryTypes []uint16
}

// snapshot returns the recorded query metadata under the lock.
func (f *fakeAuthoritativeUDP) snapshot() (gotMQ bool, gotTypes, queryTypes []uint16) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gotMQ, f.gotTypes, f.queryTypes
}

func nsRecord(name, target string) *dns.NS {
	return &dns.NS{
		Hdr: dns.Header{Name: dnsutil.Fqdn(name), Class: dns.ClassINET, TTL: 300},
		NS:  rdata.NS{Ns: dnsutil.Fqdn(target)},
	}
}

func TestExtractChildNS_AuthoritySection(t *testing.T) {
	resp := &dns.Msg{Ns: []dns.RR{nsRecord("child.example.com", "ns1.child.example.com")}}
	got := extractChildNS("child.example.com", resp)
	if len(got) != 1 || got[0].Ns != "ns1.child.example.com." {
		t.Fatalf("extractChildNS = %v, want 1 NS record", got)
	}
}

func TestExtractChildNS_AnswerSection_DualZoneHosting(t *testing.T) {
	// When the same server hosts parent and child zones, NS may be in Answer.
	resp := &dns.Msg{Answer: []dns.RR{nsRecord("child.example.com", "ns1.child.example.com")}}
	got := extractChildNS("child.example.com", resp)
	if len(got) != 1 {
		t.Fatalf("extractChildNS from Answer = %d records, want 1", len(got))
	}
}

func TestExtractChildNS_MismatchedOwner(t *testing.T) {
	resp := &dns.Msg{Ns: []dns.RR{nsRecord("other.example.com", "ns1.other.example.com")}}
	if got := extractChildNS("child.example.com", resp); len(got) != 0 {
		t.Fatalf("extractChildNS matched wrong owner: %v", got)
	}
}

func TestExtractChildNS_Nil(t *testing.T) {
	if got := extractChildNS("child.example.com", nil); got != nil {
		t.Fatalf("extractChildNS(nil) = %v, want nil", got)
	}
}

// fakeAuthoritativeUDP serves single-question UDP queries on a random local
// port, recording whether the query carried an MQTYPE-Query option.  When
// includeNS is true, the response carries the delegation NS records alongside
// the DS answer (simulating a MQTYPE-capable authority).
func startFakeAuthority(t *testing.T, includeNS bool) *fakeAuthoritativeUDP {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAuthoritativeUDP{conn: conn, addr: conn.LocalAddr().String(), includeNS: includeNS}
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
			atomic.AddInt32(&f.queryCount, 1)
			if len(req.Question) > 0 {
				f.mu.Lock()
				f.queryTypes = append(f.queryTypes, dns.RRToType(req.Question[0]))
				f.mu.Unlock()
			}
			// Record MQTYPE-Query option presence.
			for _, rr := range req.Pseudo {
				if mq, ok := rr.(*dns.MQQUERY); ok {
					f.mu.Lock()
					f.gotMQ = true
					f.gotTypes = mq.Types
					f.mu.Unlock()
				}
			}

			resp := new(dns.Msg)
			dnsutil.SetReply(resp, req)
			resp.Authoritative = true
			// DS answer.
			resp.Answer = []dns.RR{&dns.DS{
				Hdr: dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
				DS:  rdata.DS{KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: "abcdef"},
			}}
			if includeNS {
				// Delegation NS in the Authority section (merged response).
				resp.Ns = []dns.RR{nsRecord(req.Question[0].Header().Name, "ns1."+req.Question[0].Header().Name)}
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

// TestQueryNameserversConcurrent_MQTYPE verifies the MQTYPE-Query option is
// attached to authority queries and the merged response is returned.
func TestQueryNameserversConcurrent_MQTYPE(t *testing.T) {
	f := startFakeAuthority(t, true)

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
	rec := &Recursive{resolver: r}

	question := Question{Name: "child.example.com.", Qtype: dns.TypeDS, Qclass: dns.ClassINET}
	resp, verdict, err := rec.queryNameserversConcurrent(
		context.Background(), []string{f.addr}, question, []uint16{dns.TypeNS}, nil, false, "example.com.", defense.Detector{})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if verdict != defense.VerdictClean {
		t.Errorf("verdict = %v, want clean", verdict)
	}
	gotMQ, gotTypes, _ := f.snapshot()
	if !gotMQ {
		t.Error("authority query did not carry MQTYPE-Query option")
	}
	if len(gotTypes) != 1 || gotTypes[0] != dns.TypeNS {
		t.Errorf("MQTYPE list = %v, want [NS]", gotTypes)
	}
	// Merged response carries both DS (Answer) and NS (Authority).
	ds := dnssec.FindDS(resp.Answer)
	if len(ds) == 0 {
		t.Error("merged response missing DS answer")
	}
	ns := extractChildNS("child.example.com", resp)
	if len(ns) == 0 {
		t.Error("merged response missing delegation NS")
	}
}

// TestResolveChildNameservers_Fallback verifies the RFC 10029 §3.5 fallback:
// when the merged response carries no NS (authority ignored the MQTYPE option
// per RFC 6891), resolveChildNameservers issues a standalone NS query.
func TestResolveChildNameservers_Fallback(t *testing.T) {
	f := startFakeAuthority(t, false) // includeNS=false → merged response has no NS

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
	rec := &Recursive{resolver: r}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Merged response (DS only, no NS) as if returned by the authority.
	merged := new(dns.Msg)
	merged.Answer = []dns.RR{&dns.DS{
		Hdr: dns.Header{Name: "child.example.com.", Class: dns.ClassINET, TTL: 300},
		DS:  rdata.DS{KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: "abcdef"},
	}}

	// NS target resolution will fail (ns1.child.example.com does not exist
	// locally) — the assertion is that the fallback query was ISSUED.
	rec.resolveChildNameservers(ctx, []string{f.addr}, "child.example.com", "example.com.", "www.example.com", nil, false, merged)

	// The fallback issued exactly one standalone NS query (plus the initial
	// DS query in the merged path is not counted — it came from outside).
	if got := atomic.LoadInt32(&f.queryCount); got != 1 {
		t.Fatalf("fallback issued %d queries, want 1 standalone NS query", got)
	}
	_, _, queryTypes := f.snapshot()
	if len(queryTypes) != 1 || queryTypes[0] != dns.TypeNS {
		t.Errorf("fallback query type = %v, want [NS]", queryTypes)
	}
}

// TestResolveChildNameservers_MergedReusesResponse verifies the merged path
// issues NO additional query — NS comes from the passed response.
func TestResolveChildNameservers_MergedReusesResponse(t *testing.T) {
	f := startFakeAuthority(t, true)

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
	rec := &Recursive{resolver: r}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Merged response with the delegation NS in the Authority section.
	merged := new(dns.Msg)
	merged.Ns = []dns.RR{nsRecord("child.example.com", "ns1.child.example.com")}

	rec.resolveChildNameservers(ctx, []string{f.addr}, "child.example.com", "example.com.", "www.example.com", nil, false, merged)

	if got := atomic.LoadInt32(&f.queryCount); got != 0 {
		t.Fatalf("merged path issued %d queries, want 0 (response reused)", got)
	}
}

// TestQueryNameserversConcurrent_NoMQTYPE verifies queries without an MQTYPE
// list carry no option (backward compatibility).
func TestQueryNameserversConcurrent_NoMQTYPE(t *testing.T) {
	f := startFakeAuthority(t, false)

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
	rec := &Recursive{resolver: r}

	question := Question{Name: "child.example.com.", Qtype: dns.TypeDS, Qclass: dns.ClassINET}
	if _, _, err := rec.queryNameserversConcurrent(
		context.Background(), []string{f.addr}, question, nil, nil, false, "example.com.", defense.Detector{}); err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if gotMQ, _, _ := f.snapshot(); gotMQ {
		t.Error("query without MQTYPE list must not carry the option")
	}
}
