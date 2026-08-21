package upstream

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"zjdns/config"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// fakeEchoUDPServer answers A queries, echoing the question name — verbatim
// or lowercased (a case-rewriting middlebox) — and records every question
// name it receives, in order.
type fakeEchoUDPServer struct {
	conn      *net.UDPConn
	lowercase bool

	mu       sync.Mutex
	received []string
}

func startFakeEchoUDPServer(tb testing.TB, lowercase bool) (addr string, received func() []string, shutdown func()) {
	tb.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		tb.Fatalf("fake echo server: listen: %v", err)
	}
	srv := &fakeEchoUDPServer{conn: conn, lowercase: lowercase}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
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
			req.Data = nil
			if len(req.Question) == 0 {
				continue
			}

			srv.mu.Lock()
			srv.received = append(srv.received, req.Question[0].Header().Name)
			srv.mu.Unlock()

			resp := dnsutil.SetReply(new(dns.Msg), req)
			resp.Authoritative = true
			qname := req.Question[0].Header().Name
			if lowercase {
				qname = dnsutil.Canonical(qname)
			}
			resp.Question[0].Header().Name = qname
			resp.Answer = []dns.RR{&dns.A{
				Hdr:  dns.Header{Name: qname, Class: dns.ClassINET, TTL: 60},
				Addr: netip.MustParseAddr("192.0.2.1"),
			}}
			if err := resp.Pack(); err != nil {
				continue
			}
			if _, err := conn.WriteToUDP(resp.Data, remote); err != nil {
				return
			}
		}
	}()

	received = func() []string {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		return append([]string(nil), srv.received...)
	}
	shutdown = func() {
		_ = conn.Close()
		<-done
	}
	return conn.LocalAddr().String(), received, shutdown
}

func queryA(name string) *dns.Msg {
	msg := new(dns.Msg)
	msg.ID = 0x1234
	dnsutil.SetQuestion(msg, name, dns.TypeA, dns.ClassINET)
	return msg
}

func TestExecuteQuery_CapsGuard_EchoAccepted(t *testing.T) {
	addr, received, shutdown := startFakeEchoUDPServer(t, false)
	defer shutdown()

	client := New()
	defer client.Close()
	server := &config.UpstreamServer{Address: addr, Protocol: config.ProtoUDP, CapsGuard: true}

	const name = "wWw.BaiDu.CoM"
	res := client.ExecuteQuery(context.Background(), queryA(name+"."), server)
	if res.Error != nil {
		t.Fatalf("ExecuteQuery: %v", res.Error)
	}
	if res.Response == nil {
		t.Fatal("ExecuteQuery returned no response")
	}

	names := received()
	if len(names) != 1 {
		t.Fatalf("expected 1 query, got %d: %v", len(names), names)
	}
	sent := names[0]
	if !strings.EqualFold(sent, name+".") {
		t.Fatalf("sent question %q, want case-insensitive %q", sent, name+".")
	}
	// The served question is byte-identical to what was sent: the 0x20 echo
	// passed verification (a mismatch would have triggered a retry → 2 queries).
	if got := res.Response.Question[0].Header().Name; got != sent {
		t.Fatalf("response question %q != sent question %q", got, sent)
	}
}

func TestExecuteQuery_CapsGuard_MismatchRetried(t *testing.T) {
	addr, received, shutdown := startFakeEchoUDPServer(t, true) // lowercasing middlebox
	defer shutdown()

	client := New()
	defer client.Close()
	server := &config.UpstreamServer{Address: addr, Protocol: config.ProtoUDP, CapsGuard: true}

	// Many letters: P(no flip at all) ≈ 2^-24, so the randomized path runs
	// for all practical purposes; the no-flip branch is still asserted.
	const name = "wWw.BaiDu.CoM.ExAmPle.OrG.CoM.Cn."
	res := client.ExecuteQuery(context.Background(), queryA(name), server)
	if res.Error != nil {
		t.Fatalf("ExecuteQuery: %v", res.Error)
	}
	if res.Response == nil {
		t.Fatal("ExecuteQuery returned no response")
	}

	names := received()
	first := names[0]
	if first == name {
		// Randomization produced no flip — nothing to verify, single query.
		if len(names) != 1 {
			t.Fatalf("no-flip path: expected 1 query, got %d: %v", len(names), names)
		}
		return
	}

	// The mismatched first response was discarded; the retry must use the
	// original case and be served unverified (draft §6.4 baseline).
	if len(names) != 2 {
		t.Fatalf("expected 2 queries (mismatch + retry), got %d: %v", len(names), names)
	}
	if names[1] != name {
		t.Fatalf("retry question %q, want original case %q", names[1], name)
	}
	if got := res.Response.Question[0].Header().Name; got != dnsutil.Canonical(name) {
		t.Fatalf("served question %q, want the retry's (lowercased) echo %q", got, dnsutil.Canonical(name))
	}
}

func TestExecuteQuery_CapsGuard_DisabledSendsOriginalCase(t *testing.T) {
	addr, received, shutdown := startFakeEchoUDPServer(t, false)
	defer shutdown()

	client := New()
	defer client.Close()
	// CapsGuard off (zero value): the question is sent exactly as-is — one
	// query, byte-identical.
	server := &config.UpstreamServer{Address: addr, Protocol: config.ProtoUDP}

	const name = "wWw.BaiDu.CoM."
	res := client.ExecuteQuery(context.Background(), queryA(name), server)
	if res.Error != nil {
		t.Fatalf("ExecuteQuery: %v", res.Error)
	}
	names := received()
	if len(names) != 1 || names[0] != name {
		t.Fatalf("expected a single byte-identical query for %q, got %v", name, names)
	}
	if got := res.Response.Question[0].Header().Name; got != name {
		t.Fatalf("response question %q, want %q", got, name)
	}
}

func TestExecuteQuery_CapsGuard_SharedQuestionRRCopied(t *testing.T) {
	// Regression: the resolver fan-out appends the SAME question RR
	// interface to every worker's message (forward.go / nameserver.go), so
	// concurrent ExecuteQuery calls share one *Header.  CapsGuard must copy
	// the RR before mutating its case — otherwise the two queries
	// overwrite each other's randomized/original name and fail the echo
	// check (observed against real 8.8.8.8 + 1.1.1.1 fan-out).
	addr1, received1, shutdown1 := startFakeEchoUDPServer(t, false)
	defer shutdown1()
	addr2, received2, shutdown2 := startFakeEchoUDPServer(t, false)
	defer shutdown2()

	client := New()
	defer client.Close()

	shared := queryA("wWw.BaiDu.CoM.")
	msg1 := queryA("wWw.BaiDu.CoM.")
	msg2 := queryA("wWw.BaiDu.CoM.")
	// Simulate the fan-out: both messages share the same question RR.
	msg1.Question[0] = shared.Question[0]
	msg2.Question[0] = shared.Question[0]

	server1 := &config.UpstreamServer{Address: addr1, Protocol: config.ProtoUDP, CapsGuard: true}
	server2 := &config.UpstreamServer{Address: addr2, Protocol: config.ProtoUDP, CapsGuard: true}

	ctx := context.Background()
	var wg sync.WaitGroup
	var res1, res2 *Result
	wg.Go(func() { res1 = client.ExecuteQuery(ctx, msg1, server1) })
	wg.Go(func() { res2 = client.ExecuteQuery(ctx, msg2, server2) })
	wg.Wait()

	if res1.Error != nil || res2.Error != nil {
		t.Fatalf("ExecuteQuery errors: %v / %v", res1.Error, res2.Error)
	}
	// Each server must receive exactly one query — a cross-upstream case
	// overwrite would trigger a mismatch retry on one of them.
	if n := len(received1()); n != 1 {
		t.Errorf("server1 queries = %d, want 1 (%v)", n, received1())
	}
	if n := len(received2()); n != 1 {
		t.Errorf("server2 queries = %d, want 1 (%v)", n, received2())
	}
	// Each response echoes its own server's query (the shared RR was never
	// mutated — the original name stays intact for both callers).
	if got := res1.Response.Question[0].Header().Name; got != received1()[0] {
		t.Errorf("server1 response question %q != sent %q", got, received1()[0])
	}
	if got := res2.Response.Question[0].Header().Name; got != received2()[0] {
		t.Errorf("server2 response question %q != sent %q", got, received2()[0])
	}
}

func TestExecuteQuery_CapsGuard_PTRExempt(t *testing.T) {
	// Reverse (PTR) queries skip the echo check: middleboxes such as Cisco
	// DNS guard rewrite reverse-lookup qnames, which would trigger a
	// spurious mismatch on every PTR query (mirrors unbound's exemption).
	// The query still succeeds against a case-rewriting server — single
	// query, no retry.
	addr, received, shutdown := startFakeEchoUDPServer(t, true) // lowercasing middlebox
	defer shutdown()

	client := New()
	defer client.Close()
	server := &config.UpstreamServer{Address: addr, Protocol: config.ProtoUDP, CapsGuard: true}

	msg := new(dns.Msg)
	msg.ID = 0x1234
	dnsutil.SetQuestion(msg, "WwW.168.192.In-Addr.ArPa.", dns.TypePTR, dns.ClassINET)

	res := client.ExecuteQuery(context.Background(), msg, server)
	if res.Error != nil {
		t.Fatalf("ExecuteQuery: %v", res.Error)
	}
	names := received()
	if len(names) != 1 {
		t.Fatalf("PTR: expected 1 query (no echo-check retry), got %d: %v", len(names), names)
	}
}

func TestExecuteQuery_CapsGuard_NoLettersNotRandomized(t *testing.T) {
	addr, received, shutdown := startFakeEchoUDPServer(t, false)
	defer shutdown()

	client := New()
	defer client.Close()
	server := &config.UpstreamServer{Address: addr, Protocol: config.ProtoUDP, CapsGuard: true}

	const name = "12345.67890."
	res := client.ExecuteQuery(context.Background(), queryA(name), server)
	if res.Error != nil {
		t.Fatalf("ExecuteQuery: %v", res.Error)
	}
	names := received()
	if len(names) != 1 || names[0] != name {
		t.Fatalf("expected a single byte-identical query for %q, got %v", name, names)
	}
	if got := res.Response.Question[0].Header().Name; got != name {
		t.Fatalf("response question %q, want %q", got, name)
	}
}
