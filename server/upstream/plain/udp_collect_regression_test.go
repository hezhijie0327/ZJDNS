package plain

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
	"zjdns/config"
	"zjdns/internal/lrumap"
	"zjdns/server/defense"
	"zjdns/server/upstream/pool"
	socks5 "zjdns/server/upstream/socks5"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// collectTestServer is a scripted UDP responder for executeUDPCollect
// regression tests.  Modes:
//
//	divergent — every query gets two EDNS answers with fresh nonce IPs
//	            (never equal across packets, so cross-round signature
//	            confirmation can never match);
//	drip      — every query gets a varied nonce answer every 80ms, keeping
//	            the collect window from ever expiring (the S2 attack);
//	single    — one clean EDNS answer with a fixed IP;
//	silent    — no response at all.
type collectTestServer struct {
	pc    *net.UDPConn
	nonce atomic.Uint32
	mode  atomic.Value // string
}

func newCollectTestServer(t *testing.T) *collectTestServer {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &collectTestServer{pc: pc.(*net.UDPConn)}
	s.mode.Store("single")
	t.Cleanup(func() { _ = pc.Close() })
	go s.serve()
	return s
}

func (s *collectTestServer) addr() string { return s.pc.LocalAddr().String() }

func (s *collectTestServer) setMode(mode string) { s.mode.Store(mode) }

func (s *collectTestServer) serve() {
	buf := make([]byte, 4096)
	for {
		n, peer, err := s.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		req := new(dns.Msg)
		req.Data = append(req.Data[:0], buf[:n]...)
		if err := req.Unpack(); err != nil {
			continue
		}
		switch s.mode.Load().(string) {
		case "divergent":
			// Two answers with distinct nonce IPs — an identical repeat
			// would confirm the candidate and serve it immediately.
			for range 2 {
				s.reply(peer, req, s.nonceIP(), 1)
			}
		case "drip":
			go func(peer net.Addr, req *dns.Msg) {
				for range 30 {
					if s.mode.Load().(string) != "drip" {
						return
					}
					s.reply(peer, req, s.nonceIP(), 1)
					time.Sleep(80 * time.Millisecond)
				}
			}(peer, req)
		case "single":
			s.reply(peer, req, netip.MustParseAddr("192.0.2.53"), 1)
		case "silent":
		}
	}
}

// nonceIP builds a fresh unique answer address — answers never repeat, so
// identical-repeat confirmation and cross-round signature matching can
// never succeed against them.
func (s *collectTestServer) nonceIP() netip.Addr {
	v := s.nonce.Add(1)
	return netip.AddrFrom4([4]byte{198, 51, 100, byte(v & 0xFF)}) //nolint:gosec // G115: test nonce, low byte only
}

// reply sends count EDNS A answers for req, each carrying the given IP.
func (s *collectTestServer) reply(peer net.Addr, req *dns.Msg, ip netip.Addr, count int) {
	for range count {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, req)
		resp.Extra = []dns.RR{optRR()}
		resp.Answer = []dns.RR{&dns.A{
			Hdr:  dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 60},
			Addr: ip,
		}}
		if err := resp.Pack(); err != nil {
			return
		}
		if _, err := s.pc.WriteTo(resp.Data, peer); err != nil {
			return
		}
	}
}

// newMaxPipeOneClient builds a Client whose UDP pool allows a single
// in-flight collect slot per conn, so one leaked ExchangeCollect
// registration permanently blocks every later collect on that conn.
func newMaxPipeOneClient(timeout time.Duration) *Client {
	return &Client{
		udpPool: pool.NewUDPPool(1, 1, 1, func(payload []byte) (string, bool) {
			if len(payload) < 2 {
				return "", false
			}
			return string(payload[:2]), true
		}),
		getProxy:       func(*config.UpstreamServer) *socks5.Dialer { return nil },
		timeout:        timeout,
		hopGuard:       defense.NewHopGuard(),
		hopguardWarned: lrumap.New[string, struct{}](8),
	}
}

func collectQueryMsg(name string) *dns.Msg {
	msg := dnsutil.SetQuestion(new(dns.Msg), name, dns.TypeA)
	return msg
}

// TestExecuteUDPCollect_DivergentRoundsReleaseRegistration pins the
// collect-registration pairing across divergent rounds: the round loop
// registers under a fresh matchKey each round, so the previous round's
// registration must be released before the re-query.  With maxPipe=1 a
// single leaked slot makes every later collect block until its context
// deadline — observable as the second query failing.
func TestExecuteUDPCollect_DivergentRoundsReleaseRegistration(t *testing.T) {
	srv := newCollectTestServer(t)
	c := newMaxPipeOneClient(1400 * time.Millisecond)
	server := &config.UpstreamServer{Address: srv.addr(), Protocol: config.ProtoUDP, Spoofguard: true}

	srv.setMode("divergent")
	ctx1, cancel1 := context.WithTimeout(t.Context(), 1400*time.Millisecond)
	defer cancel1()
	_, err := c.executeUDPCollect(ctx1, collectQueryMsg("pair.example.com."), server)
	if err == nil {
		t.Fatal("divergent rounds with no cross-round signature match must not serve an answer")
	}

	// The same pooled conn must still accept a collect query: with the
	// registration released, the single clean answer is served after the
	// 150ms single-datagram window.
	srv.setMode("single")
	start := time.Now()
	ctx2, cancel2 := context.WithTimeout(t.Context(), 1400*time.Millisecond)
	defer cancel2()
	resp, err2 := c.executeUDPCollect(ctx2, collectQueryMsg("pair.example.com."), server)
	if err2 != nil {
		t.Fatalf("second collect query blocked — a divergent round leaked its registration: %v", err2)
	}
	if len(resp.Answer) == 0 {
		t.Fatal("second collect query returned no answer")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("second query took %v — capacity slot was not released by the divergent rounds", elapsed)
	}
}

// TestExecuteUDPCollect_ConnDeathDivergentNotServed pins the conn-death
// branch: when the collect conn dies mid-round, an unconfirmed divergent
// candidate must fail closed (errCollectClosed → TCP fallback) instead of
// being served as a verified answer.
func TestExecuteUDPCollect_ConnDeathDivergentNotServed(t *testing.T) {
	srv := newCollectTestServer(t)
	c := newMaxPipeOneClient(5 * time.Second)
	server := &config.UpstreamServer{Address: srv.addr(), Protocol: config.ProtoUDP, Spoofguard: true}

	// Grab the pooled conn the collect will reuse, then kill it once the
	// divergent candidates have landed (still inside the collect window).
	uc, err := c.acquireUDP(t.Context(), server.Address, "", false, nil)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	srv.setMode("divergent")
	go func() {
		time.Sleep(300 * time.Millisecond)
		c.udpPool.Remove(uc)
	}()

	resp, err := c.executeUDPCollect(t.Context(), collectQueryMsg("conndeath.example.com."), server)
	if err == nil && resp != nil {
		t.Fatalf("conn death must not serve an unconfirmed divergent candidate (got answer %v)", resp.Answer)
	}
	if err != nil && !errors.Is(err, errCollectClosed) {
		t.Logf("conn death returned %v (fail-closed is acceptable)", err)
	}
}

// TestExecuteUDPCollect_DripDeadlineNotServed pins the deadline branch
// under a drip attack: varied answers arriving faster than the collect
// window keep every window alive, so the query reaches its budget with
// divergent candidates still in-window — the deadline must fail closed
// (ambiguous → TCP fallback) rather than serve the last-injected packet.
func TestExecuteUDPCollect_DripDeadlineNotServed(t *testing.T) {
	srv := newCollectTestServer(t)
	c := newMaxPipeOneClient(1500 * time.Millisecond)
	server := &config.UpstreamServer{Address: srv.addr(), Protocol: config.ProtoUDP, Spoofguard: true}

	srv.setMode("drip")
	defer srv.setMode("single")
	ctx, cancel := context.WithTimeout(t.Context(), 1500*time.Millisecond)
	defer cancel()
	resp, err := c.executeUDPCollect(ctx, collectQueryMsg("drip.example.com."), server)
	if err == nil && resp != nil {
		t.Fatalf("deadline under divergent drip must not serve the last packet (got answer %v)", resp.Answer)
	}
}
