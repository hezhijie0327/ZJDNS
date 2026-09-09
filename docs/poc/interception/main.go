// Interception-rate rig — measures how reliably ZJDNS's guard stack filters
// injected (poisoned) UDP responses on the forwarding path.
//
// Run with: go run . [-fakes 2] [-delay 25ms] [-fakettl 32] [-realttl 64]
//
// The rig is a DNS "upstream" that answers every query twice: N fake
// responses fired immediately (the GFW empirical shape — bare single-answer
// A, no EDNS, per-packet-varying attacker IPs, correct transaction ID and a
// case-echoed question, stamped with a distinct IP TTL) and the real
// response (EDNS + fixed IP) after -delay with its own IP TTL.  Point a
// forwarding ZJDNS at the rig with the guard combination under test, query
// unique qnames, and count attacker-IP answers (leaked) vs real-IP answers
// (intercepted):
//
//	go build -o /tmp/zjdns ./cmd/zjdns
//	go run ./docs/poc/interception -addr 127.0.0.1:5399 &
//	cat > /tmp/fwd.json <<'JSON'
//	{"server":{"protocol":{"udp":"15353","tcp":"15353"}},
//	 "upstream":[{"address":"127.0.0.1:5399","protocol":"udp",
//	              "spoofguard":true,"hopguard":true,"capsguard":true,"skip_cache":true}]}
//	JSON
//	/tmp/zjdns -config /tmp/fwd.json &
//	ok=0; bad=0; for i in $(seq 1 100); do
//	  a=$(dig +short +time=10 +tries=1 @127.0.0.1 -p 15353 u$i.test A)
//	  case "$a" in 93.184.216.34) ok=$((ok+1));; 66.66.*) bad=$((bad+1));; esac
//	done; echo "intercepted=$ok leaked=$bad"
//
// The fakes vary per packet, so an identical-repeat confirmation never
// matches them; the real answer is deterministic.  With no guard enabled
// the first fake wins the race (baseline leak rate ≈ 100%); each guard and
// combination should drive the leak rate to 0.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/ipv4"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// ttlConn stamps a chosen IP TTL on every WriteTo.
type ttlConn struct {
	net.PacketConn
	pcp *ipv4.PacketConn
	ttl int
}

// realAnswer is the deterministic "truth" the rig serves after the delay.
const realAnswer = "93.184.216.34"

func main() {
	addr := flag.String("addr", "127.0.0.1:5399", "listen address")
	fakes := flag.Int("fakes", 2, "fake responses per query")
	arm := flag.Int("arm", 0, "clean (real-only) queries before injection starts — hopguard learns its TTL baseline from these")
	delay := flag.Duration("delay", 25*time.Millisecond, "real response delay")
	fakeTTL := flag.Int("fakettl", 32, "IP TTL stamped on fake packets")
	realTTL := flag.Int("realttl", 64, "IP TTL stamped on real packets")
	fakeEDNS := flag.Bool("fake-edns", false, "fakes carry an OPT (echoing the query's DO bit) — models an injector beyond the bare non-EDNS GFW shape")
	fakeCase := flag.String("fake-case", "echo", "fake question case: echo (copy the query verbatim) or blind (fixed lowercase — a template injector that never echoes 0x20 case)")
	flag.Parse()

	pc, err := net.ListenPacket("udp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	pcp := ipv4.NewPacketConn(pc)
	fakePC := &ttlConn{PacketConn: pc, pcp: pcp, ttl: *fakeTTL}
	realPC := &ttlConn{PacketConn: pc, pcp: pcp, ttl: *realTTL}

	log.Printf("interception rig listening on %s (fakes=%d arm=%d delay=%v fakeTTL=%d realTTL=%d, truth=%s)",
		*addr, *fakes, *arm, *delay, *fakeTTL, *realTTL, realAnswer)
	buf := make([]byte, 4096)
	var seq int
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			log.Fatal(err)
		}
		q := new(dns.Msg)
		q.Data = buf[:n]
		if err := q.Unpack(); err != nil || len(q.Question) != 1 {
			continue
		}
		seq++
		inject := *fakes
		if seq <= *arm {
			inject = 0
		}
		go answer(fakePC, realPC, src, q, inject, *delay, *fakeEDNS, *fakeCase, seq)
	}
}

func (c *ttlConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if err := c.pcp.SetTTL(c.ttl); err != nil {
		return 0, err
	}
	return c.pcp.WriteTo(b, nil, addr)
}

// answer fires the fakes, waits, then serves the real response.  The fake
// question is the parsed query echoed verbatim — case included — so a 0x20
// randomized outbound question still matches (the strongest forger under
// the model capsguard assumes).
func answer(fakePC, realPC net.PacketConn, src net.Addr, q *dns.Msg, fakes int, delay time.Duration, fakeEDNS bool, fakeCase string, seq int) {
	fakeQname := q.Question[0].Header().Name
	if fakeCase == "blind" {
		fakeQname = strings.ToLower(fakeQname)
	}
	for i := range fakes {
		fake := dnsutil.SetReply(new(dns.Msg), q)
		// The GFW empirical shape carries no OPT — drop the DO bit
		// SetReply copied from the query (the fork's Pack materialises an
		// OPT whenever Security is set).  -fake-edns keeps it to model a
		// stronger injector.
		if !fakeEDNS {
			fake.Security = false
		}
		fake.ID = q.ID
		fake.Question[0].Header().Name = fakeQname
		fake.Answer = []dns.RR{&dns.A{
			Hdr:  dns.Header{Name: fakeQname, Class: dns.ClassINET, TTL: 300},
			Addr: netip.MustParseAddr(fmt.Sprintf("66.66.%d.%d", (seq+i)%250+1, (seq*7+i*13)%250+1)),
		}}
		if err := fake.Pack(); err == nil {
			_, _ = fakePC.WriteTo(fake.Data, src)
		}
	}

	time.Sleep(delay)

	realMsg := dnsutil.SetReply(new(dns.Msg), q)
	realMsg.ID = q.ID
	realMsg.Answer = []dns.RR{&dns.A{
		Hdr:  dns.Header{Name: q.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
		Addr: netip.MustParseAddr(realAnswer),
	}}
	realMsg.Extra = []dns.RR{&dns.OPT{Hdr: dns.Header{Name: ".", Class: dns.ClassINET}}}
	if err := realMsg.Pack(); err == nil {
		_, _ = realPC.WriteTo(realMsg.Data, src)
	}
}
