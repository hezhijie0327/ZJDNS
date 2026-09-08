package resolver

import (
	"context"
	"errors"
	"net"
	"strings"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/pending"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// nsAddrFlightResult is the shared result of one NS-address walk: the
// resolved "ip:port" addresses and the answer records (callers cache them;
// records are treated read-only, matching the glue-record paths).
type nsAddrFlightResult struct {
	addrs  []string
	answer []dns.RR
}

// resolveNSAddrFlight resolves one NS name/qtype pair, deduplicating
// concurrent walks via singleflight.  Unreachable authorities respawn the
// full root walk per level per query; self-similar NS sets multiply the
// tree.  Singleflight bounds concurrent walks to one leader per
// (NS name, qtype); callers with the same key wait for and share the
// result, bounded by their own ctx.
//
// The leader runs under an intrinsic DefaultNSAddrFlightTimeout budget: a
// leader started by a long-budget caller (an earlier CNAME hop's fan-out
// carrying the full DefaultRecursiveQueryTimeout) keeps walking through
// cross-zone NS cycles (huaweicloud-dns.cn → hwclouds-dns.net/.com
// referring to each other) that wedge until the leader's own ctx expires.
// The nested WithTimeout composes — the flight ends at whichever deadline
// is earlier, so the leader still respects a shorter caller budget while
// never running longer than 1s regardless of who started the flight.  The
// result still populates the NS-address cache for later queries.
//
// Cross-name cycles (A's NS addresses need B's walk and vice versa) degrade
// into bounded waits: the nested join becomes a follower, its level ctx
// expires, and the walk continues without those addresses — never a storm.
// A self-referential join (same key from inside the leader's own walk) is
// likewise bounded by ctx, and the bailiwick/in-bailiwick guards in
// resolveNextNameservers make it unreachable in practice.
func (r *Recursive) resolveNSAddrFlight(ctx context.Context, nsName string, qtype uint16, depth int, forceTCP bool) nsAddrFlightResult {
	r.nsAddrFlightOnce.Do(func() {
		r.nsAddrFlight = pending.NewResultGroup[string, nsAddrFlightResult]()
	})
	key := zdnsutil.Canonical(dnsutil.Fqdn(nsName)) + "|" + dns.TypeToString[qtype]
	// _ = error/leader: a follower whose ctx expired gets the zero value;
	// the len(res.addrs) checks below treat it as a miss.
	res, _, _ := r.nsAddrFlight.Do(ctx, key, func(leaderCtx context.Context) (nsAddrFlightResult, error) {
		flightCtx, flightCancel := withEarlierTimeout(leaderCtx, config.DefaultNSAddrFlightTimeout)
		defer flightCancel()
		out := r.nsAddrWalk(flightCtx, nsName, qtype, depth, forceTCP)
		if len(out.addrs) == 0 && len(out.answer) == 0 {
			return nsAddrFlightResult{}, errors.New("ns address walk failed")
		}
		return out, nil
	})
	return res
}

// nsAddrWalk runs the actual walk for one NS name/qtype pair and reduces the
// response to addresses + answer records.
func (r *Recursive) nsAddrWalk(ctx context.Context, nsName string, qtype uint16, depth int, forceTCP bool) nsAddrFlightResult {
	qr := r.resolve(ctx, Question{Name: nsName, Qtype: qtype, Qclass: dns.ClassINET}, nil, depth, forceTCP, true)
	if qr.Err != nil {
		return nsAddrFlightResult{}
	}
	out := nsAddrsFromResult(qr.Answer, qr.Additional, nsName, qtype)
	out.answer = qr.Answer
	return out
}

// nsAddrsFromResult extracts "ip:port" addresses for an NS name from a walk's
// answer section (records matching qtype) plus, for A queries, AAAA glue from
// the additional section.
func nsAddrsFromResult(answer, additional []dns.RR, nsName string, qtype uint16) nsAddrFlightResult {
	var out nsAddrFlightResult
	for _, rrec := range answer {
		switch a := rrec.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				out.addrs = append(out.addrs, net.JoinHostPort(a.A.String(), config.DefaultUDPPort))
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				out.addrs = append(out.addrs, net.JoinHostPort(a.AAAA.String(), config.DefaultUDPPort))
			}
		}
	}
	// For A queries, also collect AAAA glue from Additional.
	if qtype == dns.TypeA {
		for _, rrec := range additional {
			if aaaa, ok := rrec.(*dns.AAAA); ok && strings.EqualFold(aaaa.Header().Name, nsName) {
				out.addrs = append(out.addrs, net.JoinHostPort(aaaa.AAAA.String(), config.DefaultUDPPort))
			}
		}
	}
	return out
}
