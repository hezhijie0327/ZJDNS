package resolver

import (
	"context"
	"errors"
	"net"
	"strings"
	"zjdns/config"
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
// concurrent walks via singleflight.  The old per-walk independence ("the
// NS-address cache deduplicates once populated") exploded when the cache
// NEVER populated: a delegation whose authoritative servers are unreachable
// respawns the full root walk for the same NS names at every level, and
// self-similar NS sets (nsXX.constellix.com ↔ nsXX.constellix.net referring
// to each other) multiply the tree — one client lookup of kernel.org fired
// ~290k UDP queries (2026-08).  One leader walks; concurrent callers with
// the same key wait for and share the result, bounded by their own ctx.
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
	key := dnsutil.Canonical(dnsutil.Fqdn(nsName)) + "|" + dns.TypeToString[qtype]
	// _ = error/leader: a follower whose ctx expired gets the zero value;
	// the len(res.addrs) checks below treat it as a miss.
	res, _, _ := r.nsAddrFlight.Do(ctx, key, func(ctx context.Context) (nsAddrFlightResult, error) {
		out := r.nsAddrWalk(ctx, nsName, qtype, depth, forceTCP)
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
	qr := r.resolve(ctx, Question{Name: nsName, Qtype: qtype, Qclass: dns.ClassINET}, nil, depth, forceTCP)
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
