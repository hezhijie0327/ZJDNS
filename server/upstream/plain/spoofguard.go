// Spoofguard: the UDP multi-read response-validation state machine.
// spoofguardState tracks EDNS-bearing candidates and applies the
// accept/collect/confirm detection logic (see docs/poc/spoofguard and
// AGENTS.md "Defense Mechanisms").

package plain

import (
	"errors"
	"math/rand/v2"
	"time"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
)

// spoofguardState tracks EDNS-bearing candidates and applies detection logic
// during the multi-read loop.  Connection-agnostic — used by both raw UDP and
// SOCKS5 proxy paths.
type spoofguardState struct {
	copyBufShrinkCount   int
	prev, last           *dns.Msg
	prevAns, lastAns     int
	rejected, candidates int
	packets              int // datagrams received this query (window adaptation)
	lastRecv             time.Time

	// nonEDNS holds a non-EDNS fallback candidate.  It is only populated
	// when no EDNS response arrived.  nonEDNSSafe marks candidates whose
	// shape GFW injection does not replicate (CNAME chains) — those can be
	// served directly; a bare single-answer A/AAAA is ambiguous and must be
	// confirmed by a matching re-query before it is served.
	nonEDNS     *dns.Msg
	nonEDNSAns  int
	nonEDNSSafe bool

	// TTL values for hopguard learning — stored per candidate.
	lastTTL, prevTTL, nonEDNSTTL uint8

	// copyBuf is reused across processPacket calls within a single
	// multi-read loop, eliminating per-candidate heap allocations.
	copyBuf []byte
}

// Copy-buffer shrink cadence for spoofguardState.copyBuf (C-L6): after
// copyBufShrinkAfter copies, an oversized buffer (copyBufShrinkFactor× the
// working set, above copyBufShrinkMinCap) is reallocated down.
const (
	copyBufShrinkAfter  = 256
	copyBufShrinkFactor = 4
	copyBufShrinkMinCap = 512
)

// Sentinel errors for the spoofguard/hopguard collect paths — the per-query
// errors.New sites were ~700M allocations on a loaded server; callers only
// check err == nil, so the strings carried no information.
var (
	errQuestionMismatch   = errors.New("plain: pooled UDP response question mismatch")
	errCollectClosed      = errors.New("plain: pooled udp connection closed during spoofguard collect")
	errAmbiguousNoConfirm = errors.New("plain: ambiguous UDP response (single-answer, no EDNS) — no matching confirmation")
	errAmbiguous          = errors.New("plain: ambiguous UDP response (single-answer, no EDNS)")
	errNoResponse         = errors.New("plain: no UDP response received")
)

// matchQuestion reports whether the response echoes the query's question.
func matchQuestion(response, query *dns.Msg) bool {
	if len(response.Question) != 1 || len(query.Question) != 1 {
		return false
	}
	rq := response.Question[0]
	qq := query.Question[0]
	return dns.EqualName(rq.Header().Name, qq.Header().Name) &&
		dns.RRToType(rq) == dns.RRToType(qq) &&
		rq.Header().Class == qq.Header().Class
}

// sameUDPAnswer reports whether two candidate responses carry the same
// answer records (owner, type, and rdata; TTL ignored).  Used to confirm an
// ambiguous single-answer non-EDNS response via a matching re-query — GFW
// fakes vary per packet, while the real server's answer is deterministic.
func sameUDPAnswer(a, b *dns.Msg) bool {
	if a == nil || b == nil || len(a.Answer) != len(b.Answer) {
		return false
	}
	for i := range a.Answer {
		if !sameRRData(a.Answer[i], b.Answer[i]) {
			return false
		}
	}
	return true
}

func sameRRData(x, y dns.RR) bool {
	if x == nil || y == nil {
		return false
	}
	if !dns.EqualName(x.Header().Name, y.Header().Name) || dns.RRToType(x) != dns.RRToType(y) {
		return false
	}
	switch a := x.(type) {
	case *dns.A:
		b, ok := y.(*dns.A)
		return ok && a.A == b.A
	case *dns.AAAA:
		b, ok := y.(*dns.AAAA)
		return ok && a.AAAA == b.AAAA
	case *dns.CNAME:
		b, ok := y.(*dns.CNAME)
		return ok && a.CNAME == b.CNAME
	default:
		return false
	}
}

// collectWindow returns the silence window before returning the best
// candidate: the full window when a second packet could still arrive for
// comparison, the short single-candidate window when only one datagram was
// received (nothing to compare — authorities answer a query once).  Injected
// domains are gated upstream by the TLD poison probe and the poisonguard
// verdict, so the short single-candidate wait keeps that defense intact.
func (s *spoofguardState) collectWindow() time.Duration {
	if s.packets < 2 {
		return config.DefaultSpoofguardSingleWindow
	}
	return config.DefaultSpoofguardCollectWindow
}

// copyData returns a byte slice of length n holding a copy of raw[:n],
// reusing s.copyBuf to avoid per-candidate heap allocations in the
// multi-read loop.
func (s *spoofguardState) copyData(raw []byte, n int) []byte {
	if cap(s.copyBuf) < n {
		s.copyBuf = make([]byte, n)
	}
	s.copyBuf = s.copyBuf[:n]
	copy(s.copyBuf, raw[:n])
	s.copyBufShrinkCount++
	// Copy-buffer shrink cadence: after copyBufShrinkAfter copies, an oversized
	// buffer (4× the working set, ≥512 B floor) is reallocated down (C-L6).
	if s.copyBufShrinkCount >= copyBufShrinkAfter && cap(s.copyBuf) > copyBufShrinkFactor*n && cap(s.copyBuf) > copyBufShrinkMinCap {
		s.copyBuf = make([]byte, n)
		copy(s.copyBuf, raw[:n])
		s.copyBufShrinkCount = 0
	}
	return s.copyBuf
}

// unpackCandidate unpacks raw[:n] into a pooled message, detaching Data
// before return; nil when the wire does not parse.  The five former inline
// copies of this block had already drifted once (U5) (U9).
func (s *spoofguardState) unpackCandidate(raw []byte, n int) *dns.Msg {
	resp := pool.DefaultMessage.Get()
	resp.Data = s.copyData(raw, n)
	if err := resp.Unpack(); err != nil {
		pool.DefaultMessage.Put(resp)
		return nil
	}
	resp.Data = nil
	return resp
}

// processPacket applies EDNS-gate and fast-return checks to a single raw packet.
// Returns a response to return immediately, or nil to continue the loop.
func (s *spoofguardState) processPacket(raw []byte, n int, queryUDPSize uint16, addr string, ttlConfident bool, ttl uint8, spoofguardEnabled bool) *dns.Msg {
	s.packets++
	s.lastRecv = time.Now()

	// Fast signals from raw header — check first, before EDNS gate.
	// AN≥2, NS>0, or AD=1 are strong authority signals regardless of
	// whether the server supports EDNS.
	ancount := uint16(raw[6])<<8 | uint16(raw[7])
	nscount := uint16(raw[8])<<8 | uint16(raw[9])
	ad := (raw[3] >> 5) & 1
	rcode := int(raw[3] & 0x0F)

	if ancount >= 2 || nscount > 0 || ad == 1 {
		resp := s.unpackCandidate(raw, n)
		if resp == nil {
			return nil
		}
		if s.prev != nil {
			pool.DefaultMessage.Put(s.prev)
			s.prev = nil
		}
		if s.last != nil {
			pool.DefaultMessage.Put(s.last)
			s.last = nil
		}
		if s.nonEDNS != nil {
			pool.DefaultMessage.Put(s.nonEDNS)
			s.nonEDNS = nil
		}
		log.Debugf("UPSTREAM: UDP spoofguard fast return from %s (AN=%d, NS=%d, AD=%d, rejected=%d)", addr, ancount, nscount, ad, s.rejected)
		s.last = resp
		s.lastTTL = ttl
		return resp
	}

	// Non-NOERROR response — accepted as a real server signal.
	if rcode != dns.RcodeSuccess {
		log.Debugf("UPSTREAM: UDP spoofguard accepted %s (real server) from %s", dns.RcodeToString[uint16(rcode)], addr)
	}

	// EDNS-gate: GFW only injects bare A/AAAA records without EDNS and
	// without CNAME chains.  Non-EDNS responses are collected as a
	// low-priority fallback — EDNS-bearing candidates always win and the
	// collect window waits for a second candidate, so a real EDNS response
	// beats an injected bare A.  Single-answer non-EDNS is no longer
	// dropped outright: legitimate authorities that don't echo EDNS return
	// that exact shape, and dropping it made every such query block the full
	// query budget (github.com nsone, production incident 2026-08).
	//
	// When spoofguard is disabled (HopGuard-only mode), skip the EDNS gate
	// entirely — HopGuard's TTL validation is the sole filter. The response
	// has already passed HopGuard validation before entering processPacket.
	if rcode == dns.RcodeSuccess && queryUDPSize > 0 {
		if !spoofguardEnabled {
			resp := s.unpackCandidate(raw, n)
			if resp == nil {
				return nil
			}
			s.last = resp
			s.lastTTL = ttl
			return resp
		}
		resp := s.unpackCandidate(raw, n)
		if resp == nil {
			return nil
		}

		// EDNS presence is determined from resp.UDPSize, not raw ARCOUNT
		// (which counts ALL additional records).  This fork's Unpack removes
		// the OPT RR from Extra and folds its options into Pseudo, setting
		// Msg.UDPSize only when an OPT was present — so a bare `*dns.OPT`
		// scan of Extra never matched and the EDNS candidate path was dead.
		hasEDNS := resp.UDPSize > 0
		if hasEDNS {
			// An EDNS response is a legitimate candidate, NOT a spoofguard
			// target — route it into the ambiguous EDNS-bearing handling
			// (fast-accept on TTL confidence or collect). Dropping it here
			// would discard the only response and time the query out.
			return s.collectEDNSCandidate(resp, ttlConfident, ttl, addr)
		}

		// Non-EDNS NOERROR responses (single-answer included) are collected
		// as the low-priority fallback instead of being dropped.  The old
		// gate rejected single-answer non-EDNS as a "GFW injects bare
		// A/AAAA" signature — but legitimate authorities that do not echo
		// EDNS return exactly that shape (e.g. github.com's nsone servers),
		// so every query to them blocked the full 9s budget and SERVFAILed.
		// pickBest still prefers EDNS-bearing candidates and the collect
		// window waits for a second candidate.  A bare single-answer A/AAAA
		// is marked ambiguous (nonEDNSSafe=false): executeUDPCollect only
		// serves it after a matching re-query confirms it (pure-UDP
		// consistency — GFW fakes vary per packet, the real answer is
		// deterministic); CNAME-bearing responses are safe to serve
		// directly (GFW does not inject CNAME chains).
		hasCNAME := false
		for _, rr := range resp.Answer {
			if _, ok := rr.(*dns.CNAME); ok {
				hasCNAME = true
				break
			}
		}
		s.nonEDNSSafe = hasCNAME
		s.rejected++
		if s.nonEDNS != nil {
			pool.DefaultMessage.Put(s.nonEDNS)
		}
		s.nonEDNS = resp
		s.nonEDNSAns = len(resp.Answer)
		s.nonEDNSTTL = ttl
		log.Debugf("UPSTREAM: UDP spoofguard non-EDNS fallback #%d from %s, answer=%d (collecting, waiting for EDNS)", s.rejected, addr, s.nonEDNSAns)
		return nil
	}

	// Ambiguous EDNS-bearing — when TTL is confident, fast-accept
	// instead of collecting. GFW can't simultaneously forge the correct
	// TTL and valid EDNS content; the two signals are orthogonal.
	//
	// When spoofguard is disabled, the response has already passed
	// HopGuard TTL validation — return it directly without candidate
	// collection.
	if !spoofguardEnabled {
		resp := s.unpackCandidate(raw, n)
		if resp == nil {
			return nil
		}
		s.last = resp
		s.lastTTL = ttl
		return resp
	}
	resp := s.unpackCandidate(raw, n)
	if resp == nil {
		return nil
	}
	return s.collectEDNSCandidate(resp, ttlConfident, ttl, addr)
}

// collectEDNSCandidate handles an EDNS-bearing NOERROR response: fast-accept
// when the TTL is confident, otherwise collect as an ambiguous candidate.
// Returns the response to return immediately, or nil to continue the loop.
func (s *spoofguardState) collectEDNSCandidate(resp *dns.Msg, ttlConfident bool, ttl uint8, addr string) *dns.Msg {
	if ttlConfident {
		if s.prev != nil {
			pool.DefaultMessage.Put(s.prev)
			s.prev = nil
		}
		if s.last != nil {
			pool.DefaultMessage.Put(s.last)
			s.last = nil
		}
		if s.nonEDNS != nil {
			pool.DefaultMessage.Put(s.nonEDNS)
			s.nonEDNS = nil
		}
		s.last = resp
		s.lastTTL = ttl
		log.Debugf("UPSTREAM: UDP spoofguard fast-accept from %s (EDNS, TTL trusted, answer=%d)", addr, len(resp.Answer))
		return resp
	}

	s.candidates++
	// A repeated identical answer confirms the server's response — GFW
	// fakes vary per packet while the real answer is deterministic (the
	// same principle as the non-EDNS re-query confirm).  Return
	// immediately instead of waiting out the collect window; a mismatched
	// repeat keeps collecting (the candidate may still be a fake).
	if s.last != nil && sameUDPAnswer(s.last, resp) {
		log.Debugf("UPSTREAM: UDP spoofguard confirmed by identical repeat from %s (answer=%d)", addr, len(resp.Answer))
		pool.DefaultMessage.Put(s.last)
		if s.prev != nil {
			pool.DefaultMessage.Put(s.prev)
			s.prev = nil
		}
		s.last = resp
		s.lastTTL = ttl
		s.lastAns = len(resp.Answer)
		return resp
	}
	if s.prev != nil {
		pool.DefaultMessage.Put(s.prev)
	}
	s.prevTTL = s.lastTTL
	s.prev = s.last
	s.prevAns = s.lastAns
	s.last = resp
	s.lastAns = len(resp.Answer)
	s.lastTTL = ttl
	log.Debugf("UPSTREAM: UDP spoofguard EDNS candidate #%d from %s, answer=%d (ambiguous, collecting more)", s.candidates, addr, s.lastAns)
	return nil
}

// pickBestTTL returns the TTL of the candidate that pickBest would return.
func (s *spoofguardState) pickBestTTL() uint8 {
	if s.last != nil {
		return s.lastTTL
	}
	if s.nonEDNS != nil {
		return s.nonEDNSTTL
	}
	// pickBest prefers the richer prev when last is single-answer — feed
	// the TTL of the record that will actually be served (U16).
	if s.prev != nil {
		return s.prevTTL
	}
	return 0
}

// pickBest returns the best candidate.  EDNS-bearing candidates are always
// preferred; the non-EDNS fallback is only used when no EDNS response arrived
// (e.g. authoritative servers that don't echo EDNS).  The fallback is served
// only after the collect window so a second (EDNS) candidate gets a chance to
// outrank it.
func (s *spoofguardState) pickBest() *dns.Msg {
	// No EDNS candidate — fall back to non-EDNS (already validated as
	// CNAME-bearing or multi-answer in processPacket).
	if s.last == nil {
		if s.nonEDNS != nil {
			log.Debugf("UPSTREAM: spoofguard fell back to non-EDNS candidate (ans=%d, collected=%d)", s.nonEDNSAns, s.rejected)
		}
		return s.nonEDNS
	}
	// EDNS candidates exist — prefer them.  Discard non-EDNS fallback.
	if s.nonEDNS != nil {
		pool.DefaultMessage.Put(s.nonEDNS)
		s.nonEDNS = nil
	}
	if s.prev == nil {
		return s.last
	}
	if s.lastAns == 1 && s.prevAns > 1 {
		log.Debugf("UPSTREAM: spoofguard chose richer prev (ans=%d) over tail (ans=%d)", s.prevAns, s.lastAns)
		pool.DefaultMessage.Put(s.last)
		return s.prev
	}
	if s.prevAns == 1 && s.lastAns > 1 {
		log.Debugf("UPSTREAM: spoofguard chose richer tail (ans=%d) over prev (ans=%d)", s.lastAns, s.prevAns)
		pool.DefaultMessage.Put(s.prev)
		return s.last
	}
	// Equal answer count: pick randomly to avoid deterministic tail-win
	// that a GFW attacker can exploit by delaying their fake response.
	if rand.IntN(2) == 0 { //nolint:gosec // G404: tie-breaking — not cryptographic
		log.Debugf("UPSTREAM: spoofguard chose prev (ans=%d, same richness, random)", s.prevAns)
		pool.DefaultMessage.Put(s.last)
		return s.prev
	}
	log.Debugf("UPSTREAM: spoofguard chose tail (ans=%d, same richness, random)", s.lastAns)
	pool.DefaultMessage.Put(s.prev)
	return s.last
}
