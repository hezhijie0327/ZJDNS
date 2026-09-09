// Spoofguard: the UDP multi-read response-validation state machine.
// spoofguardState tracks EDNS-bearing candidates and applies the
// accept/collect/confirm detection logic (see docs/poc/spoofguard and
// AGENTS.md "Defense Mechanisms").

package plain

import (
	"errors"
	"math/rand/v2"
	"strings"
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

	// confirmed marks that the returned candidate was corroborated by an
	// identical repeat within this round — the strongest corroboration the
	// pure-UDP path has (GFW fakes vary per packet, the real answer is
	// deterministic).  Feed sites consult it: an unarmed hopguard baseline
	// must only learn from corroborated samples.
	confirmed bool

	// divergentEDNS marks that this round collected EDNS candidates whose
	// answers DISAGREE.  Equal-richness divergent candidates make pickBest
	// a coin flip (an EDNS-capable forger ties the real answer), so the
	// window path defers to cross-round confirmation instead of serving
	// the flip outright.
	divergentEDNS bool

	// copyBuf is reused across processPacket calls within a single
	// multi-read loop, eliminating per-candidate heap allocations.
	copyBuf []byte
}

// candidateSig is one divergent candidate carried across collect rounds
// for signature-intersection confirmation.
type candidateSig struct {
	msg *dns.Msg
	ttl uint8
}

// Copy-buffer shrink cadence for spoofguardState.copyBuf: after
// copyBufShrinkAfter copies, an oversized buffer (copyBufShrinkFactor× the
// working set, above copyBufShrinkMinCap) is reallocated down.
const (
	copyBufShrinkAfter  = 256
	copyBufShrinkFactor = 4
	copyBufShrinkMinCap = 512
)

// Sentinel errors for the spoofguard/hopguard collect paths — package-level
// so the per-query hot path never allocates; callers only check err == nil,
// so the strings carry no per-query information.
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
	// buffer (4× the working set, ≥512 B floor) is reallocated down.
	if s.copyBufShrinkCount >= copyBufShrinkAfter && cap(s.copyBuf) > copyBufShrinkFactor*n && cap(s.copyBuf) > copyBufShrinkMinCap {
		s.copyBuf = make([]byte, n)
		copy(s.copyBuf, raw[:n])
		s.copyBufShrinkCount = 0
	}
	return s.copyBuf
}

// unpackCandidate unpacks raw[:n] into a pooled message, detaching Data
// before return; nil when the wire does not parse.
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

// unpackMatching unpacks a candidate and drops it when it does not echo the
// query's question — a misrouted or forged datagram must never enter the
// candidate set, whatever its fast signals say.
func (s *spoofguardState) unpackMatching(raw []byte, n int, query *dns.Msg) *dns.Msg {
	resp := s.unpackCandidate(raw, n)
	if resp == nil {
		return nil
	}
	if !matchQuestion(resp, query) {
		pool.DefaultMessage.Put(resp)
		return nil
	}
	return resp
}

// processPacket applies EDNS-gate and fast-return checks to a single raw packet.
// Returns a response to return immediately, or nil to continue the loop.
func (s *spoofguardState) processPacket(raw []byte, n int, query *dns.Msg, addr string, ttlConfident bool, ttl uint8, spoofguardEnabled bool) *dns.Msg {
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
		resp := s.unpackMatching(raw, n, query)
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

	// HopGuard-only mode with an ARMED baseline: the TTL fingerprint has
	// already gated this packet (Validate ran before processPacket), so the
	// content heuristics are off — return the first matching datagram
	// directly.  While the baseline is still LEARNING, hopguard-only falls
	// through to the full spoofguard discipline below instead: an honest
	// baseline needs corroborated samples, and a first-datagram return under
	// injection would feed the injector's TTL into the histogram 1:1.
	if !spoofguardEnabled && ttlConfident {
		resp := s.unpackMatching(raw, n, query)
		if resp == nil {
			return nil
		}
		// Release prior candidates: the baseline can arm mid-round (a
		// concurrent query's Feed flips Confident between this round's
		// packets), so earlier-collected candidates may be orphaned here.
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
		return resp
	}

	resp := s.unpackMatching(raw, n, query)
	if resp == nil {
		return nil
	}

	// Non-NOERROR responses are server verdicts, not injected answers —
	// route them straight into the EDNS-candidate handling (serve after the
	// silence window).  The empirical injection shapes are NOERROR answers;
	// bare no-EDNS NOERROR shapes get the ambiguity treatment below.
	if rcode != dns.RcodeSuccess {
		return s.collectEDNSCandidate(resp, ttlConfident, ttl, addr)
	}

	// EDNS presence is determined from resp.UDPSize, not raw ARCOUNT
	// (which counts ALL additional records): this fork's Unpack removes
	// the OPT RR from Extra, folds its options into Pseudo, and sets
	// Msg.UDPSize only when an OPT was present.
	hasEDNS := resp.UDPSize > 0
	if hasEDNS {
		// An EDNS response is a legitimate candidate, NOT a spoofguard
		// target — route it into the ambiguous EDNS-bearing handling
		// (fast-accept on TTL confidence or collect). Dropping it here
		// would discard the only response and time the query out.
		return s.collectEDNSCandidate(resp, ttlConfident, ttl, addr)
	}

	// Non-EDNS NOERROR responses (single-answer included) are the
	// low-priority fallback; legitimate authorities that do not echo
	// EDNS return exactly that shape — including every response to a
	// FORMERR-retried non-EDNS query (RFC 6891 §6.2.2).  A bare
	// single-answer A/AAAA is marked ambiguous (nonEDNSSafe=false):
	// executeUDPCollect only serves it after a matching re-query confirms
	// it (pure-UDP consistency — GFW fakes vary per packet, the real answer
	// is deterministic); CNAME-bearing responses are safe to serve
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
		s.confirmed = true
		return resp
	}
	if s.prev != nil {
		pool.DefaultMessage.Put(s.prev)
	}
	if s.last != nil && !sameUDPAnswer(s.last, resp) {
		s.divergentEDNS = true
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

// takeCandidates removes the EDNS candidate slots (prev + last), keying
// each by its answer signature — ownership of every returned message moves
// to the caller.  Used by the divergent-window path: the real answer's
// signature repeats across re-queries, a per-packet-varying forger's never
// does.
func (s *spoofguardState) takeCandidates() map[string]candidateSig {
	out := make(map[string]candidateSig, 2)
	for _, c := range [2]struct {
		msg *dns.Msg
		ttl uint8
	}{{s.prev, s.prevTTL}, {s.last, s.lastTTL}} {
		if c.msg != nil {
			out[answerSignature(c.msg)] = candidateSig{msg: c.msg, ttl: c.ttl}
		}
	}
	s.prev, s.last = nil, nil
	return out
}

// answerSignature formats a candidate's answer section into a comparable
// string (owner, type, rdata — TTL excluded, matching sameRRData).  Only
// called on divergent rounds under active injection; the formatting cost is
// irrelevant there.
func answerSignature(m *dns.Msg) string {
	var b strings.Builder
	for _, rr := range m.Answer {
		b.WriteString(rr.String())
		b.WriteByte('|')
	}
	return b.String()
}

// pickBest returns the best candidate together with its TTL, taking
// ownership of the winner: the winning slot is cleared and the losers are
// returned to the pool, so the caller holds the only remaining reference to
// the returned message.  EDNS-bearing candidates are always preferred; the
// non-EDNS fallback is only used when no EDNS response arrived (e.g.
// authoritative servers that don't echo EDNS).  The fallback is served
// only after the collect window so a second (EDNS) candidate gets a chance to
// outrank it.
func (s *spoofguardState) pickBest() (best *dns.Msg, ttl uint8) {
	// No EDNS candidate — fall back to non-EDNS (already validated as
	// CNAME-bearing or multi-answer in processPacket).
	if s.last == nil {
		if s.nonEDNS == nil {
			return nil, 0
		}
		log.Debugf("UPSTREAM: spoofguard fell back to non-EDNS candidate (ans=%d, collected=%d)", s.nonEDNSAns, s.rejected)
		resp, ttl := s.nonEDNS, s.nonEDNSTTL
		s.nonEDNS = nil
		return resp, ttl
	}
	// EDNS candidates exist — prefer them.  Discard non-EDNS fallback.
	if s.nonEDNS != nil {
		pool.DefaultMessage.Put(s.nonEDNS)
		s.nonEDNS = nil
	}
	if s.prev == nil {
		resp, ttl := s.last, s.lastTTL
		s.last = nil
		return resp, ttl
	}
	if s.lastAns == 1 && s.prevAns > 1 {
		log.Debugf("UPSTREAM: spoofguard chose richer prev (ans=%d) over tail (ans=%d)", s.prevAns, s.lastAns)
		pool.DefaultMessage.Put(s.last)
		s.last = nil
		resp, ttl := s.prev, s.prevTTL
		s.prev = nil
		return resp, ttl
	}
	if s.prevAns == 1 && s.lastAns > 1 {
		log.Debugf("UPSTREAM: spoofguard chose richer tail (ans=%d) over prev (ans=%d)", s.lastAns, s.prevAns)
		pool.DefaultMessage.Put(s.prev)
		s.prev = nil
		resp, ttl := s.last, s.lastTTL
		s.last = nil
		return resp, ttl
	}
	// Equal answer count: pick randomly to avoid deterministic tail-win
	// that a GFW attacker can exploit by delaying their fake response.
	if rand.IntN(2) == 0 { //nolint:gosec // G404: tie-breaking — not cryptographic
		log.Debugf("UPSTREAM: spoofguard chose prev (ans=%d, same richness, random)", s.prevAns)
		pool.DefaultMessage.Put(s.last)
		s.last = nil
		resp, ttl := s.prev, s.prevTTL
		s.prev = nil
		return resp, ttl
	}
	log.Debugf("UPSTREAM: spoofguard chose tail (ans=%d, same richness, random)", s.lastAns)
	pool.DefaultMessage.Put(s.prev)
	s.prev = nil
	resp, ttl := s.last, s.lastTTL
	s.last = nil
	return resp, ttl
}
