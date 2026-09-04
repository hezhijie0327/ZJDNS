package plain

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"time"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/internal/resolv"
	"zjdns/server/defense"
	zpool "zjdns/server/upstream/pool"
	socks5 "zjdns/server/upstream/socks5"

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

// ExecuteUDP sends a DNS query over UDP to the upstream server, optionally
// routing through a SOCKS5 proxy. When server.Spoofguard is true, uses raw
// socket multi-read to capture both GFW-injected fakes and the real response,
// returning the chronologically last (tail) response.
func (c *Client) ExecuteUDP(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	if msg == nil {
		return nil, errors.New("plain: nil query message")
	}
	if server == nil {
		return nil, errors.New("plain: nil server config")
	}
	proxyDialer := c.getProxy(server)

	// GFW only hijacks A/AAAA — skip multi-read for other QTYPEs.
	isAQtype := len(msg.Question) > 0 &&
		(dns.RRToType(msg.Question[0]) == dns.TypeA ||
			dns.RRToType(msg.Question[0]) == dns.TypeAAAA)

	if isAQtype && (server.Spoofguard || server.HopGuard) {
		if c.udpPool != nil {
			// Pooled collect mode — readLoop captures the IP TTL via
			// control messages, so both spoofguard and hopguard run over
			// the pooled sockets (proxy ASSOCIATE sockets included; hopguard
			// TTL capture degrades to unavailable over SOCKS5).
			if resp, err := c.executeUDPCollect(ctx, msg, server); err == nil {
				return resp, nil
			}
			// Pooled collect failed — fall through to pooled single.
		}
	}

	// Pooled path: reuse connected UDP sockets, proxied ASSOCIATE relays
	// included (see pool/udp.go).
	if c.udpPool != nil {
		if resp, err := c.executeUDPPooled(ctx, msg, server); err == nil {
			return resp, nil
		}
	}

	// Pool unavailable or failed — per-query dials.
	if proxyDialer != nil {
		return c.exchangeViaProxyUDP(ctx, msg, server.Address, proxyDialer)
	}

	response, _, err := c.udpClient.Exchange(ctx, msg, config.ProtoUDP, server.Address)
	return response, err
}

// acquireUDP gets a pooled UDP socket for the server, dialing through the
// SOCKS5 proxy when configured.  The pool key includes the proxy so direct
// and proxied sockets never share a relay, and the ASSOCIATE handshake is
// paid once per socket instead of per query.  wantTTL requests IP TTL
// capture on freshly dialed sockets — only hopguard consumes it, so
// spoofguard-only and plain upstreams dial TTL-free sockets.
func (c *Client) acquireUDP(ctx context.Context, addr, proxy string, wantTTL bool, proxyDialer *socks5.Dialer) (*zpool.UDPConn, error) {
	key := addr
	if proxy != "" {
		key = addr + "|" + proxy
	}
	return c.udpPool.Acquire(ctx, key, addr, wantTTL, func(dialCtx context.Context, a string) (net.Conn, error) {
		if proxyDialer != nil {
			return proxyDialer.DialUDP(dialCtx, a)
		}
		var d net.Dialer
		return resolv.Default.DialContext(dialCtx, "udp", a, &d)
	})
}

// executeUDPPooled sends a query over a pooled UDP socket.  The query ID is
// rewritten to a per-socket tracking ID (demultiplexing key); the response is
// verified against the original question before being returned — a misrouted
// datagram (ID collision after wrap-around, or a buggy server echoing a stale
// reply) can never be served as this query's response.
func (c *Client) executeUDPPooled(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	uc, err := c.acquireUDP(ctx, server.Address, server.Proxy, server.HopGuard, c.getProxy(server))
	if err != nil {
		return nil, err
	}

	originalID := msg.ID
	trackingID := uc.NextID()
	msg.ID = trackingID
	// Pack into a pooled buffer — msg.Pack reuses msg.Data's capacity, and
	// Message.Put zeroes Data, so this avoids the per-query pack allocation.
	// The buffer is released only after Exchange has consumed msgData (a
	// concurrent PackQuery would otherwise overwrite the wire in flight).
	packBuf := pool.AcquirePackBuf()
	msg.Data = packBuf
	packErr := msg.Pack()
	msgData := msg.Data
	if packErr != nil {
		pool.ReleasePackBuf(packBuf)
		msg.Data = nil
		msg.ID = originalID
		return nil, packErr
	}
	if cap(msgData) != pool.UDPBufferSize {
		pool.ReleasePackBuf(packBuf) // Pack grew past the class — recycle it, drop the grown buffer
	}
	msg.Data = nil
	msg.ID = originalID

	payload, err := uc.Exchange(ctx, msgData, string([]byte{byte(trackingID >> 8), byte(trackingID)})) //nolint:gosec // G115: DNS ID fits uint16
	pool.ReleasePackBuf(msgData)                                                                       // class-capacity check inside; grown buffers are dropped
	if err != nil {
		if uc.IsDead() {
			c.udpPool.Remove(uc)
		}
		return nil, err
	}

	response := pool.DefaultMessage.Get()
	response.Data = payload
	if err := response.Unpack(); err != nil {
		// Return the pooled payload buffer (M-3-6).
		zpool.ReleaseUDPPayload(payload)
		pool.DefaultMessage.Put(response)
		return nil, err
	}
	response.Data = nil
	// Payload consumed (unpacked, no longer referenced) — return it.
	zpool.ReleaseUDPPayload(payload)
	response.ID = originalID

	// Question verification (RFC 7766 §7 discipline): the routing key was the
	// ID, but a stale/duplicated datagram could carry a matching ID for a
	// different question.
	if !matchQuestion(response, msg) {
		pool.DefaultMessage.Put(response)
		return nil, errQuestionMismatch
	}
	return response, nil
}

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

// executeUDPCollect sends a query over a pooled UDP socket and collects
// multiple responses via the pool's collect mode — the spoofguard state
// machine runs in this goroutine, reusing the pooled connection across
// queries.  HopGuard TTL validation gates the same packets (the pool's
// readLoop captures the IP TTL via control messages); when capture is
// unavailable (e.g. Windows), HopGuard degrades to TTL-less operation.
func (c *Client) executeUDPCollect(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	uc, err := c.acquireUDP(ctx, server.Address, server.Proxy, server.HopGuard, c.getProxy(server))
	if err != nil {
		return nil, err
	}

	// HopGuard: the pooled socket captured TTLs in readLoop — wire the
	// fingerprint gate here.  A nil capture (no control-message support)
	// degrades to spoofguard-only behaviour: TTL=0 passes Validate and
	// never becomes confident.
	var hg *defense.HopGuard
	if server.HopGuard {
		hg = c.hopGuard
		if uc.Capture() == nil {
			// nil capture is the defined degradation (proxy relays, non-unix
			// platforms) — Debug, not Warn: the recursive walk touches one
			// new NS address after another, and a Warn per address floods.
			if _, warned := c.hopguardWarned.LoadOrStore(server.Address, struct{}{}); !warned {
				log.Debugf("UPSTREAM: hopguard TTL/HopLimit capture not available on %s", server.Address)
			}
		}
	}

	originalID := msg.ID
	maxDeadline := time.Now().Add(c.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(maxDeadline) {
		maxDeadline = dl
	}

	// One timer per collect window, Reset per iteration — time.After inside
	// the select allocated a fresh timer every poll (M-3-6).
	pollTimer := time.NewTimer(config.DefaultSpoofguardPollInterval)
	defer pollTimer.Stop()

	// previous holds the best candidate of the prior round when it was
	// ambiguous (a bare single-answer non-EDNS response).  A matching repeat
	// confirms it as the real server's answer — GFW fakes vary per packet
	// while the real answer is deterministic — and an ambiguous response is
	// NEVER served without that confirmation (pure UDP, no TCP fallback).
	var previous *dns.Msg

	for round := 0; ; round++ {
		trackingID := uc.NextID()
		msg.ID = trackingID
		// Pooled pack buffer per round — released after ExchangeCollect's
		// synchronous write (see executeUDPPooled).
		packBuf := pool.AcquirePackBuf()
		msg.Data = packBuf
		packErr := msg.Pack()
		msgData := msg.Data
		if packErr != nil {
			pool.ReleasePackBuf(packBuf)
			msg.Data = nil
			if previous != nil {
				pool.DefaultMessage.Put(previous)
			}
			return nil, packErr
		}
		if cap(msgData) != pool.UDPBufferSize {
			pool.ReleasePackBuf(packBuf) // Pack grew past the class — recycle it, drop the grown buffer
		}
		msg.Data = nil
		msg.ID = originalID

		matchKey := string([]byte{byte(trackingID >> 8), byte(trackingID)}) //nolint:gosec // G115: DNS ID — protocol-bounded uint16
		collectCh, err := uc.ExchangeCollect(ctx, msgData, matchKey)
		pool.ReleasePackBuf(msgData) // class-capacity check inside; grown buffers are dropped
		if err != nil {
			if uc.IsDead() {
				c.udpPool.Remove(uc)
			}
			if previous != nil {
				pool.DefaultMessage.Put(previous)
			}
			return nil, err
		}

		var sg spoofguardState
	collect:
		for {
			select {
			case <-ctx.Done():
				if sg.last != nil {
					pool.DefaultMessage.Put(sg.last)
				}
				if sg.prev != nil {
					pool.DefaultMessage.Put(sg.prev)
				}
				if sg.nonEDNS != nil {
					pool.DefaultMessage.Put(sg.nonEDNS)
				}
				if previous != nil {
					pool.DefaultMessage.Put(previous)
				}
				uc.ReleaseCollect(matchKey)
				return nil, ctx.Err()
			case pkt, ok := <-collectCh:
				if !ok {
					// The conn died mid-collect: return the other candidates
					// to the pool — only sg.last is handed to the caller.
					uc.ReleaseCollect(matchKey)
					if sg.prev != nil {
						pool.DefaultMessage.Put(sg.prev)
					}
					if sg.nonEDNS != nil {
						pool.DefaultMessage.Put(sg.nonEDNS)
					}
					if previous != nil {
						pool.DefaultMessage.Put(previous)
					}
					if sg.last != nil {
						sg.last.ID = originalID // tracking ID must not escape (U5)
						return sg.last, nil
					}
					return nil, errCollectClosed
				}
				// Gate on 12 bytes first — processPacket reads raw[6..9] for
				// the fast-signal checks; a 2-9 byte datagram with a matching
				// ID would index out of range (H9; the multi-read path gates
				// n<12).  ID/length validation also runs BEFORE HopGuard Feed
				// so that stray datagrams never enter the TTL histogram (M1).
				if len(pkt.Data) < 12 || uint16(pkt.Data[0])<<8|uint16(pkt.Data[1]) != trackingID {
					pkt.Release() // M8: every rejected packet returns its tiered buffer
					continue
				}
				// HopGuard: validate gates packet acceptance; Feed happens
				// only after spoofguard accepts the response (below).
				if hg != nil && !hg.Validate(server.Address, pkt.TTL) {
					if hg.ShouldSampleRejected(server.Address) {
						hg.Feed(server.Address, pkt.TTL)
					}
					pkt.Release() // M8
					continue
				}
				ttlConfident := hg != nil && hg.Confident(server.Address) && pkt.TTL != 0
				resp := sg.processPacket(pkt.Data, len(pkt.Data), msg.UDPSize, server.Address, ttlConfident, pkt.TTL, server.Spoofguard)
				pkt.Release()
				if resp != nil {
					// Safe: fast-return (AN≥2/NS>0/AD=1), TTL-confident EDNS,
					// or spoofguard-disabled path.
					if sg.last != nil && sg.last != resp {
						pool.DefaultMessage.Put(sg.last)
					}
					if sg.prev != nil && sg.prev != resp {
						pool.DefaultMessage.Put(sg.prev)
					}
					if sg.nonEDNS != nil && sg.nonEDNS != resp {
						pool.DefaultMessage.Put(sg.nonEDNS)
					}
					if previous != nil {
						pool.DefaultMessage.Put(previous)
					}
					if hg != nil {
						hg.Feed(server.Address, pkt.TTL)
					}
					resp.ID = originalID
					uc.ReleaseCollect(matchKey)
					return resp, nil
				}
			case <-pollTimer.C:
				now := time.Now()
				// Adaptive re-arm: with candidates collected, wake exactly
				// when the silence window expires instead of a fixed 100ms
				// cadence — the fixed poll quantised the 150ms single window
				// to 150-250ms actual waits (avg +50ms per window-bound
				// response).  Window semantics are unchanged: the same
				// silence must still elapse before a candidate is served.
				next := config.DefaultSpoofguardPollInterval
				if sg.last != nil || sg.nonEDNS != nil {
					if remaining := sg.collectWindow() - now.Sub(sg.lastRecv); remaining > 0 && remaining < next {
						next = remaining
					}
				}
				pollTimer.Reset(next)
				if sg.last != nil && now.Sub(sg.lastRecv) > sg.collectWindow() {
					// EDNS candidate — safe, return directly.
					resp := sg.pickBest()
					if hg != nil {
						hg.Feed(server.Address, sg.pickBestTTL())
					}
					if previous != nil {
						pool.DefaultMessage.Put(previous)
					}
					resp.ID = originalID
					uc.ReleaseCollect(matchKey)
					return resp, nil
				}
				if sg.last == nil && sg.nonEDNS != nil && now.Sub(sg.lastRecv) > sg.collectWindow() {
					resp := sg.pickBest()
					uc.ReleaseCollect(matchKey)
					if sg.nonEDNSSafe || sg.rejected <= 1 {
						// CNAME-bearing — GFW does not inject CNAME chains.
						// Or a single clean response: the empirical GFW
						// pattern injects TWO bare fakes per query, so a
						// lone response carries no injection signal and is
						// safe to serve directly (no confirmation re-query
						// latency for legitimate no-EDNS servers).
						if hg != nil {
							hg.Feed(server.Address, sg.pickBestTTL())
						}
						if previous != nil {
							pool.DefaultMessage.Put(previous)
						}
						resp.ID = originalID
						return resp, nil
					}
					// Ambiguous bare single-answer non-EDNS: confirm with a
					// matching re-query before serving (pure UDP).
					if previous != nil && sameUDPAnswer(previous, resp) {
						if hg != nil {
							hg.Feed(server.Address, sg.pickBestTTL())
						}
						pool.DefaultMessage.Put(previous)
						resp.ID = originalID
						return resp, nil
					}
					if previous != nil {
						pool.DefaultMessage.Put(previous)
					}
					previous = resp
					if round+1 >= config.DefaultSpoofguardConfirmRounds || now.After(maxDeadline) {
						pool.DefaultMessage.Put(resp)
						return nil, errAmbiguousNoConfirm
					}
					break collect // re-query in the next round
				}
				if now.After(maxDeadline) {
					resp := sg.pickBest()
					if resp == nil {
						if previous != nil {
							pool.DefaultMessage.Put(previous)
						}
						uc.ReleaseCollect(matchKey)
						return nil, errNoResponse
					}
					if sg.last != nil || sg.nonEDNSSafe || sg.rejected <= 1 {
						if hg != nil {
							hg.Feed(server.Address, sg.pickBestTTL())
						}
						if previous != nil {
							pool.DefaultMessage.Put(previous)
						}
						resp.ID = originalID
						uc.ReleaseCollect(matchKey)
						return resp, nil
					}
					// Ambiguous at the deadline — never serve it.
					pool.DefaultMessage.Put(resp)
					if previous != nil {
						pool.DefaultMessage.Put(previous)
					}
					uc.ReleaseCollect(matchKey)
					return nil, errAmbiguous
				}
			}
		}
	}
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

// exchangeViaProxyUDP sends a DNS query over UDP through a SOCKS5 proxy
// using UDP ASSOCIATE (RFC 1928 §6).
func (c *Client) exchangeViaProxyUDP(ctx context.Context, msg *dns.Msg, addr string, proxyDialer *socks5.Dialer) (*dns.Msg, error) {
	if err := msg.Pack(); err != nil {
		return nil, err
	}

	pconn, err := dialProxyUDP(ctx, proxyDialer, addr, msg.Data)
	if err != nil {
		return nil, err
	}
	defer func() { _ = pconn.Close() }()
	// The ASSOCIATE handshake consumed the dial deadline — restore
	// ctx-bound deadlines or a lost datagram hangs ReadFrom forever.
	stop := context.AfterFunc(ctx, func() { _ = pconn.SetDeadline(time.Now()) })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = pconn.SetDeadline(deadline)
	}

	respBuf, ok := socks5.ReadPool.Get().(*[]byte)
	if !ok {
		return nil, errors.New("socks5 read pool type error")
	}
	defer func() { clear(*respBuf); socks5.ReadPool.Put(respBuf) }()

	n, _, readErr := pconn.ReadFrom(*respBuf)
	if readErr != nil {
		return nil, readErr
	}

	response := pool.DefaultMessage.Get()
	response.Data = (*respBuf)[:n]
	if err := response.Unpack(); err != nil {
		pool.DefaultMessage.Put(response)
		return nil, err
	}
	response.Data = nil
	// Reject ID mismatches like the TCP proxy path — silently rewriting
	// the ID would accept a datagram that belongs to a different query.
	if response.ID != msg.ID {
		pool.DefaultMessage.Put(response)
		return nil, fmt.Errorf("udp proxy response id mismatch: expected %d, got %d", msg.ID, response.ID)
	}
	return response, nil
}

// dialProxyUDP creates a SOCKS5 UDP ASSOCIATE connection and sends the packed
// query to the remote address.
func dialProxyUDP(ctx context.Context, proxyDialer *socks5.Dialer, addr string, packed []byte) (net.PacketConn, error) {
	pconn, err := proxyDialer.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		_ = pconn.Close()
		return nil, err
	}

	if _, err := pconn.WriteTo(packed, remoteAddr); err != nil {
		_ = pconn.Close()
		return nil, err
	}

	return pconn, nil
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
