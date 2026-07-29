package plain

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"sync"
	"time"
	"zjdns/config"
	"zjdns/internal/ipttl"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/defense"
	socks5 "zjdns/server/upstream/socks5"

	"codeberg.org/miekg/dns"
)

// spoofguardState tracks EDNS-bearing candidates and applies detection logic
// during the multi-read loop.  Connection-agnostic — used by both raw UDP and
// SOCKS5 proxy paths.
type spoofguardState struct {
	prev, last           *dns.Msg
	prevAns, lastAns     int
	rejected, candidates int
	lastRecv             time.Time

	// nonEDNS holds a non-EDNS fallback candidate.  It is only populated
	// when the response carries an authority signal (CNAME chain or AN≥2)
	// that GFW injection does not replicate — GFW injects bare A/AAAA
	// records without CNAMEs.  EDNS-bearing candidates always take
	// precedence; non-EDNS is used only when no EDNS response arrives.
	nonEDNS    *dns.Msg
	nonEDNSAns int

	// TTL values for hopguard learning — stored per candidate.
	lastTTL, prevTTL, nonEDNSTTL uint8

	// copyBuf is reused across processPacket calls within a single
	// multi-read loop, eliminating per-candidate heap allocations.
	copyBuf []byte
}

// spoofguardBufPool reuses 4KB read buffers across spoofguard queries.
// 4096 = standard DNS UDP max payload (RFC 6891 §6.2.5); responses larger
// than 4096 bytes set TC=1 and are truncated, so 4096 is the correct upper
// bound for a single UDP datagram.
var spoofguardBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, pool.RecursiveUDPBufferSize)
		return &b
	},
}

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
	// HopGuard also needs multi-read: reject the GFW fake by TTL mismatch,
	// then keep reading for the real response.
	needMultiRead := server.Spoofguard || server.HopGuard
	if needMultiRead && len(msg.Question) > 0 &&
		(dns.RRToType(msg.Question[0]) == dns.TypeA ||
			dns.RRToType(msg.Question[0]) == dns.TypeAAAA) {
		return c.executeUDPMultiRead(ctx, msg, server, proxyDialer)
	}

	if proxyDialer != nil {
		return c.exchangeViaProxyUDP(ctx, msg, server.Address, proxyDialer)
	}

	response, _, err := c.udpClient.Exchange(ctx, msg, config.ProtoUDP, server.Address)
	return response, err
}

// executeUDPMultiRead performs the spoofguard multi-read detection loop.
// When proxyDialer is nil, uses raw UDP; otherwise routes through SOCKS5.
func (c *Client) executeUDPMultiRead(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, proxyDialer *socks5.Dialer) (*dns.Msg, error) {
	// The caller (EDNS middleware or recursive buildMsg) is responsible for
	// setting EDNS on the query.  We must NOT add a second OPT — the fork
	// handles EDNS transparently via msg.UDPSize, and a duplicate in Extra
	// causes FORMERR from some servers.
	if err := msg.Pack(); err != nil {
		return nil, err
	}

	// ── Connection setup ──────────────────────────────────────────
	var conn net.Conn
	var pconn net.PacketConn
	var buf []byte

	if proxyDialer != nil {
		var err error
		pconn, err = dialProxyUDP(ctx, proxyDialer, server.Address, msg.Data)
		if err != nil {
			return nil, err
		}
		defer func() { _ = pconn.Close() }()
		bufPtr, ok := socks5.ReadPool.Get().(*[]byte)
		if !ok {
			return nil, errors.New("socks5 read pool type error")
		}
		buf = *bufPtr
		// clear() before Put prevents data leakage between reuse cycles.
		defer func() { clear(buf); socks5.ReadPool.Put(bufPtr) }()
	} else {
		var err error
		conn, err = net.Dial("udp", server.Address)
		if err != nil {
			return nil, err
		}
		defer func() { _ = conn.Close() }()
		if _, err := conn.Write(msg.Data); err != nil {
			return nil, err
		}
		bufPtr, ok := spoofguardBufPool.Get().(*[]byte)
		if !ok {
			return nil, errors.New("spoofguard buffer pool type error")
		}
		buf = *bufPtr
		// clear() before Put prevents data leakage between reuse cycles.
		defer func() { clear(buf); spoofguardBufPool.Put(bufPtr) }()
	}

	// ── HopGuard: enable TTL/HopLimit capture on raw UDP conns ──
	var tc *ipttl.Capture
	var hg *defense.HopGuard
	if server.HopGuard && conn != nil {
		hg = c.hopGuard
		udpConn, ok := conn.(*net.UDPConn)
		if !ok {
			return nil, errors.New("plain: unexpected connection type for UDP TTL capture")
		}
		tc = ipttl.New(udpConn)
		if tc == nil {
			if _, warned := c.hopguardWarned.LoadOrStore(server.Address, true); !warned {
				log.Warnf("UPSTREAM: hopguard TTL/HopLimit capture not available on %s", server.Address)
			}
		}
	}

	// ── Multi-read loop ───────────────────────────────────────────
	maxDeadline := time.Now().Add(config.DefaultDNSQueryTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(maxDeadline) {
		maxDeadline = dl
	}

	var sg spoofguardState

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		var n int
		var err error
		var ttl uint8
		if tc != nil { //nolint:gocritic // three-branch read dispatch
			_ = conn.SetReadDeadline(time.Now().Add(config.DefaultSpoofguardPollInterval))
			n, ttl, err = tc.ReadFrom(buf)
		} else if pconn != nil {
			_ = pconn.SetDeadline(time.Now().Add(config.DefaultSpoofguardPollInterval))
			n, _, err = pconn.ReadFrom(buf)
		} else {
			_ = conn.SetDeadline(time.Now().Add(config.DefaultSpoofguardPollInterval))
			n, err = conn.Read(buf)
		}

		if err != nil {
			netErr, ok := errors.AsType[net.Error](err)
			if ok && netErr.Timeout() {
				now := time.Now()
				if sg.last != nil || sg.nonEDNS != nil {
					// Return the best candidate after the collect window expires.
					// After the collect window expires, return the best candidate
					// even if ambiguous — single-answer EDNS responses are common
					// for uncensored domains. The window already waited for a second
					// candidate (potential GFW fake) to compare against.
					if sg.last != nil && now.Sub(sg.lastRecv) > config.DefaultSpoofguardCollectWindow {
						return sg.pickBest(), nil
					}
					// For non-EDNS-only fallback, use the same window.
					if sg.last == nil && sg.nonEDNS != nil && now.Sub(sg.lastRecv) > config.DefaultSpoofguardCollectWindow {
						return sg.pickBest(), nil
					}
					if now.After(maxDeadline) {
						return sg.pickBest(), nil
					}
				} else if now.After(maxDeadline) {
					return nil, errors.New("no UDP response received")
				}
				continue
			}
			if sg.last != nil {
				pool.DefaultMessage.Put(sg.last)
			}
			if sg.prev != nil {
				pool.DefaultMessage.Put(sg.prev)
			}
			if sg.nonEDNS != nil {
				pool.DefaultMessage.Put(sg.nonEDNS)
			}
			return nil, err
		}

		// HopGuard: feed every observed TTL to the histogram so new TTLs
		// after routing changes can be learned. Validate still gates
		// packet acceptance, but recording is decoupled — rejected TTLs
		// accumulate in the histogram and become trusted after decay
		// cycles if they repeat consistently.
		if hg != nil {
			hg.Feed(server.Address, ttl)
		}
		if hg != nil && !hg.Validate(server.Address, ttl) {
			continue
		}

		if n < 12 || uint16(buf[0])<<8|uint16(buf[1]) != msg.ID {
			continue
		}

		// TTL confidence signal for spoofguard: when hopguard is armed
		// and the TTL is trusted, ambiguous EDNS responses can be
		// fast-accepted without waiting for a second candidate.
		ttlConfident := hg != nil && hg.Confident(server.Address)
		if resp := sg.processPacket(buf[:n], n, msg.UDPSize, server.Address, ttlConfident, ttl); resp != nil {
			if hg != nil {
				hg.Feed(server.Address, sg.pickBestTTL())
			}
			return resp, nil
		}
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
	response.ID = msg.ID
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

// copyData returns a byte slice of length n holding a copy of raw[:n],
// reusing s.copyBuf to avoid per-candidate heap allocations in the
// multi-read loop.
func (s *spoofguardState) copyData(raw []byte, n int) []byte {
	if cap(s.copyBuf) < n {
		s.copyBuf = make([]byte, n)
	}
	s.copyBuf = s.copyBuf[:n]
	copy(s.copyBuf, raw[:n])
	return s.copyBuf
}

// processPacket applies EDNS-gate and fast-return checks to a single raw packet.
// Returns a response to return immediately, or nil to continue the loop.
func (s *spoofguardState) processPacket(raw []byte, n int, queryUDPSize uint16, addr string, ttlConfident bool, ttl uint8) *dns.Msg {
	s.lastRecv = time.Now()

	// Fast signals from raw header — check first, before EDNS gate.
	// AN≥2, NS>0, or AD=1 are strong authority signals regardless of
	// whether the server supports EDNS.
	ancount := uint16(raw[6])<<8 | uint16(raw[7])
	nscount := uint16(raw[8])<<8 | uint16(raw[9])
	ad := (raw[3] >> 5) & 1
	hasEDNS := uint16(raw[10])<<8|uint16(raw[11]) > 0
	rcode := int(raw[3] & 0x0F)

	if ancount >= 2 || nscount > 0 || ad == 1 {
		resp := pool.DefaultMessage.Get()
		resp.Data = s.copyData(raw, n)
		if err := resp.Unpack(); err != nil {
			pool.DefaultMessage.Put(resp)
			return nil
		}
		resp.Data = nil
		if s.prev != nil {
			pool.DefaultMessage.Put(s.prev)
		}
		if s.last != nil {
			pool.DefaultMessage.Put(s.last)
		}
		if s.nonEDNS != nil {
			pool.DefaultMessage.Put(s.nonEDNS)
			s.nonEDNS = nil
		}
		log.Debugf("UPSTREAM: UDP spoofguard fast return from %s (AN=%d, NS=%d, AD=%d, EDNS=%v, rejected=%d)", addr, ancount, nscount, ad, hasEDNS, s.rejected)
		s.last = resp
		s.lastTTL = ttl
		return resp
	}

	// Non-NOERROR with no EDNS — accepted as a real server signal.
	if rcode != dns.RcodeSuccess && !hasEDNS {
		log.Debugf("UPSTREAM: UDP spoofguard accepted %s (no-EDNS, real server) from %s", dns.RcodeToString[uint16(rcode)], addr)
	}

	// EDNS-gate: GFW only injects bare A/AAAA records without EDNS and
	// without CNAME chains.  Non-EDNS responses are collected as a fallback
	// only when they contain a CNAME or multiple answers — patterns that
	// GFW does not replicate.  Single-answer non-EDNS (GFW signature) is
	// still rejected.
	if rcode == dns.RcodeSuccess && !hasEDNS && queryUDPSize > 0 {
		resp := pool.DefaultMessage.Get()
		resp.Data = s.copyData(raw, n)
		if err := resp.Unpack(); err != nil {
			pool.DefaultMessage.Put(resp)
			return nil
		}
		resp.Data = nil

		// Only keep non-EDNS responses with CNAME or AN≥2 — these are
		// authoritative patterns GFW doesn't inject (GFW injects single
		// A/AAAA records).
		hasCNAME := false
		for _, rr := range resp.Answer {
			if _, ok := rr.(*dns.CNAME); ok {
				hasCNAME = true
				break
			}
		}
		if !hasCNAME && len(resp.Answer) < 2 {
			s.rejected++
			pool.DefaultMessage.Put(resp)
			log.Debugf("UPSTREAM: UDP spoofguard rejected non-EDNS response #%d from %s", s.rejected, addr)
			return nil
		}

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
	resp := pool.DefaultMessage.Get()
	resp.Data = s.copyData(raw, n)
	if err := resp.Unpack(); err != nil {
		pool.DefaultMessage.Put(resp)
		return nil
	}
	resp.Data = nil

	if ttlConfident {
		if s.prev != nil {
			pool.DefaultMessage.Put(s.prev)
		}
		if s.last != nil {
			pool.DefaultMessage.Put(s.last)
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
	return 0
}

// pickBest returns the best candidate.  EDNS-bearing candidates are always
// preferred; the non-EDNS fallback is only used when no EDNS response arrived
// (e.g. authoritative servers that don't support EDNS).  Non-EDNS fallback
// candidates are only stored if they carry CNAME or AN≥2 — patterns GFW
// injection does not replicate.
func (s *spoofguardState) pickBest() *dns.Msg {
	// No EDNS candidate — fall back to non-EDNS (already validated as
	// CNAME-bearing or multi-answer in processPacket).
	if s.last == nil {
		if s.nonEDNS != nil {
			log.Debugf("UPSTREAM: spoofguard fell back to non-EDNS candidate (ans=%d, rejected=%d)", s.nonEDNSAns, s.rejected)
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
