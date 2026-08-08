package plain

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"time"
	"zjdns/config"
	"zjdns/internal/ipttl"
	"zjdns/internal/log"
	"zjdns/internal/pool"
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
	isAQtype := len(msg.Question) > 0 &&
		(dns.RRToType(msg.Question[0]) == dns.TypeA ||
			dns.RRToType(msg.Question[0]) == dns.TypeAAAA)

	if isAQtype && (server.Spoofguard || server.HopGuard) {
		if proxyDialer != nil {
			// Defense over SOCKS5: the multi-read loop runs on the proxy
			// UDP socket.  HopGuard auto-disables here — SOCKS5 forwards
			// datagrams without IP TTL metadata.
			return c.executeUDPMultiRead(ctx, msg, server, proxyDialer)
		}
		if c.udpPool != nil {
			// Pooled collect mode — readLoop captures the IP TTL via
			// control messages, so both spoofguard and hopguard run over
			// the pooled sockets.
			if resp, err := c.executeUDPCollect(ctx, msg, server); err == nil {
				return resp, nil
			}
			// Pooled collect failed — fall through to fallback.
		} else if server.HopGuard {
			// No pool — hopguard needs the exclusive-socket TTL capture.
			return c.executeUDPMultiRead(ctx, msg, server, proxyDialer)
		}
	}

	if proxyDialer != nil {
		return c.exchangeViaProxyUDP(ctx, msg, server.Address, proxyDialer)
	}

	// Pooled path: reuse connected UDP sockets (see pool/udp.go).
	if c.udpPool != nil {
		if resp, err := c.executeUDPPooled(ctx, msg, server); err == nil {
			return resp, nil
		}
	}

	response, _, err := c.udpClient.Exchange(ctx, msg, config.ProtoUDP, server.Address)
	return response, err
}

// executeUDPPooled sends a query over a pooled UDP socket.  The query ID is
// rewritten to a per-socket tracking ID (demultiplexing key); the response is
// verified against the original question before being returned — a misrouted
// datagram (ID collision after wrap-around, or a buggy server echoing a stale
// reply) can never be served as this query's response.
func (c *Client) executeUDPPooled(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	uc, err := c.udpPool.Acquire(ctx, server.Address, server.Address, func(dialCtx context.Context, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(dialCtx, "udp", addr)
	})
	if err != nil {
		return nil, err
	}

	originalID := msg.ID
	trackingID := uc.NextID()
	msg.ID = trackingID
	packErr := msg.Pack()
	msgData := msg.Data
	msg.ID = originalID
	if packErr != nil {
		return nil, packErr
	}

	payload, err := uc.Exchange(ctx, msgData, string([]byte{byte(trackingID >> 8), byte(trackingID)})) //nolint:gosec // G115: DNS ID fits uint16
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
		return nil, errors.New("plain: pooled UDP response question mismatch")
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
	uc, err := c.udpPool.Acquire(ctx, server.Address, server.Address, func(dialCtx context.Context, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(dialCtx, "udp", addr)
	})
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
			if _, warned := c.hopguardWarned.LoadOrStore(server.Address, true); !warned {
				log.Warnf("UPSTREAM: hopguard TTL/HopLimit capture not available on %s", server.Address)
			}
		}
	}

	originalID := msg.ID
	trackingID := uc.NextID()
	msg.ID = trackingID
	packErr := msg.Pack()
	msgData := msg.Data
	msg.ID = originalID
	if packErr != nil {
		return nil, packErr
	}

	matchKey := string([]byte{byte(trackingID >> 8), byte(trackingID)}) //nolint:gosec // G115: DNS ID — protocol-bounded uint16
	collectCh, err := uc.ExchangeCollect(ctx, msgData, matchKey)
	if err != nil {
		if uc.IsDead() {
			c.udpPool.Remove(uc)
		}
		return nil, err
	}

	maxDeadline := time.Now().Add(c.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(maxDeadline) {
		maxDeadline = dl
	}

	var sg spoofguardState
	// One timer per collect window, Reset per iteration — time.After inside
	// the select allocated a fresh timer every poll (M-3-6).
	pollTimer := time.NewTimer(config.DefaultSpoofguardPollInterval)
	defer pollTimer.Stop()
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
			uc.ReleaseCollect(matchKey)
			return nil, ctx.Err()
		case pkt, ok := <-collectCh:
			if !ok {
				// The conn died mid-collect: return the other candidates to
				// the pool — only sg.last is handed to the caller.  This
				// branch is reachable since close() now wakes collect
				// waiters (M-3-6).
				uc.ReleaseCollect(matchKey)
				if sg.prev != nil {
					pool.DefaultMessage.Put(sg.prev)
				}
				if sg.nonEDNS != nil {
					pool.DefaultMessage.Put(sg.nonEDNS)
				}
				if sg.last != nil {
					return sg.last, nil
				}
				return nil, errors.New("pooled udp connection closed during spoofguard collect")
			}
			// Gate on 12 bytes first — processPacket reads raw[6..9] for the
			// fast-signal checks; a 2-9 byte datagram with a matching ID
			// would index out of range (H9; the multi-read path gates n<12).
			// ID/length validation also runs BEFORE HopGuard Feed so that
			// stray datagrams never enter the TTL histogram (M1).
			if len(pkt.Data) < 12 || uint16(pkt.Data[0])<<8|uint16(pkt.Data[1]) != trackingID {
				continue
			}
			// HopGuard: validate gates packet acceptance; Feed happens only
			// after spoofguard accepts the response (below) — the learning
			// phase otherwise lets a fixed-TTL flood win the mode and arm
			// the guard on the attacker's TTL (M1).  Rejected TTLs are
			// sampled 1-in-16 into the histogram so legitimate drift can
			// recover (M2).
			if hg != nil && !hg.Validate(server.Address, pkt.TTL) {
				if hg.ShouldSampleRejected(server.Address) {
					hg.Feed(server.Address, pkt.TTL)
				}
				continue
			}
			// TTL confidence signal for spoofguard: when hopguard is armed
			// and the TTL is trusted, ambiguous EDNS responses can be
			// fast-accepted without waiting for a second candidate.  A
			// TTL=0 read (no control message on some platforms) carries no
			// TTL evidence — never fast-accept on it (M-low).
			ttlConfident := hg != nil && hg.Confident(server.Address) && pkt.TTL != 0
			resp := sg.processPacket(pkt.Data, len(pkt.Data), msg.UDPSize, server.Address, ttlConfident, pkt.TTL, server.Spoofguard)
			// processPacket copied the payload (copyData) — return the
			// pooled buffer on every exit path (M-3-6).
			pkt.Release()
			if resp != nil {
				if sg.last != nil && sg.last != resp {
					pool.DefaultMessage.Put(sg.last)
				}
				if sg.prev != nil && sg.prev != resp {
					pool.DefaultMessage.Put(sg.prev)
				}
				if sg.nonEDNS != nil && sg.nonEDNS != resp {
					pool.DefaultMessage.Put(sg.nonEDNS)
				}
				// Feed exactly once per accepted response (the adoption
				// feed was a duplicate — every query was counted twice,
				// halving the arming threshold; M-low).
				if hg != nil {
					hg.Feed(server.Address, pkt.TTL)
				}
				resp.ID = originalID
				uc.ReleaseCollect(matchKey)
				return resp, nil
			}
		case <-pollTimer.C:
			pollTimer.Reset(config.DefaultSpoofguardPollInterval)
			now := time.Now()
			if sg.last != nil && now.Sub(sg.lastRecv) > config.DefaultSpoofguardCollectWindow {
				resp := sg.pickBest()
				if hg != nil {
					hg.Feed(server.Address, sg.pickBestTTL())
				}
				resp.ID = originalID
				uc.ReleaseCollect(matchKey)
				return resp, nil
			}
			if sg.last == nil && sg.nonEDNS != nil && now.Sub(sg.lastRecv) > config.DefaultSpoofguardCollectWindow {
				resp := sg.pickBest()
				if hg != nil {
					hg.Feed(server.Address, sg.pickBestTTL())
				}
				resp.ID = originalID
				uc.ReleaseCollect(matchKey)
				return resp, nil
			}
			if now.After(maxDeadline) {
				resp := sg.pickBest()
				if resp == nil {
					uc.ReleaseCollect(matchKey)
					return nil, errors.New("no UDP response received")
				}
				if hg != nil {
					hg.Feed(server.Address, sg.pickBestTTL())
				}
				resp.ID = originalID
				uc.ReleaseCollect(matchKey)
				return resp, nil
			}
		}
	}
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
	var lastN int // last read length — buffer prefix zeroed on return

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
		// Zero only the used prefix — nothing reads beyond the last read
		// length (R3-L13 family; the buffer is reused across loop reads).
		defer func() { clear(buf[:lastN]); socks5.ReadPool.Put(bufPtr) }()
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
		// Zero only the used prefix (R3-L13 family).
		defer func() { clear(buf[:lastN]); spoofguardBufPool.Put(bufPtr) }()
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
	maxDeadline := time.Now().Add(c.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(maxDeadline) {
		maxDeadline = dl
	}

	var sg spoofguardState

	for {
		select {
		case <-ctx.Done():
			// Return every pooled candidate — the error path below does the
			// same; a bare return leaked them to the GC on first-win
			// cancellation (M2).
			if sg.last != nil {
				pool.DefaultMessage.Put(sg.last)
			}
			if sg.prev != nil {
				pool.DefaultMessage.Put(sg.prev)
			}
			if sg.nonEDNS != nil {
				pool.DefaultMessage.Put(sg.nonEDNS)
			}
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
		lastN = n

		if err != nil && !errors.Is(err, ipttl.ErrNoControlMessage) {
			// A missing TTL control message (ipttl.ErrNoControlMessage) is
			// NOT a network failure — the datagram was received, just without
			// TTL metadata. It skips this error handling and falls through
			// to packet processing as a TTL-less read (ttl=0 → not
			// confident), instead of dropping the datagram and failing the
			// query.
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

		// ID/length validation runs BEFORE HopGuard so stray datagrams never
		// enter the TTL histogram (M1).
		if n < 12 || uint16(buf[0])<<8|uint16(buf[1]) != msg.ID {
			continue
		}

		// HopGuard: validate gates packet acceptance; Feed happens only
		// after spoofguard accepts the response (below) — the learning
		// phase otherwise lets a fixed-TTL flood win the mode and arm the
		// guard on the attacker's TTL (M1).  Rejected TTLs are sampled
		// 1-in-16 so legitimate drift can recover (M2).
		if hg != nil && !hg.Validate(server.Address, ttl) {
			if hg.ShouldSampleRejected(server.Address) {
				hg.Feed(server.Address, ttl)
			}
			continue
		}

		// TTL confidence signal for spoofguard: when hopguard is armed
		// and the TTL is trusted, ambiguous EDNS responses can be
		// fast-accepted without waiting for a second candidate.  A TTL=0
		// read carries no TTL evidence — never fast-accept on it (M-low).
		ttlConfident := hg != nil && hg.Confident(server.Address) && ttl != 0
		if resp := sg.processPacket(buf[:n], n, msg.UDPSize, server.Address, ttlConfident, ttl, server.Spoofguard); resp != nil {
			// Feed exactly once per accepted response (M-low).
			if hg != nil {
				hg.Feed(server.Address, ttl)
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
	if s.copyBufShrinkCount >= 256 && cap(s.copyBuf) > 4*n && cap(s.copyBuf) > 512 {
		s.copyBuf = make([]byte, n)
		copy(s.copyBuf, raw[:n])
		s.copyBufShrinkCount = 0
	}
	return s.copyBuf
}

// processPacket applies EDNS-gate and fast-return checks to a single raw packet.
// Returns a response to return immediately, or nil to continue the loop.
func (s *spoofguardState) processPacket(raw []byte, n int, queryUDPSize uint16, addr string, ttlConfident bool, ttl uint8, spoofguardEnabled bool) *dns.Msg {
	s.lastRecv = time.Now()

	// Fast signals from raw header — check first, before EDNS gate.
	// AN≥2, NS>0, or AD=1 are strong authority signals regardless of
	// whether the server supports EDNS.
	ancount := uint16(raw[6])<<8 | uint16(raw[7])
	nscount := uint16(raw[8])<<8 | uint16(raw[9])
	ad := (raw[3] >> 5) & 1
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
	// without CNAME chains.  Non-EDNS responses are collected as a fallback
	// only when they contain a CNAME or multiple answers — patterns that
	// GFW does not replicate.  Single-answer non-EDNS (GFW signature) is
	// still rejected.
	//
	// When spoofguard is disabled (HopGuard-only mode), skip the EDNS gate
	// entirely — HopGuard's TTL validation is the sole filter. The response
	// has already passed HopGuard validation before entering processPacket.
	if rcode == dns.RcodeSuccess && queryUDPSize > 0 {
		if !spoofguardEnabled {
			resp := pool.DefaultMessage.Get()
			resp.Data = s.copyData(raw, n)
			if err := resp.Unpack(); err != nil {
				pool.DefaultMessage.Put(resp)
				return nil
			}
			resp.Data = nil
			s.last = resp
			s.lastTTL = ttl
			return resp
		}
		resp := pool.DefaultMessage.Get()
		resp.Data = s.copyData(raw, n)
		if err := resp.Unpack(); err != nil {
			pool.DefaultMessage.Put(resp)
			return nil
		}
		resp.Data = nil

		// EDNS presence is determined from the parsed OPT RR, not raw
		// ARCOUNT (which counts ALL additional records).
		hasEDNS := false
		for _, extra := range resp.Extra {
			if _, ok := extra.(*dns.OPT); ok {
				hasEDNS = true
				break
			}
		}
		if hasEDNS {
			// An EDNS response is a legitimate candidate, NOT a spoofguard
			// target — route it into the ambiguous EDNS-bearing handling
			// (fast-accept on TTL confidence or collect). Dropping it here
			// would discard the only response and time the query out.
			return s.collectEDNSCandidate(resp, ttlConfident, ttl, addr)
		}

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
	//
	// When spoofguard is disabled, the response has already passed
	// HopGuard TTL validation — return it directly without candidate
	// collection.
	if !spoofguardEnabled {
		resp := pool.DefaultMessage.Get()
		resp.Data = s.copyData(raw, n)
		if err := resp.Unpack(); err != nil {
			pool.DefaultMessage.Put(resp)
			return nil
		}
		resp.Data = nil
		s.last = resp
		s.lastTTL = ttl
		return resp
	}
	resp := pool.DefaultMessage.Get()
	resp.Data = s.copyData(raw, n)
	if err := resp.Unpack(); err != nil {
		pool.DefaultMessage.Put(resp)
		return nil
	}
	resp.Data = nil
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
