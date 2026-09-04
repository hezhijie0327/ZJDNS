package plain

import (
	"context"
	"errors"
	"fmt"
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
