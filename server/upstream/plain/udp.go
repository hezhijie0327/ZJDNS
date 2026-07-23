package plain

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/pool"
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
}

// spoofguardBufPool reuses 4KB read buffers across spoofguard queries.
var spoofguardBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 4096)
		return &b
	},
}

// ExecuteUDP sends a DNS query over UDP to the upstream server, optionally
// routing through a SOCKS5 proxy. When server.Spoofguard is true, uses raw
// socket multi-read to capture both GFW-injected fakes and the real response,
// returning the chronologically last (tail) response.
func (c *Client) ExecuteUDP(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	proxyDialer := c.getProxy(server)

	// GFW only hijacks A/AAAA.  Skip spoofguard for other QTYPEs
	// (NS, DS, DNSKEY, etc.) — no fakes to detect.
	if server.Spoofguard && len(msg.Question) > 0 &&
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
		bufPtr := socks5.ReadPool.Get().(*[]byte)
		buf = *bufPtr
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
		bufPtr := spoofguardBufPool.Get().(*[]byte)
		buf = *bufPtr
		defer func() { clear(buf); spoofguardBufPool.Put(bufPtr) }()
	}

	// ── Multi-read loop ───────────────────────────────────────────
	maxDeadline := time.Now().Add(config.DefaultDNSQueryTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(maxDeadline) {
		maxDeadline = dl
	}

	var sg spoofguardState

	for {
		var n int
		var err error
		if pconn != nil {
			_ = pconn.SetDeadline(time.Now().Add(config.DefaultSpoofguardPollInterval))
			n, _, err = pconn.ReadFrom(buf)
		} else {
			_ = conn.SetReadDeadline(time.Now().Add(config.DefaultSpoofguardPollInterval))
			n, err = conn.Read(buf)
		}

		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				now := time.Now()
				if sg.last != nil {
					// Don't return a lone single-answer candidate
					// — likely a GFW fake copying EDNS.  Keep waiting
					// for a richer response or a second candidate.
					ambiguous := sg.prev == nil && sg.lastAns == 1
					if !ambiguous && now.Sub(sg.lastRecv) > config.DefaultSpoofguardCollectWindow {
						return sg.pickBest(), nil
					}
					if now.After(maxDeadline) {
						if ambiguous {
							pool.DefaultMessage.Put(sg.last)
							return nil, errors.New("no EDNS response received")
						}
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
			return nil, err
		}

		if n < 12 || uint16(buf[0])<<8|uint16(buf[1]) != msg.ID {
			continue
		}

		if resp := sg.processPacket(buf[:n], n, msg.UDPSize, server.Address); resp != nil {
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

	respBuf := socks5.ReadPool.Get().(*[]byte)
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

// processPacket applies EDNS-gate and fast-return checks to a single raw packet.
// Returns a response to return immediately, or nil to continue the loop.
func (s *spoofguardState) processPacket(raw []byte, n int, queryUDPSize uint16, addr string) *dns.Msg {
	s.lastRecv = time.Now()

	// EDNS-gate: GFW only injects NOERROR responses.
	if uint16(raw[10])<<8|uint16(raw[11]) == 0 {
		rcode := int(raw[3] & 0x0F)
		if rcode == dns.RcodeSuccess && queryUDPSize > 0 {
			s.rejected++
			log.Debugf("UPSTREAM: UDP spoofguard rejected non-EDNS response #%d from %s", s.rejected, addr)
			return nil
		}
		if rcode != dns.RcodeSuccess {
			log.Debugf("UPSTREAM: UDP spoofguard accepted %s (no-EDNS, real server) from %s", dns.RcodeToString[uint16(rcode)], addr)
		}
	}

	// Fast signals from raw header.
	ancount := uint16(raw[6])<<8 | uint16(raw[7])
	nscount := uint16(raw[8])<<8 | uint16(raw[9])
	ad := (raw[3] >> 5) & 1
	if ancount >= 2 || nscount > 0 || ad == 1 {
		resp := pool.DefaultMessage.Get()
		resp.Data = make([]byte, n)
		copy(resp.Data, raw[:n])
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
		log.Debugf("UPSTREAM: UDP spoofguard fast return from %s (AN=%d, NS=%d, AD=%d, rejected=%d)", addr, ancount, nscount, ad, s.rejected)
		return resp
	}

	// Ambiguous — collect as candidate.
	resp := pool.DefaultMessage.Get()
	resp.Data = make([]byte, n)
	copy(resp.Data, raw[:n])
	if err := resp.Unpack(); err != nil {
		pool.DefaultMessage.Put(resp)
		return nil
	}
	resp.Data = nil

	s.candidates++
	if s.prev != nil {
		pool.DefaultMessage.Put(s.prev)
	}
	s.prev = s.last
	s.prevAns = s.lastAns
	s.last = resp
	s.lastAns = len(resp.Answer)
	log.Debugf("UPSTREAM: UDP spoofguard EDNS candidate #%d from %s, answer=%d (ambiguous, collecting more)", s.candidates, addr, s.lastAns)
	return nil
}

// pickBest returns the richer of the two EDNS-bearing candidates.
func (s *spoofguardState) pickBest() *dns.Msg {
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
	log.Debugf("UPSTREAM: spoofguard chose tail (ans=%d, same richness)", s.lastAns)
	if s.prev != nil {
		pool.DefaultMessage.Put(s.prev)
	}
	return s.last
}
