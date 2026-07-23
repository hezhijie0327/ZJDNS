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

	if proxyDialer != nil {
		return c.exchangeViaProxyUDP(ctx, msg, server.Address, proxyDialer)
	}

	if server.Spoofguard {
		return c.executeUDPMultiRead(ctx, msg, server)
	}

	response, _, err := c.udpClient.Exchange(ctx, msg, config.ProtoUDP, server.Address)
	return response, err
}

// executeUDPMultiRead sends a DNS query via raw UDP and reads multiple
// responses using a dynamic silence window.  GFW fakes arrive in a burst,
// then stop; the real response arrives later and the socket goes silent.
// The last matching response after sustained silence is the real answer.
func (c *Client) executeUDPMultiRead(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	if err := msg.Pack(); err != nil {
		return nil, err
	}

	conn, err := net.Dial("udp", server.Address)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write(msg.Data); err != nil {
		return nil, err
	}

	maxDeadline := time.Now().Add(config.DefaultDNSQueryTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(maxDeadline) {
		maxDeadline = dl
	}

	var prev, last *dns.Msg // previous and last matching responses
	var matchCount int
	var lastRecv time.Time
	bufPtr := spoofguardBufPool.Get().(*[]byte)
	buf := *bufPtr
	defer func() { clear(buf); spoofguardBufPool.Put(bufPtr) }()

	for {
		_ = conn.SetReadDeadline(time.Now().Add(config.DefaultSpoofguardPollInterval))
		n, err := conn.Read(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				now := time.Now()
				if last != nil {
					if now.Sub(lastRecv) > config.DefaultSpoofguardCollectWindow {
						return pickBest(last, prev), nil
					}
					if now.After(maxDeadline) {
						return pickBest(last, prev), nil
					}
				} else if now.After(maxDeadline) {
					return nil, errors.New("no UDP response received")
				}
				continue
			}
			if last != nil {
				return pickBest(last, prev), nil
			}
			return nil, err
		}

		// Quick ID check — skip GFW injections without allocating.
		if n < 12 || uint16(buf[0])<<8|uint16(buf[1]) != msg.ID {
			continue
		}

		resp := pool.DefaultMessage.Get()
		resp.Data = make([]byte, n)
		copy(resp.Data, buf[:n])
		if err := resp.Unpack(); err != nil {
			pool.DefaultMessage.Put(resp)
			continue
		}
		resp.Data = nil

		// Shift: prev becomes the old last, new resp becomes last.
		// We keep both to compare answer richness on return.
		if prev != nil {
			pool.DefaultMessage.Put(prev)
		}
		prev = last
		last = resp
		matchCount++
		lastRecv = time.Now()
		log.Debugf("UPSTREAM: UDP spoofguard collected response #%d from %s, answer=%d", matchCount, server.Address, len(resp.Answer))
	}
}

// pickBest returns the better of the last and previous matching responses.
// Defaults to last (tail), but if last has only 1 answer record and a
// previous response had more, the richer response is preferred — GFW fakes
// almost always carry exactly 1 A record.
func pickBest(last, prev *dns.Msg) *dns.Msg {
	if prev == nil {
		return last
	}
	lastN := len(last.Answer)
	prevN := len(prev.Answer)
	if lastN == 1 && prevN > 1 {
		log.Debugf("UPSTREAM: spoofguard chose richer (ans=%d) over tail (ans=%d)", prevN, lastN)
		pool.DefaultMessage.Put(last)
		return prev
	}
	if prevN == 1 && lastN > 1 {
		log.Debugf("UPSTREAM: spoofguard chose tail (ans=%d) over prev (ans=%d)", lastN, prevN)
		pool.DefaultMessage.Put(prev)
		return last
	}
	log.Debugf("UPSTREAM: spoofguard chose tail (ans=%d, same richness)", lastN)
	if prev != nil {
		pool.DefaultMessage.Put(prev)
	}
	return last
}

// exchangeViaProxyUDP sends a DNS query over UDP through a SOCKS5 proxy
// using UDP ASSOCIATE (RFC 1928 §6).
func (c *Client) exchangeViaProxyUDP(ctx context.Context, msg *dns.Msg, addr string, proxyDialer *socks5.Dialer) (*dns.Msg, error) {
	pconn, err := proxyDialer.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	err = msg.Pack()
	packed := msg.Data
	if err != nil {
		return nil, err
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = pconn.SetDeadline(deadline)
	}

	if _, err := pconn.WriteTo(packed, remoteAddr); err != nil {
		return nil, err
	}

	// Reuse a pooled buffer for the response read. Max DNS message size
	// is 65535 bytes (dns.MaxMsgSize); the pool buffer is 8192 which covers
	// the common case (~512–1232). Larger responses allocate.
	respBuf := socks5.ReadPool.Get().(*[]byte)
	n, _, readErr := pconn.ReadFrom(*respBuf)
	if readErr != nil {
		clear(*respBuf)
		socks5.ReadPool.Put(respBuf)
		return nil, readErr
	}

	response := pool.DefaultMessage.Get()
	response.Data = (*respBuf)[:n]
	if err := response.Unpack(); err != nil {
		clear(*respBuf)
		socks5.ReadPool.Put(respBuf)
		pool.DefaultMessage.Put(response)
		return nil, err
	}
	response.Data = nil
	clear(*respBuf)
	socks5.ReadPool.Put(respBuf)

	response.ID = msg.ID
	return response, nil
}
