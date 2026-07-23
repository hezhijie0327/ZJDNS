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
// responses within the collection window. GFW-injected fakes arrive before
// the real server response on the same socket — the last response (tail)
// is the real answer.
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

	deadline := time.Now().Add(config.DefaultSpoofguardCollectWindow)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	var lastResp *dns.Msg
	bufPtr := spoofguardBufPool.Get().(*[]byte)
	buf := *bufPtr
	defer func() { clear(buf); spoofguardBufPool.Put(bufPtr) }()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(config.DefaultSpoofguardPollInterval))
		n, err := conn.Read(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				if time.Now().After(deadline) {
					break
				}
				continue
			}
			if lastResp != nil {
				return lastResp, nil
			}
			return nil, err
		}

		if n < 12 || uint16(buf[0])<<8|uint16(buf[1]) != msg.ID {
			continue
		}

		raw := make([]byte, n)
		copy(raw, buf[:n])

		resp := pool.DefaultMessage.Get()
		resp.Data = raw
		if err := resp.Unpack(); err != nil {
			pool.DefaultMessage.Put(resp)
			continue
		}
		resp.Data = nil

		// Keep previous response (GFW fake) and continue reading.
		// The real response always arrives last.
		if lastResp != nil {
			pool.DefaultMessage.Put(lastResp)
		}
		lastResp = resp
		log.Debugf("UPSTREAM: UDP spoofguard collected response from %s, answer=%d", server.Address, len(resp.Answer))
	}

	if lastResp != nil {
		return lastResp, nil
	}
	return nil, errors.New("no UDP response received")
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
