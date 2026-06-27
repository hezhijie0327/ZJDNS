package client

import (
	"context"
	"net"

	"github.com/miekg/dns"

	"zjdns/config"
	"zjdns/internal/log"
)

func (c *Client) executeTraditionalQuery(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	proxyDialer := c.getProxyDialer(server)

	if server.Protocol == config.ProtoTCP && c.tcpPool != nil {
		poolKey := proxyPoolKey(server.Address, server.Proxy)
		pc, err := c.tcpPool.Acquire(ctx, poolKey, server.Address, func(dialCtx context.Context, addr string) (net.Conn, error) {
			if proxyDialer != nil {
				return proxyDialer.DialContext(dialCtx, "tcp", addr)
			}
			var d net.Dialer
			return d.DialContext(dialCtx, "tcp", addr)
		})
		if err == nil {
			response, err := pc.Exchange(ctx, msg)
			if err == nil {
				return response, nil
			}
			if pc.IsDead() {
				c.tcpPool.Remove(pc)
			}
			log.Debugf("UPSTREAM: pipelined TCP query to %s failed: %v, falling back", server.Address, err)
		}
	}

	// Non-pooled fallback. When a proxy is configured, do manual dial + exchange
	// because dns.Client.ExchangeContext cannot be routed through a SOCKS5 proxy.
	if proxyDialer != nil {
		if server.Protocol == config.ProtoTCP {
			return c.exchangeViaProxy(ctx, msg, server.Address, proxyDialer)
		}
		// UDP over SOCKS5 uses UDP ASSOCIATE.
		return c.exchangeViaProxyUDP(ctx, msg, server.Address, proxyDialer)
	}

	var client *dns.Client
	if server.Protocol == config.ProtoTCP {
		client = c.tcpClient
	} else {
		client = c.udpClient
	}
	response, _, err := client.ExchangeContext(ctx, msg, server.Address)
	return response, err
}

// exchangeViaProxy sends a DNS query over TCP through a SOCKS5 proxy using
// manual dial + dns.Conn exchange.
func (c *Client) exchangeViaProxy(ctx context.Context, msg *dns.Msg, addr string, proxyDialer *Socks5Dialer) (*dns.Msg, error) {
	conn, err := proxyDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	dnsConn := new(dns.Conn)
	dnsConn.Conn = conn
	if err := dnsConn.WriteMsg(msg); err != nil {
		return nil, err
	}
	response, err := dnsConn.ReadMsg()
	if err != nil {
		return nil, err
	}
	response.Id = msg.Id
	return response, nil
}

// exchangeViaProxyUDP sends a DNS query over UDP through a SOCKS5 proxy
// using UDP ASSOCIATE (RFC 1928 §6). Because DNS over UDP is a single
// request-response exchange, we create a PacketConn, send one query, read
// the reply, and close it.
func (c *Client) exchangeViaProxyUDP(ctx context.Context, msg *dns.Msg, addr string, proxyDialer *Socks5Dialer) (*dns.Msg, error) {
	pconn, err := proxyDialer.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	packed, err := msg.Pack()
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
	respBuf := socks5ReadPool.Get().(*[]byte)
	n, _, readErr := pconn.ReadFrom(*respBuf)
	if readErr != nil {
		socks5ReadPool.Put(respBuf)
		return nil, readErr
	}

	response := new(dns.Msg)
	if err := response.Unpack((*respBuf)[:n]); err != nil {
		socks5ReadPool.Put(respBuf)
		return nil, err
	}
	socks5ReadPool.Put(respBuf)

	response.Id = msg.Id
	return response, nil
}

func (c *Client) needsTCPFallback(result *Result, protocol string) bool {
	return protocol != config.ProtoTCP && (result.Error != nil || (result.Response != nil && result.Response.Truncated))
}
