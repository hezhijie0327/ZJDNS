package plain

import (
	"context"
	"net"
	"zjdns/config"
	"zjdns/internal/pool"
	socks5 "zjdns/server/upstream/socks5"

	"codeberg.org/miekg/dns"
)

// ExecuteUDP sends a DNS query over UDP to the upstream server, optionally
// routing through a SOCKS5 proxy.
func (c *Client) ExecuteUDP(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	proxyDialer := c.getProxy(server)

	if proxyDialer != nil {
		return c.exchangeViaProxyUDP(ctx, msg, server.Address, proxyDialer)
	}

	response, _, err := c.udpClient.Exchange(ctx, msg, config.ProtoUDP, server.Address)
	return response, err
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
		socks5.ReadPool.Put(respBuf)
		return nil, readErr
	}

	response := pool.DefaultMessagePool.Get()
	response.Data = (*respBuf)[:n]
	if err := response.Unpack(); err != nil {
		socks5.ReadPool.Put(respBuf)
		pool.DefaultMessagePool.Put(response)
		return nil, err
	}
	socks5.ReadPool.Put(respBuf)

	response.ID = msg.ID
	return response, nil
}
