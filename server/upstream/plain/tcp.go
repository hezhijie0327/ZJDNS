package plain

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	socks5 "zjdns/server/upstream/socks5"

	"codeberg.org/miekg/dns"
)

// ExecuteTCP sends a DNS query over TCP to the upstream server, optionally
// routing through a SOCKS5 proxy. Uses the pipelined connection pool when
// available, falling back to a single-shot exchange.
func (c *Client) ExecuteTCP(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	if msg == nil {
		return nil, errors.New("plain: nil query message")
	}
	if server == nil {
		return nil, errors.New("plain: nil server config")
	}
	proxyDialer := c.getProxy(server)

	segSize := 0
	if server.Splitguard {
		segSize = config.DefaultSplitguardMaxSegSize
		log.Debugf("UPSTREAM: splitguard active for %s", server.Address)
	}

	if c.tcpPool != nil {
		poolKey := server.Address
		if server.Proxy != "" {
			poolKey = server.Address + "|" + server.Proxy
		}
		pc, err := c.tcpPool.Acquire(ctx, poolKey, server.Address, func(dialCtx context.Context, addr string) (net.Conn, error) {
			if proxyDialer != nil {
				return proxyDialer.DialContext(dialCtx, "tcp", addr)
			}
			var d net.Dialer
			return d.DialContext(dialCtx, "tcp", addr)
		})
		if err == nil {
			pc.SetSegmentation(segSize)
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
		return c.exchangeViaProxy(ctx, msg, server.Address, proxyDialer, segSize)
	}

	response, _, err := c.tcpClient.Exchange(ctx, msg, config.ProtoTCP, server.Address)
	return response, err
}

// exchangeViaProxy sends a DNS query over TCP through a SOCKS5 proxy using
// manual dial + dns.Conn exchange.
func (c *Client) exchangeViaProxy(ctx context.Context, msg *dns.Msg, addr string, proxyDialer *socks5.Dialer, segSize int) (*dns.Msg, error) {
	conn, err := proxyDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	// socks5.DialContext clears the handshake deadline on success ("caller
	// manages I/O timeouts") — restore ctx-bound deadlines here, or a
	// stalled peer (no RST, no keepalive on the proxy path) hangs this
	// goroutine and its fd forever.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true) // disable Nagle for splitguard small-segment writes
	}

	// Pack and write with optional TCP segmentation.
	if err := msg.Pack(); err != nil {
		return nil, err
	}
	writeBuf := make([]byte, 2+len(msg.Data))
	binary.BigEndian.PutUint16(writeBuf[:2], uint16(len(msg.Data))) //nolint:gosec // G115: DNS length prefix
	copy(writeBuf[2:], msg.Data)
	if _, err := zdnsutil.WriteTCPMsgSegmented(conn, writeBuf, segSize); err != nil {
		return nil, err
	}

	response := pool.DefaultMessage.Get()
	if _, err := response.ReadFrom(conn); err != nil {
		pool.DefaultMessage.Put(response)
		return nil, err
	}
	if err := response.Unpack(); err != nil {
		pool.DefaultMessage.Put(response)
		return nil, err
	}
	response.Data = nil
	if response.ID != msg.ID {
		pool.DefaultMessage.Put(response)
		return nil, fmt.Errorf("response id mismatch: expected %d, got %d", msg.ID, response.ID)
	}
	return response, nil
}
