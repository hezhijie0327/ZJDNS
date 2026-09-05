package tlcp

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
	"zjdns/internal/resolv"
	socks5 "zjdns/server/upstream/socks5"

	"codeberg.org/miekg/dns"
	"gitee.com/Trisia/gotlcp/dtlcp"
)

// dialDTLCP creates a DTLCP client connection to addr using an unconnected
// UDP socket.
//
// NOTE: dtlcp.Dial requires a connected UDP socket which pion/dtls manages
// differently than gotlcp. Track gotlcp upstream for a fix to the
// connected-socket issue.
func dialDTLCP(ctx context.Context, network, addr string, cfg *dtlcp.Config) (*dtlcp.Conn, error) {
	// Pin SNI to the original hostname before the dial addr becomes a cached
	// IP (resolv SNI safety contract); cfg is built per query, so mutation is
	// safe.  Mirrors the DoH-over-TLCP default at http_tlcp.go.
	if cfg.ServerName == "" {
		if h, _, err := net.SplitHostPort(addr); err == nil && net.ParseIP(h) == nil {
			cfg.ServerName = h
		}
	}
	remoteAddr, err := resolv.Default.ResolveUDPAddr(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("dtlcp: resolve %s: %w", addr, err)
	}

	pconn, err := net.ListenPacket(network, ":0")
	if err != nil {
		return nil, fmt.Errorf("dtlcp: listen packet: %w", err)
	}

	conn := dtlcp.Client(pconn, remoteAddr, cfg)
	// Handshake bounded by a short deadline: the gotlcp server serves one
	// connection at a time (upstream limitation), so concurrent client
	// handshakes queue — a queued or racing handshake must fail fast and
	// let the caller's fallback retry, not burn the 9s query budget.
	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, config.DefaultDTLSHandshakeTimeout)
	defer cancelHandshake()
	if err := conn.HandshakeContext(handshakeCtx); err != nil {
		_ = pconn.Close()
		return nil, fmt.Errorf("dtlcp: handshake %s: %w", addr, err)
	}
	return conn, nil
}

// ExecuteDTLCP performs a DNS-over-DTLCP query (GM/T 0128-2023).
// Uses the pipelined connection pool when available (one DTLCP connection
// multiplexes many queries), falling back to a per-query dial.
func (c *Client) ExecuteDTLCP(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	if msg == nil {
		return nil, errors.New("dtlcp: nil query message")
	}
	if server == nil {
		return nil, errors.New("dtlcp: nil server config")
	}
	proxyDialer := c.getProxy(server)

	if c.dtlcpPool != nil {
		pc, err := c.dtlcpPool.Acquire(ctx, tlcpPoolKey(server), server.Address, func(dialCtx context.Context, addr string) (net.Conn, error) {
			return c.dialDTLCPConn(dialCtx, addr, server, proxyDialer)
		})
		if err == nil {
			response, err := pc.Exchange(ctx, msg)
			if err == nil {
				return response, nil
			}
			if pc.IsDead() {
				c.dtlcpPool.Remove(pc)
			}
			log.Debugf("UPSTREAM: pipelined DTLCP query to %s failed: %v, falling back", server.Address, err)
		}
	}

	// Non-pooled fallback: manual dial + DTLCP handshake + DNS exchange.
	conn, err := c.dialDTLCPConn(ctx, server.Address, server, proxyDialer)
	if err != nil {
		return nil, err
	}
	defer zdnsutil.CloseWithLog(conn, "DTLCP connection", "UPSTREAM")

	// The handshake consumed the dial deadline — restore ctx-bound
	// deadlines so a stalled server cannot hang the read (and its
	// goroutine and socket) forever.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if err := msg.Pack(); err != nil {
		return nil, fmt.Errorf("dtlcp: pack query: %w", err)
	}

	queryLen := len(msg.Data)
	if queryLen > 0xFFFF {
		return nil, errors.New("dtlcp: query exceeds 65535-byte length prefix")
	}
	req := make([]byte, 2+queryLen)
	binary.BigEndian.PutUint16(req[:2], uint16(queryLen)) //nolint:gosec // G115: guarded by the 0xFFFF check above
	copy(req[2:], msg.Data)
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("dtlcp: write query: %w", err)
	}

	respBuf := pool.DefaultBuffer.Get()
	defer pool.DefaultBuffer.Put(respBuf)
	n, err := conn.Read(respBuf)
	if err != nil {
		return nil, fmt.Errorf("dtlcp: read response: %w", err)
	}
	if n < 2 {
		return nil, fmt.Errorf("dtlcp: response too short (%d bytes)", n)
	}
	respLen := binary.BigEndian.Uint16(respBuf[:2])
	if int(respLen)+2 > n {
		return nil, fmt.Errorf("dtlcp: response truncated: want %d + 2, got %d", respLen, n)
	}
	msgBuf := respBuf[2 : 2+respLen]

	response := pool.DefaultMessage.Get()
	response.Data = msgBuf
	if err := response.Unpack(); err != nil {
		response.Data = nil
		pool.DefaultMessage.Put(response)
		return nil, fmt.Errorf("dtlcp: unpack response: %w", err)
	}
	response.Data = nil
	// Reject ID mismatches like the TLS/plain-TCP paths (M7).
	if response.ID != msg.ID {
		pool.DefaultMessage.Put(response)
		return nil, fmt.Errorf("dtlcp: response id mismatch: expected %d, got %d", msg.ID, response.ID)
	}

	log.Debugf("UPSTREAM: DTLCP query to %s succeeded", server.Address)
	return response, nil
}

// dialDTLCPConn dials a DTLCP connection and completes the handshake.  The
// returned connection is owned by the caller (or the pool) and must be closed.
func (c *Client) dialDTLCPConn(ctx context.Context, addr string, server *config.UpstreamServer, proxyDialer *socks5.Dialer) (net.Conn, error) {
	dtlcpConfig := c.dtlcpClientConfig(server)

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("dtlcp: parse address %s: %w", addr, err)
	}
	serverAddr := net.JoinHostPort(host, port)

	if proxyDialer != nil {
		pconn, pErr := proxyDialer.ListenPacket(ctx)
		if pErr != nil {
			return nil, fmt.Errorf("dtlcp: proxy ListenPacket: %w", pErr)
		}
		remoteAddr, rErr := resolv.Default.ResolveUDPAddr(ctx, serverAddr)
		if rErr != nil {
			_ = pconn.Close()
			return nil, fmt.Errorf("dtlcp: resolve %s: %w", serverAddr, rErr)
		}
		conn := dtlcp.Client(pconn, remoteAddr, dtlcpConfig)
		if hErr := conn.HandshakeContext(ctx); hErr != nil {
			_ = pconn.Close()
			return nil, fmt.Errorf("dtlcp: handshake %s: %w", serverAddr, hErr)
		}
		return conn, nil
	}
	return dialDTLCP(ctx, "udp", serverAddr, dtlcpConfig)
}
