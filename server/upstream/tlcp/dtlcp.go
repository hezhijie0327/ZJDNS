package tlcp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"gitee.com/Trisia/gotlcp/dtlcp"
)

// dialDTLCP creates a DTLCP client connection to addr using an unconnected
// UDP socket.
//
// TODO: Replace with dtlcp.Dial when upstream fixes the connected-socket issue.
func dialDTLCP(ctx context.Context, network, addr string, cfg *dtlcp.Config) (*dtlcp.Conn, error) {
	remoteAddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, fmt.Errorf("dtlcp: resolve %s: %w", addr, err)
	}

	pconn, err := net.ListenPacket(network, ":0")
	if err != nil {
		return nil, fmt.Errorf("dtlcp: listen packet: %w", err)
	}

	conn := dtlcp.Client(pconn, remoteAddr, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = pconn.Close()
		return nil, fmt.Errorf("dtlcp: handshake %s: %w", addr, err)
	}
	return conn, nil
}

// ExecuteDTLCP performs a DNS-over-DTLCP query (GM/T 0128-2023).
func (c *Client) ExecuteDTLCP(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	dtlcpConfig := c.dtlcpClientConfig(server)

	host, port, err := net.SplitHostPort(server.Address)
	if err != nil {
		return nil, fmt.Errorf("dtlcp: parse address %s: %w", server.Address, err)
	}
	addr := net.JoinHostPort(host, port)

	conn, err := dialDTLCP(ctx, "udp", addr, dtlcpConfig)
	if err != nil {
		return nil, err
	}
	defer zdnsutil.CloseWithLog(conn, "DTLCP connection", "UPSTREAM")

	if err := msg.Pack(); err != nil {
		return nil, fmt.Errorf("dtlcp: pack query: %w", err)
	}

	queryLen := len(msg.Data)
	req := make([]byte, 2+queryLen)
	binary.BigEndian.PutUint16(req[:2], uint16(queryLen)) //nolint:gosec // G115: DNS query length < 65535 (UDP datagram limit)
	copy(req[2:], msg.Data)
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("dtlcp: write query: %w", err)
	}

	respBuf := make([]byte, 4096)
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
	respBuf = respBuf[2 : 2+respLen]

	response := &dns.Msg{Data: respBuf}
	if err := response.Unpack(); err != nil {
		return nil, fmt.Errorf("dtlcp: unpack response: %w", err)
	}

	log.Debugf("UPSTREAM: DTLCP query to %s succeeded", addr)
	return response, nil
}
