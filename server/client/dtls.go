package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"github.com/pion/dtls/v3"
)

// executeDTLS performs a DNS-over-DTLS query (RFC 8094).  DNS messages are
// framed with a 2-byte big-endian length prefix, same as DoT (RFC 7858).
// No connection pooling — DTLS datagrams may be reordered or lost.
func (c *Client) executeDTLS(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	tlsConfig := c.stdTLSConfig(server)

	host, port, err := net.SplitHostPort(server.Address)
	if err != nil {
		return nil, fmt.Errorf("dtls: parse address %s: %w", server.Address, err)
	}
	addr := net.JoinHostPort(host, port)

	var dtlsOpts []dtls.ClientOption
	if server.SkipTLSVerify {
		dtlsOpts = append(dtlsOpts, dtls.WithInsecureSkipVerify(true))
	}
	if tlsConfig.ServerName != "" {
		dtlsOpts = append(dtlsOpts, dtls.WithServerName(tlsConfig.ServerName))
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("dtls: resolve %s: %w", addr, err)
	}

	conn, err := dtls.DialWithOptions("udp", udpAddr, dtlsOpts...)
	if err != nil {
		return nil, fmt.Errorf("dtls: dial %s: %w", addr, err)
	}
	defer zdnsutil.CloseWithLog(conn, "DTLS connection", "UPSTREAM")

	if err := msg.Pack(); err != nil {
		return nil, fmt.Errorf("dtls: pack query: %w", err)
	}

	// Write prefix + body in a single datagram (pion/dtls requires full-record writes).
	queryLen := len(msg.Data)
	req := make([]byte, 2+queryLen)
	binary.BigEndian.PutUint16(req[:2], uint16(queryLen)) //nolint:gosec // G115: DNS query length < 65535 (UDP datagram limit)
	copy(req[2:], msg.Data)
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("dtls: write query: %w", err)
	}

	// Read full DTLS record containing [2-byte prefix][DNS response].
	respBuf := make([]byte, 4096)
	n, err := conn.Read(respBuf)
	if err != nil {
		return nil, fmt.Errorf("dtls: read response: %w", err)
	}
	if n < 2 {
		return nil, fmt.Errorf("dtls: response too short (%d bytes)", n)
	}
	respLen := binary.BigEndian.Uint16(respBuf[:2])
	respBuf = respBuf[2 : 2+respLen]

	response := &dns.Msg{Data: respBuf}
	if err := response.Unpack(); err != nil {
		return nil, fmt.Errorf("dtls: unpack response: %w", err)
	}

	log.Debugf("UPSTREAM: DTLS query to %s succeeded", addr)
	return response, nil
}
