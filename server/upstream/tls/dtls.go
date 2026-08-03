package tls

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

	"codeberg.org/miekg/dns"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/protocol"
)

// ExecuteDTLS performs a DNS-over-DTLS query (RFC 8094).  DNS messages are
// framed with a 2-byte big-endian length prefix, same as DoT (RFC 7858).
func (c *Client) ExecuteDTLS(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	if msg == nil {
		return nil, errors.New("dtls: nil query message")
	}
	if server == nil {
		return nil, errors.New("dtls: nil server config")
	}
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
	if c.dtlsSessions != nil {
		dtlsOpts = append(dtlsOpts, dtls.WithSessionStore(c.dtlsSessions))
	}
	dtlsOpts = append(dtlsOpts,
		// DTLS 1.3 preferred, 1.2 fallback for older servers (RFC 9147 §4.2.2).
		// NOTE: our own server is 1.3-only (see server/protocol/tls/dtls.go) —
		// a dual-version [1.2,1.3] server would deadlock this client due to a
		// pion bug (dual-stack handshake never completes). Revisit when pion
		// ships the fix and the server widens its range.
		dtls.WithMinVersion(protocol.Version1_2),
		dtls.WithMaxVersion(protocol.Version1_3),
		dtls.WithVerifyConnection(func(state *dtls.State) error {
			zdnsutil.LogHandshake(&zdnsutil.HandshakeInfo{
				Role:       "UPSTREAM",
				Direction:  "DTLS negotiated for",
				RemoteAddr: addr,
				Cipher:     dtls.CipherSuiteName(state.CipherSuiteID),
			})
			return nil
		}))

	proxyDialer := c.getProxy(server)
	var conn net.Conn

	if proxyDialer != nil {
		pconn, pErr := proxyDialer.ListenPacket(ctx)
		if pErr != nil {
			return nil, fmt.Errorf("dtls: proxy ListenPacket: %w", pErr)
		}
		udpAddr, rErr := net.ResolveUDPAddr("udp", addr)
		if rErr != nil {
			_ = pconn.Close()
			return nil, fmt.Errorf("dtls: resolve %s: %w", addr, rErr)
		}
		conn, pErr = dtls.ClientWithOptions(pconn, udpAddr, dtlsOpts...)
		if pErr != nil {
			_ = pconn.Close()
			return nil, fmt.Errorf("dtls: client %s: %w", addr, pErr)
		}
	} else {
		udpAddr, rErr := net.ResolveUDPAddr("udp", addr)
		if rErr != nil {
			return nil, fmt.Errorf("dtls: resolve %s: %w", addr, rErr)
		}
		conn, rErr = dtls.DialWithOptions("udp", udpAddr, dtlsOpts...)
		if rErr != nil {
			return nil, fmt.Errorf("dtls: dial %s: %w", addr, rErr)
		}
	}
	defer zdnsutil.CloseWithLog(conn, "DTLS connection", "UPSTREAM")

	// Run the handshake explicitly under the caller's context: pion's
	// implicit handshake (triggered by the first write) uses
	// context.Background and would hang far beyond the query budget on an
	// unresponsive server.
	if hc, ok := conn.(interface{ HandshakeContext(context.Context) error }); ok {
		if err := hc.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("dtls: handshake %s: %w", addr, err)
		}
	}

	// pion's read deadline defaults to never expiring — restore ctx-bound
	// deadlines so a lost datagram cannot hang the read (and its goroutine
	// and socket) forever.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if err := msg.Pack(); err != nil {
		return nil, fmt.Errorf("dtls: pack query: %w", err)
	}

	queryLen := len(msg.Data)
	if queryLen > 65535 {
		return nil, fmt.Errorf("dtls: query too large (%d bytes)", queryLen)
	}
	req := make([]byte, 2+queryLen)
	binary.BigEndian.PutUint16(req[:2], uint16(queryLen)) //nolint:gosec // G115: DNS query length < 65535 (checked above)
	copy(req[2:], msg.Data)
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("dtls: write query: %w", err)
	}

	respBuf := pool.DefaultBuffer.Get()
	defer pool.DefaultBuffer.Put(respBuf)
	n, err := conn.Read(respBuf)
	if err != nil {
		return nil, fmt.Errorf("dtls: read response: %w", err)
	}
	if n < 2 {
		return nil, fmt.Errorf("dtls: response too short (%d bytes)", n)
	}
	respLen := binary.BigEndian.Uint16(respBuf[:2])
	if int(respLen)+2 > n {
		return nil, fmt.Errorf("dtls: short read: want %d + 2, got %d", respLen, n)
	}
	msgBuf := respBuf[2 : 2+respLen]

	response := pool.DefaultMessage.Get()
	response.Data = msgBuf
	if err := response.Unpack(); err != nil {
		response.Data = nil
		pool.DefaultMessage.Put(response)
		return nil, fmt.Errorf("dtls: unpack response: %w", err)
	}

	response.Data = nil // detach from pooled buffer before deferred Put
	log.Debugf("UPSTREAM: DTLS query to %s succeeded", addr)
	return response, nil
}
