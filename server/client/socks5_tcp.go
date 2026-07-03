package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"zjdns/internal/log"
)

// DialContext connects to targetAddr through the SOCKS5 proxy via TCP CONNECT.
// The returned net.Conn is a raw TCP connection forwarded through the proxy.
func (d *SOCKS5Dialer) DialContext(ctx context.Context, network string, targetAddr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("socks5: unsupported network %q (only tcp)", network)
	}

	deadline, hasDeadline := ctx.Deadline()

	dialer := net.Dialer{}
	if hasDeadline {
		dialer.Timeout = time.Until(deadline)
	}
	conn, err := dialer.DialContext(ctx, "tcp", d.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5: dial proxy %s: %w", d.proxyAddr, err)
	}

	if hasDeadline {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}

	if err := d.handshake(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	if err := d.connect(conn, targetAddr); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// Clear deadline — the caller manages I/O timeouts from here.
	_ = conn.SetDeadline(time.Time{})

	log.Debugf("UPSTREAM: SOCKS5 connected to %s via %s", targetAddr, d.SafeURL())
	return conn, nil
}

// connect sends a CONNECT request and skips the bind address in the response.
func (d *SOCKS5Dialer) connect(conn net.Conn, targetAddr string) error {
	host, port, err := splitHostPort(targetAddr)
	if err != nil {
		return err
	}
	req := buildSOCKS5Request(socks5CmdConnect, host, port)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5: send CONNECT: %w", err)
	}

	resp := make([]byte, 4) // VER | REP | RSV | ATYP
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5: read CONNECT response: %w", err)
	}
	if resp[1] != socks5RepSuccess {
		return fmt.Errorf("socks5: CONNECT rejected, code %d", resp[1])
	}
	return skipAddress(conn, resp[3])
}
