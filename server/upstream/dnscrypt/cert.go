package dnscrypt

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"
	"zjdns/config"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

// FetchCert sends a plain DNS query to addr and returns the unpacked response.
// When preferTCP is true, the query goes directly over TCP — matching
// dnscrypt-proxy's force_tcp behaviour.  Otherwise UDP is tried first; falls
// back to TCP on error (firewall blocking UDP, NAT dropping fragments) or
// truncation per §10.3 of draft-denis-dprive-dnscrypt-10.
func FetchCert(ctx context.Context, addr string, query []byte, preferTCP bool) (*dns.Msg, error) {
	if preferTCP {
		return fetchCertOverTCP(ctx, addr, query)
	}

	resp, err := fetchCertOverUDP(ctx, addr, query)

	// Fast path: UDP succeeded without truncation.
	if err == nil && !resp.Truncated {
		return resp, nil
	}

	// UDP failed or truncated — fall back to TCP.
	if err != nil {
		log.Debugf("UPSTREAM: DNSCrypt cert UDP failed: %v, falling back to TCP", err)
	} else {
		log.Debugf("UPSTREAM: DNSCrypt cert response truncated, retrying over TCP")
	}

	tcpResp, tcpErr := fetchCertOverTCP(ctx, addr, query)
	if tcpErr != nil {
		if err != nil {
			return nil, fmt.Errorf("udp: %w; tcp: %w", err, tcpErr)
		}
		// TCP failed and the UDP response is incomplete — reporting success
		// would serve/cache truncated certificate data.
		log.Debugf("UPSTREAM: DNSCrypt cert TCP retry failed: %v", tcpErr)
		return nil, fmt.Errorf("udp response truncated and tcp retry failed: %w", tcpErr)
	}
	return tcpResp, nil
}

// fetchCertOverUDP sends a single UDP DNS query and returns the unpacked response.
func fetchCertOverUDP(ctx context.Context, addr string, query []byte) (*dns.Msg, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial udp: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// A cancel-only context must interrupt blocking reads even without a
	// deadline (a stalled peer would otherwise hang the goroutine forever).
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	// Size the buffer to the EDNS0 UDPSize (4096) advertised in the cert
	// query — 512-byte reads truncated legitimate large responses.
	buf := make([]byte, config.DefaultDNSCryptUDPSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	// UDP silently drops datagram bytes beyond the buffer; a full buffer is
	// a possible truncation — surface it and let the caller retry over TCP.
	if n >= len(buf) {
		return nil, fmt.Errorf("read: possible datagram truncation (%d bytes read of %d buffer)", n, len(buf))
	}

	resp := &dns.Msg{}
	resp.Data = buf[:n]
	if err := resp.Unpack(); err != nil {
		return nil, fmt.Errorf("unpack: %w", err)
	}
	return resp, nil
}

// fetchCertOverTCP sends a DNS query over TCP (2-byte length prefix) and
// returns the unpacked response.
func fetchCertOverTCP(ctx context.Context, addr string, query []byte) (*dns.Msg, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial tcp: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// A cancel-only context must interrupt blocking reads even without a
	// deadline (a stalled peer would otherwise hang the goroutine forever).
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	frame := make([]byte, 2+len(query))
	frame[0] = byte(len(query) >> 8) //nolint:gosec // G115: DNS query bounded by MaxMsgSize (65535)
	frame[1] = byte(len(query))      //nolint:gosec // G115: DNS query bounded by MaxMsgSize (65535)
	copy(frame[2:], query)
	if _, err := conn.Write(frame); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	respLen := make([]byte, 2)
	if _, err := io.ReadFull(conn, respLen); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	packetLen := int(respLen[0])<<8 | int(respLen[1])
	if packetLen > dns.MaxMsgSize {
		return nil, fmt.Errorf("response too large: %d", packetLen)
	}
	buf := make([]byte, packetLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	resp := &dns.Msg{}
	resp.Data = buf
	if err := resp.Unpack(); err != nil {
		return nil, fmt.Errorf("unpack: %w", err)
	}
	return resp, nil
}
