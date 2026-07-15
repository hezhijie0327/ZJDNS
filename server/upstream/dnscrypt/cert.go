package dnscrypt

import (
	"context"
	"fmt"
	"io"
	"net"
	"zjdns/config"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

// FetchCert sends a plain DNS query to addr and returns the unpacked response.
// UDP is tried first; if the response has the TC flag set, the query is
// retried over TCP per §10.3 of draft-denis-dprive-dnscrypt-10.
func FetchCert(ctx context.Context, addr string, query []byte) (*dns.Msg, error) {
	resp, err := fetchCertOverUDP(ctx, addr, query)
	if err != nil {
		return nil, err
	}
	if !resp.Truncated {
		return resp, nil
	}

	log.Debugf("UPSTREAM: DNSCrypt cert response truncated, retrying over TCP")
	tcpResp, tcpErr := fetchCertOverTCP(ctx, addr, query)
	if tcpErr != nil {
		log.Debugf("UPSTREAM: DNSCrypt cert TCP retry failed: %v", tcpErr)
		return resp, nil
	}
	return tcpResp, nil
}

// fetchCertOverUDP sends a single UDP DNS query and returns the unpacked response.
func fetchCertOverUDP(ctx context.Context, addr string, query []byte) (*dns.Msg, error) {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial udp: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, config.DefaultDNSCryptResponseBuffer)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
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
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial tcp: %w", err)
	}
	defer func() { _ = conn.Close() }()

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
