package dnscrypt

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"
	"zjdns/config"
	"zjdns/internal/log"
	zpool "zjdns/server/upstream/pool"

	"codeberg.org/miekg/dns"
)

// certFetchTimeout is the hard budget for a single certificate fetch
// (UDP or TCP attempt).  ResultGroup promotion runs the fetch with
// context.WithoutCancel(ctx) — no cancellation, no deadline — so relying
// on ctx.Deadline() alone leaves conn.Read unbounded and leaks a goroutine
// per promoted follower when the upstream never answers (blackholed UDP).
// Every socket read therefore applies its own deadline: the earlier of this
// budget and the caller's deadline when one exists.
var certFetchTimeout = config.DefaultDNSQueryTimeout

// fetchCert sends a plain DNS query to addr and returns the unpacked response.
// When preferTCP is true, the query goes directly over TCP (pooled when
// available) — matching dnscrypt-proxy's force_tcp behaviour.  Otherwise UDP
// is tried first; falls back to TCP on error (firewall blocking UDP, NAT
// dropping fragments) or truncation per §10.3 of draft-denis-dprive-dnscrypt-10.
func (c *Client) fetchCert(ctx context.Context, addr string, query []byte, preferTCP bool) (*dns.Msg, error) {
	if preferTCP {
		return c.fetchCertTCP(ctx, addr, query)
	}

	resp, err := c.fetchCertUDP(ctx, addr, query)

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

	tcpResp, tcpErr := c.fetchCertTCP(ctx, addr, query)
	if tcpErr != nil {
		if err != nil {
			return nil, fmt.Errorf("udp: %w; tcp: %w", err, tcpErr)
		}
		// TCP failed but the truncated UDP response is better than nothing.
		log.Debugf("UPSTREAM: DNSCrypt cert TCP retry failed: %v", tcpErr)
		return resp, nil
	}
	return tcpResp, nil
}

// fetchCertUDP fetches the certificate over UDP: pooled when available (the
// socket routes the plain-DNS response by the echoed message ID — the shared
// extractor handles both DNSCrypt and plain responses), raw per-fetch dial
// otherwise.
func (c *Client) fetchCertUDP(ctx context.Context, addr string, query []byte) (*dns.Msg, error) {
	if c.udpPool != nil && len(query) >= 2 {
		uc, err := c.udpPool.Acquire(ctx, addr, addr, func(dialCtx context.Context, a string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(dialCtx, "udp", a)
		})
		if err == nil {
			respPayload, err := uc.Exchange(ctx, query, string(query[:2]))
			if err == nil {
				resp := &dns.Msg{}
				resp.Data = respPayload
				unpackErr := resp.Unpack()
				resp.Data = nil
				// Return the tiered-pool payload buffer (M-3-6) — the response
				// records were copied out by the copy-based Unpack.
				zpool.ReleaseUDPPayload(respPayload)
				if unpackErr == nil {
					return resp, nil
				}
				log.Debugf("UPSTREAM: DNSCrypt cert pooled UDP unpack failed: %v", unpackErr)
			} else {
				if uc.IsDead() {
					c.udpPool.Remove(uc)
				}
				log.Debugf("UPSTREAM: DNSCrypt cert pooled UDP failed: %v, falling back to raw dial", err)
			}
		}
	}
	return fetchCertOverUDP(ctx, addr, query)
}

// fetchCertTCP fetches the certificate over TCP: pooled when available (the
// raw pool frames the query and routes the response by its message ID),
// raw per-fetch dial otherwise.  Cert fetches are rare (once per certificate
// lifetime per server) — the pool is a connection-reuse bonus on top of the
// singleflight dedup in state(), not a critical path.
func (c *Client) fetchCertTCP(ctx context.Context, addr string, query []byte) (*dns.Msg, error) {
	if c.tcpPool != nil && len(query) >= 2 {
		rc, err := c.tcpPool.Acquire(ctx, addr, addr, func(dialCtx context.Context, a string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(dialCtx, "tcp", a)
		})
		if err == nil {
			respPayload, err := rc.Exchange(ctx, query, string(query[:2]))
			if err == nil {
				resp, unpackErr := unpackCertResponse(respPayload)
				if unpackErr == nil {
					return resp, nil
				}
				log.Debugf("UPSTREAM: DNSCrypt cert pooled TCP unpack failed: %v", unpackErr)
			} else {
				if rc.IsDead() {
					c.tcpPool.Remove(rc)
				}
				log.Debugf("UPSTREAM: DNSCrypt cert pooled TCP failed: %v, falling back to raw dial", err)
			}
		}
	}
	return fetchCertOverTCP(ctx, addr, query)
}

// unpackCertResponse unpacks a raw cert-fetch response payload.
func unpackCertResponse(payload []byte) (*dns.Msg, error) {
	resp := &dns.Msg{}
	resp.Data = payload
	if err := resp.Unpack(); err != nil {
		return nil, fmt.Errorf("unpack: %w", err)
	}
	return resp, nil
}

// fetchCertOverUDP sends a single UDP DNS query and returns the unpacked response.
func fetchCertOverUDP(ctx context.Context, addr string, query []byte) (*dns.Msg, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial udp: %w", err)
	}
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(certFetchTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

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
	// DialContext, not net.Dial: the connect itself must honor the query
	// budget — a black-holed peer (dropped SYN) would otherwise block far
	// beyond the caller's ctx deadline (M3).
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial tcp: %w", err)
	}
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(certFetchTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

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
