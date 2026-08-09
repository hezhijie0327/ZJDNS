// Package dnscrypt implements the DNSCrypt v2 client protocol for encrypted
// DNS queries with optional post-quantum key exchange (X-Wing KEM).
package dnscrypt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"zjdns/config"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"
	"zjdns/internal/pending"
	"zjdns/internal/pool"
	zpool "zjdns/server/upstream/pool"
	socks5 "zjdns/server/upstream/socks5"

	"codeberg.org/miekg/dns"
)

// Client executes encrypted DNS queries over the DNSCrypt v2 protocol.
type Client struct {
	cacheMu  sync.Mutex
	cache    *lrumap.Map[string, *State]
	getProxy func(*config.UpstreamServer) *socks5.Dialer

	// stateGroup deduplicates concurrent certificate fetches per upstream —
	// a burst of cache-miss queries must not each re-fetch (see state()).
	stateGroup *pending.ResultGroup[string, *State]

	// udpPool reuses connected UDP sockets per upstream (see pool/udp.go).
	// Responses are routed by the client-nonce prefix echoed in the response
	// header; decryption (nonce half check) + message-ID checks in executeOnce
	// are the second line of defense against misrouted datagrams.
	udpPool *zpool.UDPPool

	// tcpPool multiplexes pipelined DNSCrypt-over-TCP frames per upstream
	// (see pool/raw.go).  The encrypted query's DNS ID is unreachable, so
	// responses are routed by the same client-nonce prefix as UDP; certificate
	// fetches (plain DNS) share the pool, routed by their message ID.
	tcpPool *zpool.RawPool
}

// maxTCRetries bounds the DNSCrypt TC escalation loop. Each escalation
// consumes one iteration and sets the value for the NEXT query, so reaching
// AND sending 4096 needs one more iteration than the escalation count — 7
// iterations from the 64-byte minimum guarantee the max-padding attempt and
// the RFC §5.4.2 TCP fallback are always reachable.
const maxTCRetries = 7

// respBufPool reuses the per-query UDP response buffer. Decrypt copies the
// payload out (XchachaOpen allocates fresh), so the buffer is safe to return
// after Decrypt. Stored as *[]byte to avoid interface boxing (SA6002).
var respBufPool = sync.Pool{
	New: func() any { b := make([]byte, dnscryptcrypto.MaxDNSUDPPacketSize); return &b },
}

// New creates a Client for DNSCrypt DNS queries.
func New(getProxy func(*config.UpstreamServer) *socks5.Dialer) *Client {
	return &Client{
		cache:      lrumap.New[string, *State](config.DefaultTransportMax * 2),
		getProxy:   getProxy,
		stateGroup: pending.NewResultGroup[string, *State](),
		udpPool:    zpool.NewUDPPool(config.DefaultMaxConns, config.DefaultMaxPipe, config.DefaultMaxPoolTotalConns, dnscryptExtractKey),
		tcpPool:    zpool.NewRawPool(config.DefaultMaxConns, config.DefaultMaxPipe, config.DefaultMaxPoolTotalConns, dnscryptExtractKey),
	}
}

// dnscryptExtractKey derives a response's pool match key.  DNSCrypt
// responses (UDP and TCP alike) carry the client-nonce prefix at [8:20]
// after the resolver magic; cert-fetch responses are plain DNS with the
// echoed message ID at [0:2].  The magic check is unambiguous: byte 2 of
// ResolverMagic (0x66) has the QR flag clear, so a valid DNS response
// header can never match it.
func dnscryptExtractKey(payload []byte) (string, bool) {
	if len(payload) >= dnscryptcrypto.ResolverMagicSize+dnscryptcrypto.NonceSize/2 &&
		bytes.Equal(payload[:dnscryptcrypto.ResolverMagicSize], dnscryptcrypto.ResolverMagic[:]) {
		return string(payload[dnscryptcrypto.ResolverMagicSize : dnscryptcrypto.ResolverMagicSize+dnscryptcrypto.NonceSize/2]), true
	}
	if len(payload) >= 2 {
		return string(payload[:2]), true
	}
	return "", false
}

// Execute sends an encrypted DNS query to a DNSCrypt resolver.
func (c *Client) Execute(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, useTCP bool) (*dns.Msg, error) {
	if msg == nil {
		return nil, errors.New("dnscrypt: nil query message")
	}
	if server == nil {
		return nil, errors.New("dnscrypt: nil server config")
	}
	stampAddr, providerName, publicKey, err := c.resolveStamp(server)
	if err != nil {
		return nil, fmt.Errorf("resolving dnscrypt stamp: %w", err)
	}

	state, err := c.state(ctx, stampAddr, providerName, publicKey, server, useTCP)
	if err != nil {
		return nil, fmt.Errorf("dnscrypt resolver state: %w", err)
	}

	// Use a bounded loop instead of recursion for TC retries — the
	// minQueryLen doubles each round, converging in O(log n).
	for range maxTCRetries {
		resp, retry, err := c.executeOnce(ctx, msg, state, stampAddr, providerName, server, useTCP)
		if err != nil {
			return nil, err
		}
		if !retry {
			return resp, nil
		}
		// retry == true: TC escalation succeeded, loop again
	}
	return nil, errors.New("dnscrypt: query still truncated after max TC retries")
}

// executeOnce performs a single DNSCrypt query attempt.
// Returns (response, shouldRetry, error).
// shouldRetry is true when TC was handled by escalating minQueryLen.
func (c *Client) executeOnce(
	ctx context.Context,
	msg *dns.Msg,
	state *State,
	stampAddr, providerName string,
	server *config.UpstreamServer,
	useTCP bool,
) (*dns.Msg, bool, error) {
	if err := msg.Pack(); err != nil {
		return nil, false, fmt.Errorf("packing dns query: %w", err)
	}

	q := &dnscryptcrypto.EncryptedQuery{
		ESVersion:   state.esVersion,
		ClientMagic: state.clientMagic,
		ClientPk:    state.publicKey,
		IsTCP:       useTCP,
	}
	if state.esVersion.IsPQ() {
		q.PQCertContext = state.pqCertContext
	}
	state.mu.Lock()
	q.MinQueryLen = int(state.minQueryLen.Load())
	encrypted, clientNonce, sharedKey, err := prepareQuery(state, q, msg.Data)
	state.mu.Unlock()
	if err != nil {
		return nil, false, fmt.Errorf("encrypting dnscrypt query: %w", err)
	}

	proxyDialer := c.proxyDialer(server)
	network := "udp"
	if useTCP {
		network = "tcp"
	}
	// Reuse pooled connections — the per-query socket()/connect()/close()
	// syscall churn was the outbound hot path's dominant cost.  TCP is
	// multiplexed through the raw frame pool (routed by the client-nonce
	// prefix).  Proxied sockets are pooled too: the pool key includes the
	// proxy, and the dialFunc establishes the SOCKS5 ASSOCIATE/TCP relay —
	// the handshake is paid once per socket instead of per query.  The
	// pool-unavailable paths keep their per-query dial.
	poolKey := state.serverAddress
	if proxyDialer != nil {
		poolKey += "|" + server.Proxy
	}
	var pooledUDP *zpool.UDPConn
	var pooledTCP *zpool.RawConn
	var conn net.Conn
	if !useTCP && c.udpPool != nil {
		pooledUDP, err = c.udpPool.Acquire(ctx, poolKey, state.serverAddress, func(dialCtx context.Context, addr string) (net.Conn, error) {
			if proxyDialer != nil {
				return proxyDialer.DialUDP(dialCtx, addr)
			}
			var d net.Dialer
			return d.DialContext(dialCtx, "udp", addr)
		})
		if err != nil {
			// Pool saturated or dial failed — fall back to a per-query dial
			// rather than failing the query.
			log.Debugf("UPSTREAM: DNSCrypt UDP pool acquire failed for %s: %v", state.serverAddress, err)
		}
	} else if useTCP && c.tcpPool != nil {
		pooledTCP, err = c.tcpPool.Acquire(ctx, poolKey, state.serverAddress, func(dialCtx context.Context, addr string) (net.Conn, error) {
			if proxyDialer != nil {
				return proxyDialer.DialContext(dialCtx, "tcp", addr)
			}
			var d net.Dialer
			return d.DialContext(dialCtx, "tcp", addr)
		})
		if err != nil {
			// Pool saturated or dial failed — fall back to a per-query dial
			// rather than failing the query (TCP is already the fallback
			// path; the pool must not become a new failure mode).
			log.Debugf("UPSTREAM: DNSCrypt TCP pool acquire failed for %s: %v", state.serverAddress, err)
		}
	}
	if pooledUDP == nil && pooledTCP == nil {
		if proxyDialer != nil {
			if useTCP {
				conn, err = proxyDialer.DialContext(ctx, "tcp", state.serverAddress)
			} else {
				conn, err = proxyDialer.DialUDP(ctx, state.serverAddress)
			}
		} else {
			dialer := &net.Dialer{}
			conn, err = dialer.DialContext(ctx, network, state.serverAddress)
		}
		if err != nil {
			return nil, false, fmt.Errorf("dialing dnscrypt server %s: %w", state.serverAddress, err)
		}
		defer func() { _ = conn.Close() }()
	}

	// Pooled sockets need no per-query deadline — UDPConn.Exchange bounds the
	// wait by ctx itself.
	if conn != nil {
		deadline, ok := ctx.Deadline()
		if ok {
			_ = conn.SetDeadline(deadline)
		}
	}

	var respPayload []byte
	switch {
	case pooledUDP != nil:
		// Pooled UDP socket: route by the client-nonce prefix echoed in the
		// response header.  Decrypt below re-checks the nonce half and the
		// message ID — a misrouted datagram can never be served.
		respPayload, err = pooledUDP.Exchange(ctx, encrypted, string(clientNonce[:dnscryptcrypto.NonceSize/2]))
		if err != nil {
			if pooledUDP.IsDead() {
				c.udpPool.Remove(pooledUDP)
			}
			// Same as TCP: a read error is not a certificate problem.
			return nil, false, fmt.Errorf("reading dnscrypt response: %w", err)
		}
	case pooledTCP != nil:
		// Pooled TCP: the raw pool frames the encrypted query and routes the
		// response by the client-nonce prefix — same header shape as UDP.
		// Decrypt below re-checks the nonce half and the message ID.
		respPayload, err = pooledTCP.Exchange(ctx, encrypted, string(clientNonce[:dnscryptcrypto.NonceSize/2]))
		if err != nil {
			if pooledTCP.IsDead() {
				c.tcpPool.Remove(pooledTCP)
			}
			// Same as raw TCP: a read error is not a certificate problem.
			return nil, false, fmt.Errorf("reading dnscrypt response: %w", err)
		}
	case useTCP:
		if writeErr := dnscryptcrypto.WritePrefixed(encrypted, conn); writeErr != nil {
			return nil, false, fmt.Errorf("writing dnscrypt TCP query: %w", writeErr)
		}
		respPayload, err = readPrefixedWithCancel(ctx, conn)
		if err != nil {
			// NOT a certificate problem: a read error (timeout from a
			// saturated server, network drop) leaves the cached state valid —
			// invalidating it here would make every retry re-fetch the cert.
			return nil, false, fmt.Errorf("reading dnscrypt TCP response: %w", err)
		}
	default:
		_, err = conn.Write(encrypted)
		if err != nil {
			return nil, false, fmt.Errorf("writing dnscrypt query: %w", err)
		}
		// Decrypt copies the payload out (XchachaOpen allocates fresh), so
		// the pooled buffer is safe to return via defer once Decrypt ran.
		respBufPtr, ok := respBufPool.Get().(*[]byte)
		if !ok {
			b := make([]byte, dnscryptcrypto.MaxDNSUDPPacketSize)
			respBufPtr = &b
		}
		respBuf := *respBufPtr
		defer respBufPool.Put(respBufPtr)
		n, udpErr := readUDPWithCancel(ctx, conn, respBuf)
		if udpErr != nil {
			// Same as TCP: a read error is not a certificate problem.
			return nil, false, fmt.Errorf("reading dnscrypt response: %w", udpErr)
		}
		respPayload = respBuf[:n]
	}

	resp := &dnscryptcrypto.EncryptedResponse{
		ESVersion: state.esVersion,
	}
	// Decrypt copies the payload out — the pooled response buffer can be
	// returned now, regardless of decrypt success (M-3-6).  Capture the wire
	// size first: the estimator below runs after the buffer is released.
	respLen := len(respPayload)
	decrypted, err := resp.Decrypt(respPayload, sharedKey, clientNonce)
	zpool.ReleaseUDPPayload(respPayload)
	if err != nil {
		c.deleteState(stampAddr, providerName)
		return nil, false, fmt.Errorf("decrypting dnscrypt response: %w", err)
	}

	if len(resp.PQControl) > 0 {
		ticket, lifetime, parseErr := dnscryptcrypto.PQParseControlBlock(resp.PQControl)
		if parseErr == nil && len(ticket) > 0 &&
			dnscryptcrypto.PQResumedOverhead(len(ticket))+dnscryptcrypto.PQMinPaddingResumed <= dnscryptcrypto.MaxDNSUDPPacketSize {
			state.mu.Lock()
			// Derive the resume secret from THIS query's key: state.sharedKey
			// is a shared mutable field a concurrent in-flight PQ query can
			// overwrite between encryption and this read, producing a
			// resume secret the server cannot open.
			pqResumeSecret, err := dnscryptcrypto.PQResumeSecret(sharedKey, state.clientMagic, clientNonce[:dnscryptcrypto.NonceSize/2])
			if err != nil {
				state.mu.Unlock()
				log.Debugf("UPSTREAM: DNSCrypt PQ resume secret derivation failed: %v", err)
			} else {
				state.pqResumeSecret = pqResumeSecret
				state.pqTicket = ticket
				// RFC §11.7.1: cap ticket expiry by certificate expiry.
				ticketExpiry := time.Now().Add(time.Duration(lifetime) * time.Second)
				if state.expires.Before(ticketExpiry) {
					ticketExpiry = state.expires
				}
				state.pqTicketExpiry = ticketExpiry
				state.mu.Unlock()
				log.Debugf("UPSTREAM: DNSCrypt PQ resumption ticket stored (expires in %ds)", lifetime)
			}
		} else if len(ticket) > 0 {
			log.Debugf("UPSTREAM: DNSCrypt discarded oversized PQ resumption ticket (%d bytes)", len(ticket))
		}
	}

	log.Debugf("UPSTREAM: DNSCrypt decrypted response from %s (%d bytes)", state.serverAddress, len(decrypted))
	response := pool.DefaultMessage.Get()
	response.Data = decrypted
	err = response.Unpack()
	if err != nil {
		pool.DefaultMessage.Put(response)
		c.deleteState(stampAddr, providerName)
		return nil, false, fmt.Errorf("unpacking dnscrypt response: %w", err)
	}
	response.Data = nil
	// Reject ID mismatches like the other transports (M7 family, R3-L14) —
	// a misbehaving upstream returning a stale datagram must not be served.
	if response.ID != msg.ID {
		pool.DefaultMessage.Put(response)
		c.deleteState(stampAddr, providerName)
		return nil, false, fmt.Errorf("dnscrypt: response id mismatch: expected %d, got %d", msg.ID, response.ID)
	}

	if response.Truncated {
		// §5.4.2: escalate by at least 64 bytes on TC.  We double each
		// round to converge in O(log n) — matching dnscrypt-proxy's
		// blindAdjust().  The +64 floor is the RFC minimum.  The EWMA is
		// reset to the new budget so a concurrent shrink cannot undo the
		// escalation (estimator state is atomic — no lock on the read path).
		if state.blindAdjust() {
			log.Debugf("UPSTREAM: DNSCrypt min-query-len escalated to %d after TC", state.minQueryLen.Load())
			pool.DefaultMessage.Put(response)
			return nil, true, nil // signal retry
		}
		// RFC §5.4.2 MUST: if padding escalation can't resolve
		// the TC, retry the query over TCP instead.
		if !useTCP {
			pool.DefaultMessage.Put(response)
			resp, err := c.Execute(ctx, msg, server, true)
			return resp, false, err
		}
		// TCP still truncated at the max escalation: deliver an error, not
		// a truncated payload — the caller would otherwise parse and cache
		// incomplete data without any TC awareness.
		pool.DefaultMessage.Put(response)
		return nil, false, errors.New("dnscrypt: response still truncated over TCP at max query length")
	}

	// Feed the observed response size into the estimator: when responses
	// stay well below the padded query budget, minQueryLen shrinks over
	// time (draft §5.4.2 — the adjustment algorithm is implementation-defined).
	state.adjustQuerySize(respLen)
	return response, false, nil
}

// readUDPWithCancel reads a datagram into buf, returning early when ctx is
// cancelled.  Without this, conn.Read blocks until the deadline even after
// the resolver fan-out cancels this query (first-wins), stranding a goroutine
// + socket per query until the full timeout.  On cancellation the conn is
// closed to unblock the reader, and the caller waits for it to exit before
// the pooled buffer may be reused.
func readUDPWithCancel(ctx context.Context, conn net.Conn, buf []byte) (int, error) {
	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		defer zdnsutil.HandlePanic("DNSCrypt read")
		n, err := conn.Read(buf)
		ch <- result{n, err}
	}()
	select {
	case r := <-ch:
		return r.n, r.err
	case <-ctx.Done():
		_ = conn.Close()
		<-ch // reader is unblocked by the close; wait so buf is not reused early
		return 0, ctx.Err()
	}
}

// readPrefixedWithCancel reads a length-prefixed DNSCrypt TCP frame, returning
// early on ctx cancellation — same rationale and discipline as readUDPWithCancel.
func readPrefixedWithCancel(ctx context.Context, conn net.Conn) ([]byte, error) {
	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		defer zdnsutil.HandlePanic("DNSCrypt read")
		data, err := dnscryptcrypto.ReadPrefixed(conn)
		ch <- result{data, err}
	}()
	select {
	case r := <-ch:
		return r.data, r.err
	case <-ctx.Done():
		_ = conn.Close()
		<-ch
		return nil, ctx.Err()
	}
}

// WarmUp pre-fetches the DNSCrypt certificate for the given server.
func (c *Client) WarmUp(ctx context.Context, server *config.UpstreamServer) {
	addr, providerName, publicKey, err := c.resolveStamp(server)
	if err != nil {
		log.Debugf("UPSTREAM: DNSCrypt WarmUp failed for %s: %v", server.Address, err)
		return
	}
	// _ = error: WarmUp is best-effort — a cert-fetch failure here is only a
	// missed pre-warm; the first real query will fetch the state itself.
	_, _ = c.state(ctx, addr, providerName, publicKey, server, server.Protocol == config.ProtoDNSCryptTCP)
}

// proxyDialer returns a cached SOCKS5Dialer for the server's proxy URL,
// or nil when no proxy is configured or no proxy function is available.
func (c *Client) proxyDialer(server *config.UpstreamServer) *socks5.Dialer {
	if c.getProxy == nil {
		return nil
	}
	return c.getProxy(server)
}

// Close clears the cached DNSCrypt state and shuts down the UDP socket pool.
func (c *Client) Close() {
	if c == nil {
		return
	}
	c.cacheMu.Lock()
	c.cache = nil
	c.cacheMu.Unlock()
	if c.udpPool != nil {
		c.udpPool.Shutdown()
	}
	if c.tcpPool != nil {
		c.tcpPool.Shutdown()
	}
}
