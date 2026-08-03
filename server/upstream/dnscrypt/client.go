// Package dnscrypt implements the DNSCrypt v2 client protocol for encrypted
// DNS queries with optional post-quantum key exchange (X-Wing KEM).
package dnscrypt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"zjdns/config"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"
	"zjdns/internal/pool"
	socks5 "zjdns/server/upstream/socks5"

	"codeberg.org/miekg/dns"
)

// Client executes encrypted DNS queries over the DNSCrypt v2 protocol.
type Client struct {
	cacheMu  sync.Mutex
	cache    *lrumap.Map[string, *State]
	getProxy func(*config.UpstreamServer) *socks5.Dialer
}

// maxTCRetries bounds the DNSCrypt TC escalation loop. Each escalation
// consumes one iteration and sets the value for the NEXT query, so reaching
// AND sending 4096 needs one more iteration than the escalation count — 7
// iterations from the 64-byte minimum guarantee the max-padding attempt and
// the RFC §5.4.2 TCP fallback are always reachable.
const maxTCRetries = 7

// New creates a Client for DNSCrypt DNS queries.
func New(getProxy func(*config.UpstreamServer) *socks5.Dialer) *Client {
	return &Client{
		cache:    lrumap.New[string, *State](config.DefaultTransportMax * 2),
		getProxy: getProxy,
	}
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
	q.MinQueryLen = state.minQueryLen
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
	var conn net.Conn
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

	deadline, ok := ctx.Deadline()
	if ok {
		_ = conn.SetDeadline(deadline)
	}

	var respPayload []byte
	if useTCP {
		if writeErr := dnscryptcrypto.WritePrefixed(encrypted, conn); writeErr != nil {
			return nil, false, fmt.Errorf("writing dnscrypt TCP query: %w", writeErr)
		}
		respPayload, err = dnscryptcrypto.ReadPrefixed(conn)
		if err != nil {
			c.deleteState(stampAddr, providerName)
			return nil, false, fmt.Errorf("reading dnscrypt TCP response: %w", err)
		}
	} else {
		_, err = conn.Write(encrypted)
		if err != nil {
			return nil, false, fmt.Errorf("writing dnscrypt query: %w", err)
		}
		respBuf := make([]byte, config.DefaultDNSCryptUDPSize)
		n, udpErr := conn.Read(respBuf)
		if udpErr != nil {
			c.deleteState(stampAddr, providerName)
			return nil, false, fmt.Errorf("reading dnscrypt response: %w", udpErr)
		}
		respPayload = respBuf[:n]
	}

	resp := &dnscryptcrypto.EncryptedResponse{
		ESVersion: state.esVersion,
	}
	decrypted, err := resp.Decrypt(respPayload, sharedKey, clientNonce)
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

	if response.Truncated {
		state.mu.Lock()
		// §5.4.2: escalate by at least 64 bytes on TC.  We double each
		// round to converge in O(log n) — matching dnscrypt-proxy's
		// blindAdjust().  The +64 floor is the RFC minimum.
		next := min(max(state.minQueryLen*2, state.minQueryLen+64), dnscryptcrypto.MaxDNSUDPPacketSize)
		if next > state.minQueryLen {
			state.minQueryLen = next
			log.Debugf("UPSTREAM: DNSCrypt min-query-len escalated to %d after TC", state.minQueryLen)
			state.mu.Unlock()
			pool.DefaultMessage.Put(response)
			return nil, true, nil // signal retry
		}
		state.mu.Unlock()
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

	return response, false, nil
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

// Close clears the cached DNSCrypt state.
func (c *Client) Close() {
	if c == nil {
		return
	}
	c.cacheMu.Lock()
	c.cache = nil
	c.cacheMu.Unlock()
}
