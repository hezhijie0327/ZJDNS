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

	err = msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing dns query: %w", err)
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
		return nil, fmt.Errorf("encrypting dnscrypt query: %w", err)
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
		return nil, fmt.Errorf("dialing dnscrypt server %s: %w", state.serverAddress, err)
	}
	defer func() { _ = conn.Close() }()

	deadline, ok := ctx.Deadline()
	if ok {
		_ = conn.SetDeadline(deadline)
	}

	var respPayload []byte
	if useTCP {
		if writeErr := dnscryptcrypto.WritePrefixed(encrypted, conn); writeErr != nil {
			return nil, fmt.Errorf("writing dnscrypt TCP query: %w", writeErr)
		}
		respPayload, err = dnscryptcrypto.ReadPrefixed(conn)
		if err != nil {
			c.deleteState(stampAddr, providerName)
			return nil, fmt.Errorf("reading dnscrypt TCP response: %w", err)
		}
	} else {
		_, err = conn.Write(encrypted)
		if err != nil {
			return nil, fmt.Errorf("writing dnscrypt query: %w", err)
		}
		respBuf := make([]byte, config.DefaultDNSCryptUDPSize)
		n, udpErr := conn.Read(respBuf)
		if udpErr != nil {
			c.deleteState(stampAddr, providerName)
			return nil, fmt.Errorf("reading dnscrypt response: %w", udpErr)
		}
		respPayload = respBuf[:n]
	}

	resp := &dnscryptcrypto.EncryptedResponse{
		ESVersion: state.esVersion,
	}
	decrypted, err := resp.Decrypt(respPayload, sharedKey, clientNonce)
	if err != nil {
		c.deleteState(stampAddr, providerName)
		return nil, fmt.Errorf("decrypting dnscrypt response: %w", err)
	}

	if len(resp.PQControl) > 0 {
		ticket, lifetime, parseErr := dnscryptcrypto.PQParseControlBlock(resp.PQControl)
		if parseErr == nil && len(ticket) > 0 {
			// Discard oversized tickets — a resumed query carrying this ticket
			// plus the minimum padding floor would not fit in a UDP datagram.
			if dnscryptcrypto.PQResumedOverhead(len(ticket))+dnscryptcrypto.PQMinPaddingResumed > dnscryptcrypto.MaxDNSUDPPacketSize {
				log.Debugf("UPSTREAM: DNSCrypt discarded oversized PQ resumption ticket (%d bytes)", len(ticket))
			} else {
				state.mu.Lock()
				pqResumeSecret, err := dnscryptcrypto.PQResumeSecret(state.sharedKey, state.clientMagic, clientNonce[:dnscryptcrypto.NonceSize/2])
				if err != nil {
					state.mu.Unlock()
					log.Debugf("UPSTREAM: DNSCrypt PQ resume secret derivation failed: %v", err)
				} else {
					state.pqResumeSecret = pqResumeSecret
					state.pqTicket = ticket
					state.pqTicketExpiry = time.Now().Add(time.Duration(lifetime) * time.Second)
					state.mu.Unlock()
					log.Debugf("UPSTREAM: DNSCrypt PQ resumption ticket stored (expires in %ds)", lifetime)
				}
			}
		}
	}

	log.Debugf("UPSTREAM: DNSCrypt decrypted response from %s (%d bytes)", state.serverAddress, len(decrypted))
	response := pool.DefaultMessage.Get()
	response.Data = decrypted
	err = response.Unpack()
	if err != nil {
		pool.DefaultMessage.Put(response)
		c.deleteState(stampAddr, providerName)
		return nil, fmt.Errorf("unpacking dnscrypt response: %w", err)
	}
	response.Data = nil

	if response.Truncated {
		const maxQueryLen = 4096
		state.mu.Lock()
		// §5.4.2: escalate by at least 64 bytes on TC.  We double each
		// round to converge in O(log n) — matching dnscrypt-proxy's
		// blindAdjust().  The +64 floor is the RFC minimum.
		next := min(max(state.minQueryLen*2, state.minQueryLen+64), maxQueryLen)
		if next > state.minQueryLen {
			state.minQueryLen = next
			log.Debugf("UPSTREAM: DNSCrypt min-query-len escalated to %d after TC", state.minQueryLen)
			state.mu.Unlock()
			// The padding envelope was too small for the response.
			// Retry with the larger minQueryLen so the server has
			// enough padding headroom.  This applies to both UDP
			// (where TC also means "retry over TCP") and TCP
			// (where the DNSCrypt envelope itself is the bottleneck).
			pool.DefaultMessage.Put(response)
			_ = conn.Close()
			return c.Execute(ctx, msg, server, useTCP)
		}
		state.mu.Unlock()
	}

	return response, nil
}

// WarmUp pre-fetches the DNSCrypt certificate for the given server.
func (c *Client) WarmUp(ctx context.Context, server *config.UpstreamServer) {
	addr, providerName, publicKey, err := c.resolveStamp(server)
	if err != nil {
		log.Debugf("UPSTREAM: DNSCrypt WarmUp failed for %s: %v", server.Address, err)
		return
	}
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
