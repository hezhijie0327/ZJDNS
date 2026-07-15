// Package dnscrypt implements the DNSCrypt v2 client protocol for encrypted
// DNS queries with optional post-quantum key exchange (X-Wing KEM).
package dnscrypt

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
	"zjdns/config"
	"zjdns/internal/log"
	serverdnscrypt "zjdns/server/protocol/dnscrypt"
	socks5 "zjdns/server/upstream/socks5"

	"codeberg.org/miekg/dns"
)

// Client executes encrypted DNS queries over the DNSCrypt v2 protocol.
type Client struct {
	cache    map[string]*State
	cacheMu  sync.RWMutex
	getProxy func(*config.UpstreamServer) *socks5.Dialer
}

// New creates a Client for DNSCrypt DNS queries.
func New(getProxy func(*config.UpstreamServer) *socks5.Dialer) *Client {
	return &Client{
		cache:    make(map[string]*State),
		getProxy: getProxy,
	}
}

// Execute sends an encrypted DNS query to a DNSCrypt resolver.
func (c *Client) Execute(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, useTCP bool) (*dns.Msg, error) {
	stampAddr, providerName, publicKey, err := c.resolveStamp(server)
	if err != nil {
		return nil, fmt.Errorf("resolving dnscrypt stamp: %w", err)
	}

	state, err := c.getState(ctx, stampAddr, providerName, publicKey, server)
	if err != nil {
		return nil, fmt.Errorf("dnscrypt resolver state: %w", err)
	}

	err = msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing dns query: %w", err)
	}

	q := &serverdnscrypt.EncryptedQuery{
		ESVersion:   state.esVersion,
		ClientMagic: state.clientMagic,
		ClientPk:    state.publicKey,
		MinQueryLen: state.minQueryLen,
		IsTCP:       useTCP,
	}
	if state.esVersion.IsPQ() {
		q.PQCertContext = state.pqCertContext
	}
	encrypted, clientNonce, err := prepareQuery(state, q, msg.Data)
	if err != nil {
		return nil, fmt.Errorf("encrypting dnscrypt query: %w", err)
	}

	proxyDialer := c.getProxyDialer(server)
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
		if err := serverdnscrypt.WritePrefixed(encrypted, conn); err != nil {
			return nil, fmt.Errorf("writing dnscrypt TCP query: %w", err)
		}
		respPayload, err = serverdnscrypt.ReadPrefixed(conn)
		if err != nil {
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
			return nil, fmt.Errorf("reading dnscrypt response: %w", udpErr)
		}
		respPayload = respBuf[:n]
	}

	resp := &serverdnscrypt.EncryptedResponse{
		ESVersion: state.esVersion,
	}
	decrypted, err := serverdnscrypt.DecryptResponse(resp, respPayload, state.sharedKey, clientNonce)
	if err != nil {
		return nil, fmt.Errorf("decrypting dnscrypt response: %w", err)
	}

	if len(resp.PQControl) > 0 {
		ticket, lifetime, parseErr := serverdnscrypt.PQParseControlBlock(resp.PQControl)
		if parseErr == nil && len(ticket) > 0 {
			state.pqTicket = ticket
			state.pqTicketExpiry = time.Now().Add(time.Duration(lifetime) * time.Second)
			state.pqResumeSecret = serverdnscrypt.PQResumeSecret(state.sharedKey, state.clientMagic, clientNonce[:serverdnscrypt.NonceSize/2])
			log.Debugf("UPSTREAM: DNSCrypt PQ resumption ticket stored (expires in %ds)", lifetime)
		}
	}

	log.Debugf("UPSTREAM: DNSCrypt decrypted response from %s (%d bytes)", state.serverAddress, len(decrypted))
	response := &dns.Msg{}
	response.Data = decrypted
	err = response.Unpack()
	if err != nil {
		return nil, fmt.Errorf("unpacking dnscrypt response: %w", err)
	}

	if response.Truncated && !useTCP {
		const maxQueryLen = 4096
		if state.minQueryLen+64 <= maxQueryLen {
			state.minQueryLen += 64
			log.Debugf("UPSTREAM: DNSCrypt min-query-len escalated to %d after TC", state.minQueryLen)
		}
	}

	return response, nil
}

// WarmUp pre-fetches the DNSCrypt certificate for the given server.
func (c *Client) WarmUp(ctx context.Context, server *config.UpstreamServer) {
	addr, providerName, publicKey, err := c.resolveStamp(server)
	if err != nil {
		return
	}
	_, _ = c.getState(ctx, addr, providerName, publicKey, server)
}

// getProxyDialer returns a cached SOCKS5Dialer for the server's proxy URL,
// or nil when no proxy is configured or no proxy function is available.
func (c *Client) getProxyDialer(server *config.UpstreamServer) *socks5.Dialer {
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
