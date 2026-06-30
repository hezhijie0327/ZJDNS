package client

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"

	"zjdns/config"
	"zjdns/internal/log"
)

// dnscryptSession caches a resolved DNSCrypt session per upstream.
type dnscryptSession struct {
	info     *dnscrypt.ResolverInfo
	protoKey string
}

// dnscryptSessionKey builds a transport key for DNSCrypt session caching.
func dnscryptSessionKey(server *config.UpstreamServer) string {
	var b strings.Builder
	b.WriteString(server.Address)
	b.WriteByte('|')
	b.WriteString(server.DNSCryptProviderName)
	b.WriteByte('|')
	b.WriteString(server.DNSCryptPublicKey)
	return b.String()
}

// getDNSCryptSession returns a cached DNSCrypt session or creates one by
// fetching and validating the server certificate.
func (c *Client) getDNSCryptSession(ctx context.Context, server *config.UpstreamServer) (*dnscrypt.ResolverInfo, error) {
	key := dnscryptSessionKey(server)

	if entry, ok := c.dnscryptSessions.Load(key); ok {
		session := entry.(*dnscryptSession)
		// Verify the certificate is still valid.
		if session.info.ResolverCert != nil && session.info.ResolverCert.VerifyDate() {
			return session.info, nil
		}
		// Certificate expired — remove and re-fetch.
		c.dnscryptSessions.Delete(key)
		log.Debugf("UPSTREAM: DNSCrypt session expired for %s, re-fetching", server.Address)
	}

	serverPk, err := hex.DecodeString(strings.ReplaceAll(server.DNSCryptPublicKey, ":", ""))
	if err != nil {
		return nil, fmt.Errorf("decode dnscrypt public key: %w", err)
	}
	if len(serverPk) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid dnscrypt public key length: %d (expected %d)", len(serverPk), ed25519.PublicKeySize)
	}

	stamp := dnsstamps.ServerStamp{
		ServerAddrStr: server.Address,
		ProviderName:  server.DNSCryptProviderName,
		ServerPk:      serverPk,
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
	}

	info, err := c.dnscryptUDPClient.DialStampContext(ctx, stamp)
	if err != nil {
		return nil, fmt.Errorf("dnscrypt dial: %w", err)
	}

	session := &dnscryptSession{info: info, protoKey: key}
	c.dnscryptSessions.Store(key, session)

	log.Debugf("UPSTREAM: DNSCrypt session established for %s (provider=%s es_version=%s)",
		server.Address, info.ProviderName, info.ResolverCert.ESVersion)

	return info, nil
}

// executeDNSCrypt sends a DNS query over DNSCrypt to the upstream server.
func (c *Client) executeDNSCrypt(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, protocol string) (*dns.Msg, error) {
	info, err := c.getDNSCryptSession(ctx, server)
	if err != nil {
		return nil, fmt.Errorf("dnscrypt session: %w", err)
	}

	// Choose the appropriate client based on protocol.
	client := c.dnscryptUDPClient
	if protocol == config.ProtoTCP {
		client = c.dnscryptTCPClient
	}

	resp, err := client.ExchangeContext(ctx, msg, info)
	if err != nil {
		// On exchange failure, clear the session so the next query
		// re-establishes the shared key.
		c.dnscryptSessions.Delete(dnscryptSessionKey(server))
		return nil, fmt.Errorf("dnscrypt exchange: %w", err)
	}

	return resp, nil
}

// cleanupDNSCryptSessions removes all cached DNSCrypt sessions.
func (c *Client) cleanupDNSCryptSessions() {
	c.dnscryptSessions.Range(func(key, _ any) bool {
		c.dnscryptSessions.Delete(key)
		return true
	})
}
