// Upstream-server validation: per-server protocol/address/defense checks,
// match-rule references, and RFC 10029 MQTYPE bundle validation.

package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
)

func validateUpstreamServers(cfg *ServerConfig, rulesetTags map[string]bool) error {
	validProtocols := map[string]bool{
		// Built-in recursive
		ProtoRecursive: true,

		// Plain DNS
		ProtoUDP: true,
		ProtoTCP: true,

		// TLS-based
		ProtoTLS:   true,
		ProtoQUIC:  true,
		ProtoHTTPS: true,
		ProtoHTTP3: true,
		ProtoDTLS:  true,

		// DNSCrypt
		ProtoDNSCrypt:    true,
		ProtoDNSCryptTCP: true,

		// TLCP-based (GB/T 38636-2020)
		ProtoTLCP:     true,
		ProtoHTTPTLCP: true,

		// DTLS-based (GM/T 0128-2023)
		ProtoDTLCP: true,
	}

	for i := range cfg.Upstream {
		server := &cfg.Upstream[i]
		protocol := strings.ToLower(server.Protocol)
		if server.Protocol != "" && !validProtocols[protocol] {
			return fmt.Errorf("upstream server %d protocol invalid: %s", i, server.Protocol)
		}

		if !server.IsRecursive() {
			// Stamp addresses are parsed during normalization — the raw
			// sdns:// string is not a valid host:port or URL.
			if !strings.HasPrefix(server.Address, "sdns://") {
				if _, _, err := net.SplitHostPort(server.Address); err != nil {
					if protocol == ProtoHTTPS || protocol == ProtoHTTP3 ||
						protocol == ProtoHTTPTLCP {
						// url.Parse accepts empty strings and scheme-less
						// hosts — both silently dial ':443' later (R3-M10).
						u, err := url.Parse(server.Address)
						if err != nil || u.Scheme == "" || u.Host == "" {
							return fmt.Errorf("upstream server %d address invalid for %s: %q", i, protocol, server.Address)
						}
					} else {
						return fmt.Errorf("upstream server %d address invalid: %w", i, err)
					}
				}
			}
		}
		// DNSCrypt-specific checks for stamp-free configs.
		if (protocol == ProtoDNSCrypt || protocol == ProtoDNSCryptTCP) && !strings.HasPrefix(server.Address, "sdns://") {
			if server.ServerName == "" {
				return fmt.Errorf("upstream server %d using dnscrypt requires server_name (provider name)", i)
			}
			if server.PublicKey == "" {
				return fmt.Errorf("upstream server %d using dnscrypt requires public_key", i)
			}
		}

		// Generic server_name requirement for encrypted transports.
		if zdnsutil.IsSecureProtocol(protocol) && server.ServerName == "" && !strings.HasPrefix(server.Address, "sdns://") {
			return fmt.Errorf("upstream server %d using %s requires server_name", i, server.Protocol)
		}

		// Validate privacy profile for TLS-based protocols.
		// Strict mode (default) rejects skip_tls_verify; opportunistic allows it.
		// DNSCrypt has its own key infrastructure and doesn't use TLS certificates.
		if zdnsutil.IsSecureProtocol(protocol) && server.PrivacyProfile == PrivacyProfileStrict && server.SkipTLSVerify &&
			protocol != ProtoDNSCrypt && protocol != ProtoDNSCryptTCP {
			return fmt.Errorf("upstream server %d: privacy_profile=strict requires skip_tls_verify=false", i)
		}

		if server.Proxy != "" {
			u, err := url.Parse(server.Proxy)
			if err != nil {
				return fmt.Errorf("upstream server %d proxy URL invalid: %w", i, err)
			}
			if u.Scheme != ProtoSOCKS5 {
				return fmt.Errorf("upstream server %d proxy scheme must be %s (got %q)", i, ProtoSOCKS5, u.Scheme)
			}
			if u.Hostname() == "" {
				return fmt.Errorf("upstream server %d proxy host required", i)
			}
			if p := u.Port(); p != "" {
				if port, err := strconv.Atoi(p); err != nil || port < 1 || port > MaxPortNumber {
					return fmt.Errorf("upstream server %d proxy port invalid: %s", i, p)
				}
			}
		}

		for _, matchTag := range server.Match {
			cleanTag := strings.TrimPrefix(matchTag, "!")
			if !rulesetTags[cleanTag] {
				return fmt.Errorf("upstream server %d: match tag '%s' not found", i, cleanTag)
			}
		}

		if err := validateMQType(server); err != nil {
			return fmt.Errorf("upstream server %d: %w", i, err)
		}
	}

	// Fallback upstreams are only meaningful alongside at least one primary:
	// an all-fallback list has nothing to fall back FROM, and every response
	// would carry the uncacheable fallback EDE.
	hasFallback, hasPrimary := false, false
	for i := range cfg.Upstream {
		if cfg.Upstream[i].Fallback {
			hasFallback = true
		} else {
			hasPrimary = true
		}
	}
	if hasFallback && !hasPrimary {
		return errors.New("upstream: fallback servers require at least one non-fallback upstream")
	}
	return nil
}

// validateMQType validates an upstream's RFC 10029 MQTYPE-Query list: every
// value must be a registered data RRTYPE (RFC 6895 §3.1), unique, and within
// the RFC 10029 §4 QTx cap.
func validateMQType(server *UpstreamServer) error {
	if len(server.MQType) == 0 {
		return nil
	}
	if len(server.MQType) > DefaultMQTypeMaxQTx {
		return fmt.Errorf("mqtype: at most %d types allowed (RFC 10029 §4), got %d", DefaultMQTypeMaxQTx, len(server.MQType))
	}
	seen := make(map[uint16]struct{}, len(server.MQType))
	for _, qt := range server.MQType {
		if dns.TypeToString[qt] == "" {
			return fmt.Errorf("mqtype: unknown QTYPE %d", qt)
		}
		if _, meta := MQTypeMetaTypes[qt]; meta {
			return fmt.Errorf("mqtype: QTYPE %d (%s) is a Meta/QTYPE and must not appear in the list (RFC 6895 §3.1)", qt, dns.TypeToString[qt])
		}
		if _, dup := seen[qt]; dup {
			return fmt.Errorf("mqtype: duplicate QTYPE %d", qt)
		}
		seen[qt] = struct{}{}
	}
	return nil
}
