// Package main implements ZJDNS - High Performance DNS Server
package main

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// DNSSECValidator validates DNSSEC-signed DNS responses.
type DNSSECValidator struct{}

// HijackPrevention detects and mitigates DNS hijack attempts.
type HijackPrevention struct {
	enabled atomic.Bool
}

// SecurityManager coordinates DNSSEC validation and hijack prevention.
type SecurityManager struct {
	tls    *TLSManager
	dnssec *DNSSECValidator
	hijack *HijackPrevention
}

// ValidateResponse validates DNSSEC records in a DNS response.
// It checks if the response has DNSSEC records and if the AD flag is set.
func (v *DNSSECValidator) ValidateResponse(response *dns.Msg, dnssecOK bool) bool {
	if !dnssecOK || response == nil {
		return false
	}

	// If the response has the Authenticated Data flag set, it's validated
	if response.AuthenticatedData {
		LogDebug("DNSSEC: validated via AD flag")
		return true
	}

	// Check for DNSSEC record types in the response
	if v.hasDNSSECRecords(response) {
		LogDebug("DNSSEC: validated via DNSSEC record presence")
		return true
	}
	return false
}

// hasDNSSECRecords checks if the response contains any DNSSEC-related record types.
// DNSSEC record types include: RRSIG, NSEC, NSEC3, DNSKEY, DS
func (v *DNSSECValidator) hasDNSSECRecords(response *dns.Msg) bool {
	if response == nil {
		return false
	}

	// Check all sections for DNSSEC records
	for _, sections := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, rr := range sections {
			switch rr.(type) {
			case *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.DNSKEY, *dns.DS:
				return true
			}
		}
	}

	return false
}

// IsEnabled returns whether hijack prevention is enabled.
func (hp *HijackPrevention) IsEnabled() bool {
	return hp.enabled.Load()
}

// CheckResponse validates a DNS response for potential hijacking attempts.
// It checks if the responding server is authorized to provide answers for the queried domain.
// Returns (true, "") if valid, (false, reason) if hijacking is detected.
func (hp *HijackPrevention) CheckResponse(currentDomain, queryDomain string, response *dns.Msg) (bool, string) {
	if !hp.enabled.Load() || response == nil {
		return true, ""
	}

	currentDomain = NormalizeDomain(currentDomain)
	queryDomain = NormalizeDomain(queryDomain)

	// Check each answer record for authorization violations
	for _, rr := range response.Answer {
		answerName := NormalizeDomain(rr.Header().Name)
		rrType := rr.Header().Rrtype

		// Skip if the answer name doesn't match the query
		if answerName != queryDomain {
			continue
		}

		// NS and DS records are allowed from any authoritative server
		if rrType == dns.TypeNS || rrType == dns.TypeDS {
			continue
		}

		// Validate the answer against the server's authority
		if valid, reason := hp.validateAnswer(currentDomain, queryDomain, rrType); !valid {
			LogDebug("HIJACK: detected for %s from authority=%s, record=%s %s, reason=%s",
				queryDomain, currentDomain, dns.TypeToString[rrType], rr.Header().Name, reason)
			return false, reason
		}
	}

	return true, ""
}

// validateAnswer checks if a server has authority to return a specific record type.
func (hp *HijackPrevention) validateAnswer(authorityDomain, queryDomain string, rrType uint16) (bool, string) {
	// Check if the query domain is within the server's authority
	if !hp.isInAuthority(queryDomain, authorityDomain) {
		return false, fmt.Sprintf("Server '%s' returned out-of-authority %s record for '%s'",
			authorityDomain, dns.TypeToString[rrType], queryDomain)
	}

	// Root server validation
	if authorityDomain == "" {
		return hp.validateRootServer(queryDomain, rrType)
	}

	// TLD server validation
	if hp.isTLD(authorityDomain) {
		return hp.validateTLDServer(authorityDomain, queryDomain, rrType)
	}

	return true, ""
}

// validateRootServer checks if a root server response is valid.
// Root servers should only return glue records for other root servers.
func (hp *HijackPrevention) validateRootServer(queryDomain string, rrType uint16) (bool, string) {
	// Allow glue records for root servers
	if hp.isRootServerGlue(queryDomain, rrType) {
		return true, ""
	}

	// Root servers should not return final answers for non-root domains
	if queryDomain != "" {
		return false, fmt.Sprintf("Root server returned unauthorized %s record for '%s'",
			dns.TypeToString[rrType], queryDomain)
	}

	return true, ""
}

// validateTLDServer checks if a TLD server response is valid.
// TLD servers should only return records for their own TLD.
func (hp *HijackPrevention) validateTLDServer(tldDomain, queryDomain string, rrType uint16) (bool, string) {
	// TLD servers should only answer for their own TLD
	if queryDomain != tldDomain {
		return false, fmt.Sprintf("TLD '%s' returned %s record in Answer for subdomain '%s'",
			tldDomain, dns.TypeToString[rrType], queryDomain)
	}

	return true, ""
}

// isRootServerGlue checks if the domain is a root server glue record.
// Root server glue records are A/AAAA records for *.root-servers.net.
func (hp *HijackPrevention) isRootServerGlue(domain string, rrType uint16) bool {
	// Only A and AAAA records can be glue records
	if rrType != dns.TypeA && rrType != dns.TypeAAAA {
		return false
	}

	// Check if this is a root server domain
	return strings.HasSuffix(domain, ".root-servers.net") || domain == "root-servers.net"
}

// isTLD checks if a domain is a top-level domain (single label).
func (hp *HijackPrevention) isTLD(domain string) bool {
	return domain != "" && !strings.Contains(domain, ".")
}

// isInAuthority checks if a query domain is within a server's authority zone.
func (hp *HijackPrevention) isInAuthority(queryDomain, authorityDomain string) bool {
	// Exact match or root authority
	if queryDomain == authorityDomain || authorityDomain == "" {
		return true
	}

	// Check if query domain is a subdomain of the authority zone
	return strings.HasSuffix(queryDomain, "."+authorityDomain)
}

// SetHijackPreventionEnabled enables or disables hijack prevention.
func (hp *HijackPrevention) SetHijackPreventionEnabled(enabled bool) {
	hp.enabled.Store(enabled)
}

// NewSecurityManager creates a new SecurityManager with the given configuration.
// It initializes DNSSEC validation, hijack prevention, and optional TLS management.
func NewSecurityManager(config *ServerConfig, server *DNSServer) (*SecurityManager, error) {
	sm := &SecurityManager{
		dnssec: &DNSSECValidator{},
		hijack: &HijackPrevention{},
	}

	// Enable hijack prevention if configured
	sm.hijack.enabled.Store(config.Server.Features.HijackProtection)

	// Initialize TLS manager if certificates are configured
	if config.Server.TLS.SelfSigned || (config.Server.TLS.CertFile != "" && config.Server.TLS.KeyFile != "") {
		tlsMgr, err := NewTLSManager(server, config)
		if err != nil {
			return nil, fmt.Errorf("create TLS manager: %w", err)
		}
		sm.tls = tlsMgr
	}

	return sm, nil
}

// Shutdown gracefully shuts down the security manager and all its components.
// It closes the TLS manager if it exists.
func (sm *SecurityManager) Shutdown(timeout time.Duration) error {
	if sm.tls != nil {
		return sm.tls.shutdown()
	}
	return nil
}

// GetDNSSECValidator returns the DNSSEC validator instance.
func (sm *SecurityManager) GetDNSSECValidator() *DNSSECValidator {
	return sm.dnssec
}

// GetHijackPrevention returns the hijack prevention instance.
func (sm *SecurityManager) GetHijackPrevention() *HijackPrevention {
	return sm.hijack
}

// GetTLSManager returns the TLS manager instance.
func (sm *SecurityManager) GetTLSManager() *TLSManager {
	return sm.tls
}
