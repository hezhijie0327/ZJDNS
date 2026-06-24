package security

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"

	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
)

// Detector detects DNS hijacking by validating that a server does not return
// answer records outside its delegated zone authority. Only the Answer section
// is inspected — Authority and Additional sections carry delegation/glue data
// that the recursive resolver validates independently.
//
// The primary target is firewall/middlebox interception: a root server returning
// A records for www.google.com, or a TLD server returning A records for a
// subdomain. Detection triggers a UDP→TCP fallback which often bypasses the
// middlebox.
type Detector struct {
	enabled atomic.Bool
}

// IsEnabled returns whether hijack detection is currently active.
func (d *Detector) IsEnabled() bool {
	return d.enabled.Load()
}

// CheckResponse validates a DNS response for hijacking. Only the Answer section
// is checked — each record must be within the answering server's authority.
func (d *Detector) CheckResponse(currentDomain, queryDomain string, response *dns.Msg) (bool, string) {
	if !d.enabled.Load() || response == nil {
		return true, ""
	}

	currentDomain = dnsutil.NormalizeDomain(currentDomain)
	queryDomain = dnsutil.NormalizeDomain(queryDomain)

	for _, rr := range response.Answer {
		if valid, reason := d.checkRecord(rr, currentDomain, queryDomain); !valid {
			log.Debugf("SECURITY: hijack detected from %s: %s", currentDomain, reason)
			return false, reason
		}
	}

	return true, ""
}

// checkRecord validates a single record in the Answer section.
func (d *Detector) checkRecord(rr dns.RR, currentDomain, queryDomain string) (bool, string) {
	answerName := dnsutil.NormalizeDomain(rr.Header().Name)
	rrType := rr.Header().Rrtype

	// Only validate records that match the exact query name. Records for
	// other names (CNAME targets, sibling records) are not suspect.
	if answerName != queryDomain {
		return true, ""
	}

	// NS and DS records in the Answer section are delegation responses,
	// not injected answers.
	if rrType == dns.TypeNS || rrType == dns.TypeDS {
		return true, ""
	}

	return d.validateAnswer(currentDomain, queryDomain, rrType)
}

// validateAnswer checks that the answering server is authorized to return
// records for the queried domain.
func (d *Detector) validateAnswer(authorityDomain, queryDomain string, rrType uint16) (bool, string) {
	// Query domain must be within the server's authority zone.
	if !d.isInAuthority(queryDomain, authorityDomain) {
		return false, fmt.Sprintf("Server '%s' returned out-of-authority %s record for '%s'",
			authorityDomain, dns.TypeToString[rrType], queryDomain)
	}

	// Root zone (authorityDomain == ""): only glue records for root-servers.net
	// are allowed. Any other answer from a root server is hijacking.
	if authorityDomain == "" {
		return d.validateRootServer(queryDomain, rrType)
	}

	// TLD zone (e.g. "com", "cn"): TLD servers should only return records for
	// the TLD itself, never A/AAAA for subdomains.
	if d.isTLD(authorityDomain) {
		return d.validateTLDServer(authorityDomain, queryDomain, rrType)
	}

	return true, ""
}

func (d *Detector) validateRootServer(queryDomain string, rrType uint16) (bool, string) {
	if d.isRootServerGlue(queryDomain, rrType) {
		return true, ""
	}
	if queryDomain != "" {
		return false, fmt.Sprintf("Root server returned unauthorized %s record for '%s'",
			dns.TypeToString[rrType], queryDomain)
	}
	return true, ""
}

func (d *Detector) validateTLDServer(tldDomain, queryDomain string, rrType uint16) (bool, string) {
	if queryDomain != tldDomain {
		return false, fmt.Sprintf("TLD '%s' returned %s record in Answer for subdomain '%s'",
			tldDomain, dns.TypeToString[rrType], queryDomain)
	}
	return true, ""
}

func (d *Detector) isRootServerGlue(domain string, rrType uint16) bool {
	if rrType != dns.TypeA && rrType != dns.TypeAAAA {
		return false
	}
	return strings.HasSuffix(domain, ".root-servers.net") || domain == "root-servers.net"
}

func (d *Detector) isTLD(domain string) bool {
	return domain != "" && !strings.Contains(domain, ".")
}

func (d *Detector) isInAuthority(queryDomain, authorityDomain string) bool {
	if queryDomain == authorityDomain || authorityDomain == "" {
		return true
	}
	return strings.HasSuffix(queryDomain, "."+authorityDomain)
}

// Enable activates or deactivates hijack detection.
func (d *Detector) Enable(enabled bool) {
	d.enabled.Store(enabled)
}
