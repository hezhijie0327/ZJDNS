package security

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"

	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
)

// Detector detects DNS hijacking by validating that authoritative servers
// return responses within their delegated zone authority.
type Detector struct {
	enabled atomic.Bool
}

// IsEnabled returns whether hijack detection is currently active.
func (d *Detector) IsEnabled() bool {
	return d.enabled.Load()
}

// CheckResponse validates a DNS response for hijacking by ensuring the
// answering server is authorized for the records it returns.
func (d *Detector) CheckResponse(currentDomain, queryDomain string, response *dns.Msg) (bool, string) {
	if !d.enabled.Load() || response == nil {
		return true, ""
	}

	currentDomain = dnsutil.NormalizeDomain(currentDomain)
	queryDomain = dnsutil.NormalizeDomain(queryDomain)

	for _, rr := range response.Answer {
		answerName := dnsutil.NormalizeDomain(rr.Header().Name)
		rrType := rr.Header().Rrtype

		if answerName != queryDomain {
			continue
		}

		if rrType == dns.TypeNS || rrType == dns.TypeDS {
			continue
		}

		if valid, reason := d.validateAnswer(currentDomain, queryDomain, rrType); !valid {
			log.Debugf("SECURITY: detected for %s from authority=%s, record=%s %s, reason=%s",
				queryDomain, currentDomain, dns.TypeToString[rrType], rr.Header().Name, reason)
			return false, reason
		}
	}

	return true, ""
}

func (d *Detector) validateAnswer(authorityDomain, queryDomain string, rrType uint16) (bool, string) {
	if !d.isInAuthority(queryDomain, authorityDomain) {
		return false, fmt.Sprintf("Server '%s' returned out-of-authority %s record for '%s'",
			authorityDomain, dns.TypeToString[rrType], queryDomain)
	}

	if authorityDomain == "" {
		return d.validateRootServer(queryDomain, rrType)
	}

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
