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
		if valid, reason := d.checkRecord(rr, currentDomain, queryDomain); !valid {
			return false, reason
		}
	}

	// Also validate Authority and Additional sections for injected NS/glue
	// records that could redirect future queries to attacker-controlled servers.
	for _, rr := range response.Ns {
		if valid, reason := d.checkAuthorityRecord(rr, currentDomain); !valid {
			log.Debugf("SECURITY: suspicious NS in authority section from %s: %s %s, reason=%s",
				currentDomain, dns.TypeToString[rr.Header().Rrtype], rr.Header().Name, reason)
			return false, reason
		}
	}
	for _, rr := range response.Extra {
		rrType := rr.Header().Rrtype
		if rrType != dns.TypeA && rrType != dns.TypeAAAA {
			continue
		}
		if valid, reason := d.checkGlueRecord(rr, currentDomain, queryDomain); !valid {
			log.Debugf("SECURITY: suspicious glue in additional section from %s: %s %s, reason=%s",
				currentDomain, dns.TypeToString[rrType], rr.Header().Name, reason)
			return false, reason
		}
	}

	return true, ""
}

// checkRecord validates a single record in the Answer section.
func (d *Detector) checkRecord(rr dns.RR, currentDomain, queryDomain string) (bool, string) {
	answerName := dnsutil.NormalizeDomain(rr.Header().Name)
	rrType := rr.Header().Rrtype

	if answerName != queryDomain {
		return true, ""
	}

	if rrType == dns.TypeNS || rrType == dns.TypeDS {
		return true, ""
	}

	return d.validateAnswer(currentDomain, queryDomain, rrType)
}

// checkAuthorityRecord validates NS records in the Authority section to
// prevent injection of malicious delegation redirects.
func (d *Detector) checkAuthorityRecord(rr dns.RR, currentDomain string) (bool, string) {
	rrType := rr.Header().Rrtype
	if rrType != dns.TypeNS {
		return true, "" // only validate NS records in authority
	}
	nsName := dnsutil.NormalizeDomain(rr.Header().Name)
	// NS records in authority should name the delegated zone
	if !d.isInAuthority(nsName, currentDomain) && !d.isInAuthority(currentDomain, nsName) {
		return false, fmt.Sprintf("NS record in authority names unrelated zone '%s'", nsName)
	}
	return true, ""
}

// checkGlueRecord validates A/AAAA glue records in the Additional section.
func (d *Detector) checkGlueRecord(rr dns.RR, currentDomain, queryDomain string) (bool, string) {
	glueName := dnsutil.NormalizeDomain(rr.Header().Name)
	rrType := rr.Header().Rrtype
	// Glue records must name a server within the authority's domain
	if !d.isInAuthority(glueName, currentDomain) && glueName != currentDomain {
		return false, fmt.Sprintf("Glue %s record names server outside authority zone: '%s'",
			dns.TypeToString[rrType], glueName)
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
