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

	// Collect CNAME targets from the answer section. When an authoritative
	// server returns a CNAME to a different zone, it may also include NS
	// records for the target zone in the Authority section. This is standard
	// DNS referral behavior, not hijacking.
	var cnameTargets []string
	for _, rr := range response.Answer {
		if cname, ok := rr.(*dns.CNAME); ok {
			cnameTargets = append(cnameTargets, dnsutil.NormalizeDomain(cname.Target))
		}
	}

	// Pre-compute the set of domains that glue records are allowed to
	// be under. This includes both the exact NS target names and their
	// parent domains (e.g. ns1.qq.com → {ns1.qq.com, qq.com}).
	// Glue records in the Additional section are legitimate as long as
	// they relate to an NS target that has already been validated by
	// checkAuthorityRecord.
	nsTargetDomains := make(map[string]bool)
	for _, rr := range response.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			nsName := dnsutil.NormalizeDomain(ns.Ns)
			nsTargetDomains[nsName] = true
			// Strip the first label to get the parent domain so
			// CDN-pool glue records (ns-cmn1.qq.com) sharing the
			// same parent (qq.com) as an NS target are accepted.
			if dotIdx := strings.IndexByte(nsName, '.'); dotIdx != -1 {
				nsTargetDomains[nsName[dotIdx+1:]] = true
			}
		}
	}

	// Also validate Authority and Additional sections for injected NS/glue
	// records that could redirect future queries to attacker-controlled servers.
	for _, rr := range response.Ns {
		if valid, reason := d.checkAuthorityRecord(rr, currentDomain, cnameTargets); !valid {
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
		if valid, reason := d.checkGlueRecord(rr, currentDomain, nsTargetDomains); !valid {
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
func (d *Detector) checkAuthorityRecord(rr dns.RR, currentDomain string, cnameTargets []string) (bool, string) {
	rrType := rr.Header().Rrtype
	if rrType != dns.TypeNS {
		return true, "" // only validate NS records in authority
	}
	nsName := dnsutil.NormalizeDomain(rr.Header().Name)
	// NS records in authority should name the delegated zone
	if d.isInAuthority(nsName, currentDomain) || d.isInAuthority(currentDomain, nsName) {
		return true, ""
	}
	// When the answer contains a CNAME to a different zone, the authority
	// section may include NS records for the CNAME target's zone. This is
	// standard DNS referral behavior, not hijacking (RFC 1034 §4.3.2).
	for _, target := range cnameTargets {
		if d.isInAuthority(target, nsName) {
			return true, ""
		}
	}
	return false, fmt.Sprintf("NS record in authority names unrelated zone '%s'", nsName)
}

// checkGlueRecord validates A/AAAA glue records in the Additional section.
// Glue is legitimate if it falls within the current zone or relates to an
// NS target from the already-validated Authority section (cross-zone delegation).
// nsTargetDomains is a pre-computed set of NS target names and their parent
// domains (e.g. {ns1.qq.com, qq.com}).
func (d *Detector) checkGlueRecord(rr dns.RR, currentDomain string, nsTargetDomains map[string]bool) (bool, string) {
	glueName := dnsutil.NormalizeDomain(rr.Header().Name)
	rrType := rr.Header().Rrtype

	// In-bailiwick: within the current zone
	if d.isInAuthority(glueName, currentDomain) || glueName == currentDomain {
		return true, ""
	}

	// Cross-zone delegation: under an NS target or its parent domain.
	// The Authority section NS records have already passed checkAuthorityRecord,
	// so any glue that helps resolve those NS targets is legitimate.
	for targetDomain := range nsTargetDomains {
		if d.isInAuthority(glueName, targetDomain) {
			return true, ""
		}
	}

	return false, fmt.Sprintf("Glue %s record names server outside authority zone: '%s'",
		dns.TypeToString[rrType], glueName)
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
