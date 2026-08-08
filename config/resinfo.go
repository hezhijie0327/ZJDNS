package config

import (
	"net/url"
	"strings"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

// resinfoKeys builds the RFC 9606 §5 key/value pairs this resolver advertises.
// Each key/value pair is one TXT character-string (RFC 6763 §6.3 format).
func resinfoKeys(cfg *ServerConfig) []string {
	// qnamemin: QNAME minimisation is always active (RFC 9156) — the key is
	// a boolean attribute (no '=' per RFC 6763 §6.4).
	keys := []string{"qnamemin"}

	// exterr: the EDE codes ZJDNS can actually return (RFC 9606 §5) —
	// derived from the ExtendedError* constants used across the middleware
	// chain and the DNSSEC validator: Other(0), UnsupportedDNSKEYAlgorithm(1),
	// StaleAnswer(3), ForgedAnswer(4), DNSBogus(6), SignatureExpired(7),
	// SignatureNotYetValid(8), RRSIGsMissing(10), NSECMissing(12),
	// Blocked(15), NoReachableAuthority(22), NetworkError(23),
	// InvalidQueryType(30).  The list must not advertise codes the codebase
	// never emits (2026-08 audit: dropped 2,5,9,11,13,14,19 — never
	// emitted; added 1,7,22,30 — emitted but missing).
	keys = append(keys, "exterr=0,1,3,4,6,7,8,10,12,15,22,23,30")

	if cfg != nil && cfg.Server.Features.DDR.InfoURL != "" {
		// RFC 9606 §5 requires an https:// URI; RFC 6763 §6.1 caps a TXT
		// character-string at 255 bytes — reject instead of advertising a
		// broken key (R2 finding).
		u, err := url.Parse(cfg.Server.Features.DDR.InfoURL)
		if err == nil && u.Scheme == "https" && len(cfg.Server.Features.DDR.InfoURL) <= 255 {
			keys = append(keys, "infourl="+cfg.Server.Features.DDR.InfoURL)
		} else {
			log.Warnf("CONFIG: DDR info_url %q ignored — must be an https:// URL under 255 bytes (RFC 9606 §5, RFC 6763 §6.1)", cfg.Server.Features.DDR.InfoURL)
		}
	}
	return keys
}

// addResolverInfoRecords publishes RFC 9606 RESINFO records for resolver.arpa
// and the DDR authentication domain.  RESINFO is part of the DDR ecosystem —
// clients discover the resolver via DDR (RFC 9462) and then query its
// capabilities — so it is published whenever DDR is enabled (and only then).
// RESINFO is a property of the resolver, answered authoritatively from the
// zone rules — never resolved recursively (RFC 9606 §3).
//
// The content is static (qnamemin + exterr + optional infourl), following the
// same ZoneRule injection pattern as addChaosRecord/addDDRRecords.
func addResolverInfoRecords(cfg *ServerConfig) {
	if !shouldEnableDDR(cfg) {
		return
	}

	names := []string{"resolver.arpa"}
	if cfg.Server.Certificate.Domain != "" {
		names = append(names, cfg.Server.Certificate.Domain)
	}

	keys := resinfoKeys(cfg)
	content := make([]string, 0, len(keys))
	for _, k := range keys {
		content = append(content, quoteTXT(k))
	}

	for _, name := range names {
		if hasZoneRule(cfg, name) {
			continue
		}
		cfg.Zone = append(cfg.Zone, ZoneRule{
			Name: name,
			Answer: []ZoneRecord{{
				Type:    dns.TypeRESINFO,
				Class:   dns.ClassINET,
				TTL:     DefaultRESINFOTTL,
				Content: strings.Join(content, " "),
			}},
		})
	}

	// RFC 9462 §4/§6.4: clients MUST NOT query A/AAAA for resolver.arpa —
	// serve NODATA locally instead of forwarding the SUDN upstream (R3-M13).
	// Added AFTER the RESINFO rules: a same-name sentinel would otherwise
	// make the hasZoneRule guard above skip the RESINFO records (live-test
	// catch — resolver.arpa TYPE261 returned empty).
	if !hasZoneRule(cfg, "resolver.arpa") {
		cfg.Zone = append(cfg.Zone, ZoneRule{Name: "resolver.arpa"})
	}
}
