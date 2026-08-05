package config

import (
	"strings"

	"codeberg.org/miekg/dns"
)

// resinfoKeys builds the RFC 9606 §5 key/value pairs this resolver advertises.
// Each key/value pair is one TXT character-string (RFC 6763 §6.3 format).
func resinfoKeys(cfg *ServerConfig) []string {
	// qnamemin: QNAME minimisation is always active (RFC 9156) — the key is
	// a boolean attribute (no '=' per RFC 6763 §6.4).
	keys := []string{"qnamemin"}

	// exterr: the EDE codes ZJDNS can return (RFC 9606 §5), matching the
	// codes used in middleware/cache_lookup.go, cache_store.go and the
	// DNSSEC validator.
	keys = append(keys, "exterr=3,6,7,9,15,16,17,18,21,22,23,24,30")

	if cfg != nil && cfg.Server.Features.DDR.InfoURL != "" {
		keys = append(keys, "infourl="+cfg.Server.Features.DDR.InfoURL)
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
}
