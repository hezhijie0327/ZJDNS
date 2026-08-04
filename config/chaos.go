package config

import (
	"os"
	"strings"

	"codeberg.org/miekg/dns"
)

// addChaosRecord generates CHAOS-class TXT zone rules for standard DNS
// introspection queries: id.server, hostname.bind, version.server, version.bind,
// and per-table clearing endpoints.
//
// The .clear endpoints (cache/stats/ptr/latency/querylog/dnscrypt) are
// destructive and are gated to loopback clients in the Zone middleware —
// operators can add their own rules for the same names, which take
// precedence (see hasZoneRule). ruleset/zone rules are config-driven and
// rebuilt on restart, so they deliberately have no clear endpoint.
func addChaosRecord(cfg *ServerConfig) {
	version := DefaultVersion
	if version == "" || version == "dev" {
		version = DefaultProjectName
	}
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = DefaultProjectName
	}
	// Fixed slice, not a map: map iteration would randomize the zone rule
	// order on every run, making cfg.Zone non-reproducible.
	chaosRecords := []struct{ name, value string }{
		{"id.server", hostname},
		{"hostname.bind", hostname},
		{"version.server", version},
		{"version.bind", version},
	}
	for i := range chaosRecords {
		if hasZoneRule(cfg, chaosRecords[i].name) {
			// An operator-defined rule with the same name wins; appending
			// ours would be dead (first match wins in the evaluator).
			continue
		}
		cfg.Zone = append(cfg.Zone, ZoneRule{
			Name: chaosRecords[i].name,
			Answer: []ZoneRecord{{
				Type:    dns.TypeTXT,
				Class:   dns.ClassCHAOS,
				TTL:     DefaultTTL,
				Content: quoteTXT(chaosRecords[i].value),
			}},
		})
	}
	// Query names embed DefaultProjectName for self-identification and operator
	// discoverability (e.g. ZJDNS.stats, ZJDNS.cache.clear). This is intentional —
	// the project name identifies the server to clients that query these CHAOS records.
	for _, name := range []string{
		DefaultProjectName + ".stats",
		DefaultProjectName + ".stats.clear",
		DefaultProjectName + ".cache.clear",
		DefaultProjectName + ".ptr.clear",
		DefaultProjectName + ".latency.clear",
		DefaultProjectName + ".querylog.clear",
		DefaultProjectName + ".dnscrypt.clear",
	} {
		if hasZoneRule(cfg, name) {
			continue
		}
		// Placeholder Answer: this records only exists so the evaluator stores
		// a type-filtered entry (TXT CHAOS).  At query time wireZoneDynamicContent
		// replaces the static content with a live DynamicContent function.
		cfg.Zone = append(cfg.Zone, ZoneRule{
			Name:   name,
			Answer: []ZoneRecord{{Type: dns.TypeTXT, Class: dns.ClassCHAOS, TTL: 0, Content: `"dynamic"`}},
		})
	}
}

// hasZoneRule reports whether a zone rule with the given name already exists.
func hasZoneRule(cfg *ServerConfig, name string) bool {
	for i := range cfg.Zone {
		if strings.EqualFold(cfg.Zone[i].Name, name) {
			return true
		}
	}
	return false
}

// quoteTXT quotes a value for DNS TXT rdata. strconv.Quote produces Go
// escapes (\u, \x) that zone-file parsing does not understand — a non-ASCII
// hostname would be mangled. Escaping backslashes and quotes is the DNS
// master-file convention (RFC 1035 §5.1).
func quoteTXT(value string) string {
	escaped := strings.ReplaceAll(strings.ReplaceAll(value, "\\", "\\\\"), "\"", "\\\"")
	return "\"" + escaped + "\""
}
