package config

import (
	"os"
	"strconv"

	"codeberg.org/miekg/dns"
)

// addChaosRecord generates CHAOS-class TXT zone rules for standard DNS
// introspection queries: id.server, hostname.bind, version.server, version.bind,
// and per-table cache/stats clearing endpoints.
func addChaosRecord(cfg *ServerConfig) {
	version := DefaultVersion
	if version == "" || version == "dev" {
		version = DefaultProjectName
	}
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = DefaultProjectName
	}
	chaosRecords := map[string]string{
		"id.server":      hostname,
		"hostname.bind":  hostname,
		"version.server": version,
		"version.bind":   version,
	}
	for name, value := range chaosRecords {
		cfg.Zone = append(cfg.Zone, ZoneRule{
			Name: name,
			Answer: []ZoneRecord{{
				Type:    dns.TypeTXT,
				Class:   dns.ClassCHAOS,
				TTL:     DefaultTTL,
				Content: strconv.Quote(value),
			}},
		})
	}
	// Query names embed DefaultProjectName for self-identification and operator
	// discoverability (e.g. ZJDNS.stats, ZJDNS.db.clear). This is intentional —
	// the project name identifies the server to clients that query these CHAOS records.
	for _, name := range []string{
		DefaultProjectName + ".stats",
		DefaultProjectName + ".db.clear",
		DefaultProjectName + ".db.clear.cache",
		DefaultProjectName + ".db.clear.stats",
		DefaultProjectName + ".db.clear.querylog",
		DefaultProjectName + ".db.clear.latency",
		DefaultProjectName + ".db.clear.zone",
		DefaultProjectName + ".db.clear.ruleset",
	} {
		cfg.Zone = append(cfg.Zone, ZoneRule{
			Name:   name,
			Answer: []ZoneRecord{{Type: dns.TypeTXT, Class: dns.ClassCHAOS, TTL: 0, Content: ""}},
		})
	}
}
