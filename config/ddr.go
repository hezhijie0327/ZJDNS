package config

import (
	"fmt"
	"sort"
	"strings"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

// protoDef describes a single protocol endpoint for DDR SVCB record generation.
// Each enabled protocol contributes one entry; entries sharing the same port are
// merged into a single SVCB record with all ALPNs.
type protoDef struct {
	port     string
	alpn     string
	endpoint string // only HTTP-based protocols
}

// aggRecord accumulates ALPNs per port during DDR SVCB aggregation.
type aggRecord struct {
	port    string
	alpns   map[string]bool
	dohpath string // best-effort: first HTTP endpoint wins
}

// flatRecord is a sorted, flattened SVCB record ready for content generation.
type flatRecord struct {
	port    string
	alpns   string // comma-separated, sorted
	dohpath string
	http    bool
}

// shouldEnableDDR checks whether DDR advertisement should be generated.
// DDR requires a certificate domain, at least one IPv4 or IPv6 hint, and at
// least one enabled secure protocol.
func shouldEnableDDR(cfg *ServerConfig) bool {
	ddr := cfg.Server.Features.DDR
	if cfg.Server.Certificate.Domain == "" || (ddr.IPv4 == "" && ddr.IPv6 == "") {
		return false
	}
	// At least one secure protocol must be enabled — otherwise there is
	// nothing to advertise.
	p := cfg.Server.Protocol
	return p.TLS != "" || p.QUIC != "" || p.HTTPS.Port != "" || p.HTTP3.Port != "" ||
		p.DTLS != "" || p.TLCP != "" || p.DTLCP != "" || p.HTTPTLCP.Port != ""
}

// addDDRRecords generates SVCB zone rules for RFC 9462 Discovery of Designated
// Resolvers.  It creates one SVCB record per unique port, aggregating ALPNs
// from all protocols that share the same port.
//
// Protocol → ALPN mapping:
//
//	HTTPS → h2,  HTTP3 → h3,  HTTP_TLCP → h2
//	TLS → dot,   QUIC → doq,  DTLS → dot,   TLCP → dot,   DTLCP → dot
func addDDRRecords(cfg *ServerConfig) {
	ddr := cfg.Server.Features.DDR
	domain := strings.TrimSuffix(cfg.Server.Certificate.Domain, ".")

	if strings.ContainsAny(domain, " \"") || strings.ContainsAny(ddr.IPv4, " \"") || strings.ContainsAny(ddr.IPv6, " \"") {
		log.Warnf("CONFIG: DDR domain/IP contains unsafe characters, DDR records will not be added")
		return
	}
	if domain == "" {
		log.Warnf("CONFIG: DDR domain is empty, DDR records will not be added")
		return
	}

	normalizeEndpoint := func(ep string) string {
		if ep == "" {
			ep = DefaultQueryPath
		}
		if !strings.HasPrefix(ep, "/") {
			ep = "/" + ep
		}
		return ep
	}

	// Zone equivalents.
	zoneDirectRecords := make([]ZoneRecord, 0, 2)
	if ddr.IPv4 != "" {
		zoneDirectRecords = append(zoneDirectRecords, ZoneRecord{Type: dns.TypeA, Content: ddr.IPv4})
	}
	if ddr.IPv6 != "" {
		zoneDirectRecords = append(zoneDirectRecords, ZoneRecord{Type: dns.TypeAAAA, Content: ddr.IPv6})
	}
	if len(zoneDirectRecords) > 0 {
		cfg.Zone = append(cfg.Zone, ZoneRule{Name: domain, Answer: zoneDirectRecords})
	}

	ddrNames := []string{"_dns.resolver.arpa", "_dns." + domain}
	if cfg.Server.Protocol.UDP != "" && cfg.Server.Protocol.UDP != DefaultUDPPort {
		ddrNames = append(ddrNames, "_"+cfg.Server.Protocol.UDP+"._dns."+domain)
	}

	// Build SVCB records for all enabled encrypted protocols.
	// Each unique port gets one record; ALPNs are aggregated from all
	// protocols that share the same port.
	defs := []protoDef{
		{cfg.Server.Protocol.HTTPS.Port, "h2", cfg.Server.Protocol.HTTPS.Endpoint},
		{cfg.Server.Protocol.HTTP3.Port, "h3", cfg.Server.Protocol.HTTP3.Endpoint},
		{cfg.Server.Protocol.HTTPTLCP.Port, "h2", cfg.Server.Protocol.HTTPTLCP.Endpoint},
		{cfg.Server.Protocol.TLS, "dot", ""},
		{cfg.Server.Protocol.QUIC, "doq", ""},
		{cfg.Server.Protocol.DTLS, "dot", ""},
		{cfg.Server.Protocol.TLCP, "dot", ""},
		{cfg.Server.Protocol.DTLCP, "dot", ""},
	}

	byPort := make(map[string]*aggRecord)

	for _, d := range defs {
		if d.port == "" {
			continue
		}
		r, ok := byPort[d.port]
		if !ok {
			r = &aggRecord{port: d.port, alpns: make(map[string]bool)}
			byPort[d.port] = r
		}
		r.alpns[d.alpn] = true
		if d.endpoint != "" && r.dohpath == "" {
			r.dohpath = normalizeEndpoint(d.endpoint)
		}
	}

	// Sort records: HTTP-based first (those with dohpath), then stream-based,
	// each group ordered by port for determinism.
	var records []flatRecord
	for _, r := range byPort {
		alpnList := make([]string, 0, len(r.alpns))
		for a := range r.alpns {
			alpnList = append(alpnList, a)
		}
		sort.Strings(alpnList)
		records = append(records, flatRecord{
			port:    r.port,
			alpns:   strings.Join(alpnList, ","),
			dohpath: r.dohpath,
			http:    r.dohpath != "",
		})
	}
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].http != records[j].http {
			return records[i].http // HTTP first
		}
		return records[i].port < records[j].port
	})

	zoneServiceRecords := make([]ZoneRecord, 0, len(records))
	for priority, r := range records {
		var content string
		if r.dohpath != "" {
			content = fmt.Sprintf("%d . alpn=%s port=%s dohpath=\"%s{?dns}\"",
				priority+1, r.alpns, r.port, r.dohpath)
		} else {
			content = fmt.Sprintf("%d . alpn=%s port=%s",
				priority+1, r.alpns, r.port)
		}
		zoneServiceRecords = append(zoneServiceRecords, ZoneRecord{Type: dns.TypeSVCB, Content: content})
	}

	var zoneAdditional []ZoneRecord
	if ddr.IPv4 != "" {
		for i := range zoneServiceRecords {
			zoneServiceRecords[i].Content += " ipv4hint=" + ddr.IPv4
		}
		zoneAdditional = append(zoneAdditional, ZoneRecord{Name: domain, Type: dns.TypeA, Content: ddr.IPv4})
	}
	if ddr.IPv6 != "" {
		for i := range zoneServiceRecords {
			zoneServiceRecords[i].Content += " ipv6hint=" + ddr.IPv6
		}
		zoneAdditional = append(zoneAdditional, ZoneRecord{Name: domain, Type: dns.TypeAAAA, Content: ddr.IPv6})
	}

	for _, name := range ddrNames {
		cfg.Zone = append(cfg.Zone, ZoneRule{Name: name, Answer: zoneServiceRecords, Additional: zoneAdditional})
	}

	var ipInfo string
	switch {
	case ddr.IPv4 != "" && ddr.IPv6 != "":
		ipInfo = fmt.Sprintf("IPv4=%s IPv6=%s", ddr.IPv4, ddr.IPv6)
	case ddr.IPv4 != "":
		ipInfo = "IPv4=" + ddr.IPv4
	default:
		ipInfo = "IPv6=" + ddr.IPv6
	}
	log.Infof("CONFIG: DDR enabled for domain %s (%s, records: %d)",
		domain, ipInfo, len(zoneServiceRecords))
}
