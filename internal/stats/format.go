package stats

import (
	"fmt"
	"slices"
	"strings"
	"zjdns/internal/topk"
)

// statsMetric is a single (name, count, percentage) entry for the stats TXT
// output.  Zero-count entries are omitted by formatStatsLine.
type statsMetric struct {
	name  string
	count int64
	pct   float64
}

// FormatLines returns aggregated query statistics as formatted TXT records:
// the totals, result classes, rcodes, transport protocols, and DNSSEC
// validation classes, zero-count entries omitted.  entryCount (the cache's
// entry count) is passed through by the caller.
func (m *Journal) FormatLines(entryCount int64) []string {
	snap := m.Snapshot(entryCount)
	total := snap.Total
	totalMS := snap.TotalMS

	var avgMs float64
	if total > 0 {
		avgMs = float64(totalMS) / float64(total)
	}

	// Percentages relative to total (DNSSEC rows relative to the validated
	// subset).
	pct := func(v int64) float64 {
		if total == 0 {
			return 0
		}
		return float64(v) / float64(total) * 100
	}
	hitR, missR, staleR, zoneR := pct(snap.Hits), pct(snap.Misses), pct(snap.Stales), pct(snap.Zones)
	blockedR, badcookieR, errorR := pct(snap.Blocked), pct(snap.Badcookie), pct(snap.Errors)
	noerrR, formerrR, servfailR := pct(snap.Noerr), pct(snap.Formerr), pct(snap.Servfail)
	nxR, nimpR, refR, otherR := pct(snap.NXDomain), pct(snap.Notimp), pct(snap.Refused), pct(snap.Other)
	udpR, tcpR, tlsR, quicR := pct(snap.UDP), pct(snap.TCP), pct(snap.TLS), pct(snap.QUIC)
	httpsR, http3R, dtlsR := pct(snap.HTTPS), pct(snap.HTTP3), pct(snap.DTLS)
	dnscryptR, dnscryptTCPR, tlcpR, httpTLCPR, dtlcpR := pct(snap.DNSCrypt), pct(snap.DNSCryptTCP), pct(snap.TLCP), pct(snap.HTTPTLCP), pct(snap.DTLCP)
	dnssecTotal := snap.Secure + snap.Insecure + snap.Bogus
	poisonedR := pct(snap.Poisoned)
	var dnssecR, dnssecIR, dnssecBR float64
	if dnssecTotal > 0 {
		dt := float64(dnssecTotal)
		dnssecR = float64(snap.Secure) / dt * 100
		dnssecIR = float64(snap.Insecure) / dt * 100
		dnssecBR = float64(snap.Bogus) / dt * 100
	}

	out := make([]string, 0, 7)
	out = append(out, fmt.Sprintf("entries=%d total=%d avg=%.1fms",
		snap.Entries, total, avgMs))

	// Results — omit zero-count entries.
	if s := formatStatsLine(
		statsMetric{"hit", snap.Hits, hitR}, statsMetric{"miss", snap.Misses, missR},
		statsMetric{"stale", snap.Stales, staleR}, statsMetric{"zone", snap.Zones, zoneR},
		statsMetric{"blocked", snap.Blocked, blockedR}, statsMetric{"badcookie", snap.Badcookie, badcookieR},
		statsMetric{"error", snap.Errors, errorR},
	); s != "" {
		out = append(out, s)
	}

	// Rcodes.
	if s := formatStatsLine(
		statsMetric{"noerr", snap.Noerr, noerrR}, statsMetric{"formerr", snap.Formerr, formerrR},
		statsMetric{"servfail", snap.Servfail, servfailR}, statsMetric{"nx", snap.NXDomain, nxR},
		statsMetric{"nimp", snap.Notimp, nimpR}, statsMetric{"ref", snap.Refused, refR},
		statsMetric{"other", snap.Other, otherR},
	); s != "" {
		out = append(out, s)
	}

	// Transport protocols.
	if s := formatStatsLine(
		statsMetric{"udp", snap.UDP, udpR}, statsMetric{"tcp", snap.TCP, tcpR},
		statsMetric{"tls", snap.TLS, tlsR}, statsMetric{"quic", snap.QUIC, quicR},
		statsMetric{"https", snap.HTTPS, httpsR}, statsMetric{"http3", snap.HTTP3, http3R},
		statsMetric{"dtls", snap.DTLS, dtlsR}, statsMetric{"dnscrypt", snap.DNSCrypt, dnscryptR},
		statsMetric{"dnscrypt-tcp", snap.DNSCryptTCP, dnscryptTCPR}, statsMetric{"tlcp", snap.TLCP, tlcpR},
		statsMetric{"http-tlcp", snap.HTTPTLCP, httpTLCPR}, statsMetric{"dtlcp", snap.DTLCP, dtlcpR},
	); s != "" {
		out = append(out, s)
	}

	// DNSSEC — percentages relative to the DNSSEC-validated subset.
	if s := formatStatsLine(
		statsMetric{"secure", snap.Secure, dnssecR}, statsMetric{"insecure", snap.Insecure, dnssecIR},
		statsMetric{"bogus", snap.Bogus, dnssecBR},
	); s != "" {
		out = append(out, s)
	}

	// Poisoned stands alone — it is orthogonal to DNSSEC status, so mixing
	// it into the DNSSEC line would break that line's 100% invariant.
	if s := formatStatsLine(statsMetric{"poisoned", snap.Poisoned, poisonedR}); s != "" {
		out = append(out, s)
	}

	return out
}

// FormatRcodeLines returns the per-RCODE top-N domain journal lines — the
// highest-count domain names per RCODE, for debugging which domains produce
// the most NXDOMAIN/SERVFAIL etc.  Served by the zjdns.stats.rcode CHAOS
// query, separate from the aggregated FormatLines output.
func (m *Journal) FormatRcodeLines() []string {
	snap := m.Snapshot(0)
	var out []string
	for _, rcode := range sortedRcodes(snap.TopByRcode) {
		var b strings.Builder
		fmt.Fprintf(&b, "top-rcode%d:", rcode)
		for _, e := range snap.TopByRcode[rcode] {
			fmt.Fprintf(&b, " %s=%d", e.Key, e.Count)
		}
		out = append(out, b.String())
	}
	return out
}

// sortedRcodes returns the journal RCODE keys in ascending order so repeated
// output is stable.
func sortedRcodes(byRcode map[int][]topk.Entry[string]) []int {
	rcodes := make([]int, 0, len(byRcode))
	for rc := range byRcode {
		rcodes = append(rcodes, rc)
	}
	slices.Sort(rcodes)
	return rcodes
}

// formatStatsLine renders a partitioned stats line: zero-count entries are
// skipped, nonzero entries appear as "name=count(pct%)".
func formatStatsLine(metrics ...statsMetric) string {
	n := 0
	for _, m := range metrics {
		if m.count != 0 {
			n++
		}
	}
	if n == 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(n * 40)
	for _, m := range metrics {
		if m.count == 0 {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s=%d(%.1f%%)", m.name, m.count, m.pct)
	}
	return b.String()
}
