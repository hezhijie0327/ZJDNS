package resolver

import (
	"strings"
	"zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	dnsutilv2 "codeberg.org/miekg/dns/dnsutil"
)

// minimiseQNAME strips the original QNAME to the given number of labels beyond
// the current zone. For example, with originalQname="www.foo.bar.example.com."
// and currentZone="example.com.", labelsToAdd=1 returns "bar.example.com.".
//
// When labelsToAdd exceeds the remaining labels, the full original QNAME is
// returned (resolution has reached the target).
func minimiseQNAME(originalQname, currentZone string, labelsToAdd int) string {
	orig := dnsutil.NormalizeDomain(originalQname)
	zone := dnsutil.NormalizeDomain(currentZone)

	// Root zone
	if zone == "" {
		labels := strings.Split(strings.TrimSuffix(orig, "."), ".")
		if labelsToAdd >= len(labels) {
			return dnsutilv2.Fqdn(orig)
		}
		return dnsutilv2.Fqdn(strings.Join(labels[len(labels)-labelsToAdd:], "."))
	}

	// QNAME equals the zone — reached the target
	if orig == zone {
		return dnsutilv2.Fqdn(orig)
	}

	// QNAME is not a subdomain of the current zone — return original
	if !strings.HasSuffix(orig, "."+zone) {
		return dnsutilv2.Fqdn(orig)
	}

	remaining := orig[:len(orig)-len(zone)-1] // strip "." + zone
	if remaining == "" {
		return dnsutilv2.Fqdn(orig)
	}

	remainingLabels := strings.Split(remaining, ".")
	if labelsToAdd >= len(remainingLabels) {
		return dnsutilv2.Fqdn(orig) // reached the target
	}

	// Take the rightmost 'labelsToAdd' labels from the remaining prefix
	suffix := strings.Join(remainingLabels[len(remainingLabels)-labelsToAdd:], ".")
	return dnsutilv2.Fqdn(suffix + "." + zone)
}

// labelCount returns the number of labels in a domain name. The root zone (".")
// returns 0.
func labelCount(name string) int {
	norm := dnsutil.NormalizeDomain(name)
	if norm == "" {
		return 0
	}
	return len(strings.Split(norm, "."))
}

// labelsToAdd computes how many labels to add in this minimisation step.
// Per RFC 9156 §2.3, the first MINIMISE_ONE_LAB steps add one label each
// for maximum privacy; after minimisationCount steps, all remaining labels
// are exposed at once to bound the total number of queries.
func labelsToAdd(originalQname, currentZone string, stepsTaken, minimisationCount, minimiseOneLabel int) int {
	origLabels := labelCount(originalQname)
	zoneLabels := labelCount(currentZone)
	remainingLabels := origLabels - zoneLabels
	if remainingLabels <= 0 {
		return 0
	}

	// After minimisationCount steps, expose all remaining labels at once.
	if stepsTaken >= minimisationCount {
		return remainingLabels
	}

	// First MINIMISE_ONE_LAB steps: add one label at a time.
	if stepsTaken < minimiseOneLabel {
		return 1
	}

	// Proportional phase: distribute remaining labels over remaining steps.
	remainingSteps := minimisationCount - minimiseOneLabel
	if remainingSteps <= 0 {
		return remainingLabels
	}

	labelsLeft := remainingLabels - minimiseOneLabel // labels not yet exposed after one-label phase
	if labelsLeft <= 0 {
		return remainingLabels
	}

	stepsInPhase := stepsTaken - minimiseOneLabel + 1 // 1-indexed
	perStep := labelsLeft / remainingSteps
	remainder := labelsLeft % remainingSteps

	add := perStep
	if stepsInPhase > remainingSteps-remainder {
		add++
	}
	if add < 1 {
		add = 1
	}
	if add > labelsLeft {
		add = labelsLeft
	}

	return add
}

// minimisationQtype returns the QTYPE to use for a minimised query.
// Per RFC 9156 §2.1, A is the recommended type. For DS, NSEC, NSEC3, and
// other types whose authority lies at the parent side, we use the original
// QTYPE but still minimise the QNAME.
func minimisationQtype(originalQtype uint16) uint16 {
	switch originalQtype {
	case dns.TypeDS, dns.TypeNSEC, dns.TypeNSEC3,
		dns.TypeOPT, dns.TypeTSIG, dns.TypeTKEY,
		dns.TypeANY, dns.TypeAXFR, dns.TypeIXFR:
		return originalQtype
	default:
		return dns.TypeA
	}
}
