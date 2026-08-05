package defense

import (
	"strings"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// Verdict classifies a DNS response from a server that claims authority for
// a given zone.  It answers: "is this response suspicious for this zone?"
type Verdict int

// Detector detects DNS hijacking by validating that a server does not return
// answer records outside its delegated zone authority. Only the Answer section
// is inspected — Authority and Additional sections carry delegation/glue data
// that the recursive resolver validates independently.
//
// The primary target is firewall/middlebox interception: a root server returning
// A records for www.google.com, or a TLD server returning A records for a
// subdomain. Detection triggers a UDP→TCP fallback which often bypasses the
// middlebox.
//
// Enablement is gated at the call site via Recursive.poisonguard — the Detector
// itself is always active when constructed.
type Detector struct{}

const (
	// VerdictClean means the response is consistent with the zone's
	// authority — no hijacking detected.
	VerdictClean Verdict = iota

	// VerdictPoisoned means the response contains records the zone's
	// server should never return (e.g. a root server returning an A
	// record for www.google.com).
	VerdictPoisoned

	// VerdictUncertain means the zone *could* legitimately return
	// these records, but content analysis alone cannot distinguish a
	// real authoritative answer from a GFW-injected one.  This is the
	// authoritative-level blind spot.
	//
	// NOTE: no caller currently consumes VerdictUncertain (VerdictPoisoned
	// is the only actionable signal).  It is retained as the return path of
	// the classification switch so future multi-vantage-point analysis can
	// consume it without changing classify()'s contract.
	VerdictUncertain
)

const rootServersDomain = "root-servers.net"

// --- Verdict methods ---

func (v Verdict) String() string {
	switch v {
	case VerdictClean:
		return "clean"
	case VerdictPoisoned:
		return "poisoned"
	case VerdictUncertain:
		return "uncertain"
	default:
		return "unknown"
	}
}

// --- Detector methods ---

// Validate checks whether a DNS response from a server authoritative for zone
// is legitimate for the given queryName.  Only the Answer section is inspected.
//
//	zone == "."       → root server
//	isTLD(zone)       → TLD server (e.g. "com", "cn")
//	otherwise         → authoritative server
func (d *Detector) Validate(zone, queryName string, response *dns.Msg) Verdict {
	if response == nil {
		return VerdictClean
	}

	z := dnsutil.Canonical(zone)
	n := dnsutil.Canonical(queryName)

	for _, rr := range response.Answer {
		if rr == nil {
			continue // defensive: malformed responses must not panic the validator (R2)
		}
		if dnsutil.Canonical(rr.Header().Name) != n {
			continue
		}
		if v := d.classify(z, n, dns.RRToType(rr)); v != VerdictClean {
			if v == VerdictPoisoned {
				log.Debugf("SECURITY: poison detected from %s: %s record for '%s' → %s",
					zone, dns.TypeToString[dns.RRToType(rr)], queryName, rr.String())
			}
			return v
		}
	}
	return VerdictClean
}

// IsPoisonedByTLD checks whether a TLD or root server returned
// direct A/AAAA answers for a query name.  Those servers never
// put A/AAAA in the Answer section for a subdomain — if they
// do, the response was injected by a middlebox.
func (d *Detector) IsPoisonedByTLD(response *dns.Msg, queryName string) bool {
	if response == nil {
		return false
	}
	n := dnsutil.Canonical(queryName)
	// Root-server hostnames and TLD-apex queries legitimately get A/AAAA
	// answers from root/TLD servers (see classifyRoot/classifyTLD) — flagging
	// them would force an unnecessary TCP fallback for every such query.
	if d.isRootServerDomain(n) || d.isTLD(n) {
		return false
	}
	for _, rr := range response.Answer {
		if rr == nil {
			continue
		}
		if dnsutil.Canonical(rr.Header().Name) != n {
			continue
		}
		switch dns.RRToType(rr) {
		case dns.TypeA, dns.TypeAAAA:
			return true
		}
	}
	return false
}

// classify returns the Verdict for a single RR that matches the query name.
func (d *Detector) classify(zone, name string, rrtype uint16) Verdict {
	switch {
	case zone == ".":
		return d.classifyRoot(name, rrtype)
	case d.isTLD(zone):
		return d.classifyTLD(zone, name, rrtype)
	default:
		// Authoritative level: the zone can legitimately return
		// these records, but we can't distinguish real answers from
		// GFW-injected ones by content alone.
		return VerdictUncertain
	}
}

// classifyRoot validates responses from root servers.  Legitimate root
// responses only contain:
//   - Any record type for root-servers.net (SOA, RRSIG, NSEC, A, AAAA, etc.)
//   - NS/DS records for TLDs (e.g. "com", "cn")
//
// delegationOrProof reports whether rrtype is a delegation or DNSSEC proof
// record — the only record types a parent-zone server legitimately returns
// for a child name (NS/DS delegations plus their RRSIG signatures and
// NSEC/NSEC3 denial-of-existence proofs, RFC 4035 §3.1.1).
func delegationOrProof(rrtype uint16) bool {
	switch rrtype {
	case dns.TypeNS, dns.TypeDS, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
		return true
	}
	return false
}

func (d *Detector) classifyRoot(name string, rrtype uint16) Verdict {
	// Glue records for root server hostnames.
	if d.isRootServerDomain(name) {
		return VerdictClean
	}

	// NS/DS records for TLDs are legitimate root delegations; their RRSIG
	// and NSEC/NSEC3 proofs accompany them and must be exempted too.
	if delegationOrProof(rrtype) && d.isTLD(name) {
		return VerdictClean
	}

	if name != "." {
		return VerdictPoisoned
	}
	return VerdictClean
}

// classifyTLD validates responses from TLD servers.  TLD servers should only
// return records for the TLD itself (e.g. SOA for "com"), never A/AAAA for
// subdomains — with one legitimate exception: delegation records (DS/NS) for
// subdomains, which TLD servers answer routinely (e.g. DS for example.com
// from the com servers). This mirrors the delegation exemption in
// classifyRoot; without it, DS queries for signed child zones were judged
// Poisoned and the DNSSEC chain broke with SERVFAIL.
func (d *Detector) classifyTLD(zone, name string, rrtype uint16) Verdict {
	if name != zone {
		// Child-zone delegation and DNSSEC proof records (NS/DS/RRSIG/
		// NSEC/NSEC3) are legitimate from a TLD server — it hosts the
		// delegation, and may host the child zone itself (e.g. CNNIC
		// serves both cn and com.cn, answering com.cn NS queries with an
		// authoritative NS RRset + RRSIG). Data records (A/AAAA/CNAME/…)
		// for child names remain the GFW injection signature → Poisoned.
		if delegationOrProof(rrtype) && dnsutil.IsBelow(dnsutil.Fqdn(zone), dnsutil.Fqdn(name)) {
			return VerdictClean
		}
		return VerdictPoisoned
	}
	return VerdictClean
}

func (d *Detector) isRootServerDomain(domain string) bool {
	return dnsutil.IsBelow(dnsutil.Fqdn(rootServersDomain), dnsutil.Fqdn(domain))
}

func (d *Detector) isTLD(domain string) bool {
	// Normalise by stripping the trailing dot (if present) so that both
	// "com" and "com." are recognised as TLDs while "example.com" is
	// correctly excluded.  dnsutil.Labels("com") = 1, "com." = 2,
	// "example.com" = 2, "example.com." = 3.
	if domain == "" {
		return false
	}
	domain = strings.TrimSuffix(domain, ".")
	return dnsutil.Labels(domain) == 1
}
