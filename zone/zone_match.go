// Zone-rule matching: the evaluation walk (exact, wildcard, dynamic
// upstream-fetched), specificity selection, and tag/QTYPE gating.

package zone

import (
	"net"
	"strconv"
	"strings"
	"zjdns/config"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// ruleTypeMatches reports whether a wildcard rule's (qtype, qclass) matches
// the query — the rule must match exactly, or be a sentinel rule (0, 0).
func ruleTypeMatches(r *zoneRule, qtype, qclass uint16) bool {
	return (r.qtype == qtype && r.qclass == qclass) || (r.qtype == 0 && r.qclass == 0)
}

// Evaluate checks a query against loaded zone rules.
// matchedTags is the set of ruleset tags the client IP/domain matched.
// nil or empty map means no CIDR matching is active.
func (e *Evaluator) Evaluate(qname string, qtype, qclass uint16, matchedTags map[string]bool, clientIP net.IP) Result {
	if qclass == 0 {
		qclass = dns.ClassINET
	}
	if len(qname) > config.MaxDomainLength {
		return Result{Rcode: dns.RcodeSuccess}
	}

	table := e.table.Load()

	// 0. Check global bypass rules — if any matches, skip zone entirely.
	for i, tags := range table.bypass {
		score := matchScore(tags, matchedTags)
		if log.IsDebug() {
			log.Debugf("ZONE: bypass[%d] tags=%v client_tags=%v score=%d", i, tags, matchedTags, score)
		}
		if score > 0 {
			if log.IsDebug() {
				log.Debugf("ZONE: bypass matched, skipping zone for %s", qname)
			}
			return Result{Rcode: dns.RcodeSuccess}
		}
	}

	if e.ruleCount.Load() == 0 && len(table.bypass) == 0 {
		return Result{Rcode: dns.RcodeSuccess}
	}

	// Callers pass the canonical FQDN (handler canonicalizes qctx.Qname) —
	// Fqdn is a zero-alloc suffix check, and strings.ToLower uses the ASCII
	// fast path (no allocation when already lowercase).  dnsutil.Canonical
	// would re-lowercase via always-allocating strings.Map.
	qname = strings.ToLower(dnsutil.Fqdn(qname))

	// 1. Check dynamic content.
	if de, ok := table.dynamics[qname]; ok {
		return e.evalDynamic(qname, qtype, qclass, de, clientIP)
	}

	loadedAt := e.loadedAt.Load()

	// 2. Exact composite key lookup.
	if r := e.lookupExact(table, qname, qtype, qclass, matchedTags, loadedAt); r.Matched {
		return r
	}

	// 3. Sentinel key (rcode-only rules).
	if r := e.lookupExact(table, qname, 0, 0, matchedTags, loadedAt); r.Matched {
		return r
	}

	// 4. Wildcard suffix walk — deepest suffix first (the most specific
	// suffix wins equal scores).  Per-suffix buckets are pre-sorted by qtype
	// DESC so concrete qtype rows win ties against sentinel rows.
	return e.lookupWildcard(table, qname, qtype, qclass, matchedTags, loadedAt)
}

// bestMatch scores the candidate rules for a lookup key and returns the
// highest-scoring match.  Bucket order is deterministic (sorted at load), so
// equal-score ties resolve the same way on every query.  When wildcard is
// true, only rules whose (qtype, qclass) matches the query — or sentinel
// rules (0, 0) — are considered.
func (e *Evaluator) bestMatch(rules []*zoneRule, qname string, wildcard bool, qtype, qclass uint16, matchedTags map[string]bool, loadedAt int64) Result {
	var bestScore int
	var best Result
	for _, r := range rules {
		if wildcard && !ruleTypeMatches(r, qtype, qclass) {
			continue
		}
		score := matchScore(r.matchTags, matchedTags)
		if score < 0 {
			continue
		}
		if score <= bestScore && best.Matched {
			continue // not better than current best
		}
		bestScore = score
		best = Result{
			Domain:     r.qname,
			Matched:    true,
			Wildcard:   wildcard,
			Rcode:      r.rcode,
			Answer:     r.answer,
			Authority:  r.authority,
			Additional: r.additional,
			CreatedAt:  loadedAt,
			score:      score,
		}
	}
	if !best.Matched {
		return Result{Rcode: dns.RcodeSuccess}
	}
	// The winner's RRs are shared with the immutable rule table — clone
	// them once so the caller can mutate headers in place.
	best.Answer = cloneRRs(best.Answer)
	best.Authority = cloneRRs(best.Authority)
	best.Additional = cloneRRs(best.Additional)
	return best
}

func (e *Evaluator) lookupExact(table *zoneTable, qname string, qtype, qclass uint16, matchedTags map[string]bool, loadedAt int64) Result {
	return e.bestMatch(table.exactRules[exactKey{qname: qname, qtype: qtype, qclass: qclass}], qname, false, 0, 0, matchedTags, loadedAt)
}

// lookupWildcard walks the suffix candidates of qname from deepest to
// shallowest and returns the best wildcard match across all of them.
// Untagged rules score 0, so bestScore starts at -1 — the first (deepest)
// match is always accepted, equal scores keep the deeper suffix, and only a
// strictly higher score replaces it.
func (e *Evaluator) lookupWildcard(table *zoneTable, qname string, qtype, qclass uint16, matchedTags map[string]bool, loadedAt int64) Result {
	bestScore := -1
	var best Result
	rest := qname
	for {
		idx := strings.IndexByte(rest, '.')
		if idx < 0 {
			break
		}
		rest = rest[idx+1:]
		if rest == "" {
			break
		}
		if r := e.bestMatch(table.wildcardRules[rest], rest, true, qtype, qclass, matchedTags, loadedAt); r.Matched {
			if r.score > bestScore {
				bestScore = r.score
				best = r
			}
		}
	}
	return best
}

func (e *Evaluator) evalDynamic(qname string, qtype, qclass uint16, de *dynamicEntry, clientIP net.IP) Result {
	var contents []string
	if len(de.configs) == 0 {
		// No config records — invoke the dynamic function for every
		// query (e.g. ZJDNS.cache.clear rules that have no static
		// answer records, only a DynamicContent function).
		contents = de.fn(clientIP)
	} else {
		for _, rec := range de.configs {
			recClass := rec.Class
			if recClass == 0 {
				recClass = dns.ClassINET
			}
			if rec.Type == qtype && recClass == qclass {
				if contents == nil {
					contents = de.fn(clientIP)
				}
				break
			}
		}
	}

	result := Result{
		Domain:    qname,
		Matched:   len(contents) > 0,
		Rcode:     dns.RcodeSuccess,
		CreatedAt: e.loadedAt.Load(),
	}
	for _, content := range contents {
		rr := buildRecord(qname, &config.ZoneRecord{
			Type:    dns.TypeTXT,
			Class:   dns.ClassCHAOS,
			Content: strconv.Quote(content),
		})
		if rr != nil {
			result.Answer = append(result.Answer, rr)
		}
	}
	return result
}
