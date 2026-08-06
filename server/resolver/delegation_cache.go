package resolver

import (
	"fmt"
	"strings"
	"zjdns/config"
	"zjdns/database"
	"zjdns/internal/log"
	"zjdns/server/defense"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// delegationRecord is a row from the delegations table, parsed into Go types.
// ds is nil for insecure delegations (authenticated no-DS denial).
type delegationRecord struct {
	zone      string
	parent    string
	nsNames   []string
	addrs     []string // snapshot fallback when NS-address cache is cold
	ds        []*dns.DS
	timestamp int64
	ttl       int
}

// ancestorZones returns the ancestor zones of qname from deepest to shallowest,
// excluding the root zone.  "www.baidu.com." → ["www.baidu.com.", "baidu.com.",
// "com."]; "." → empty. The full qname is included so that a zone-cut cache hit
// for the qname itself works for non-parent-side types.  At most
// config.DefaultDelegationLookupZones entries are returned.
func ancestorZones(qname string) []string {
	fq := dnsutil.Fqdn(qname)
	if fq == "." {
		return nil
	}
	// Split by dots: "www.baidu.com." → ["www", "baidu", "com"]
	labels := strings.Split(fq[:len(fq)-1], ".")
	if len(labels) == 0 {
		return nil
	}
	limit := min(len(labels), config.DefaultDelegationLookupZones)
	zones := make([]string, 0, limit)
	for i := range limit {
		zone := strings.Join(labels[i:], ".") + "."
		zones = append(zones, zone)
	}
	return zones
}

// parentSideType reports whether qtype belongs to the parent side of a zone
// cut per RFC 4035 §1.  DS, NSEC, and NSEC3 records are served by the parent
// zone, not the child.
func parentSideType(qtype uint16) bool {
	return qtype == dns.TypeDS || qtype == dns.TypeNSEC || qtype == dns.TypeNSEC3
}

// minDelegationTTL returns the minimum positive TTL across NS and DS records,
// floored at DefaultTTL and capped at DefaultMaxCacheableTTL.  Mirrors
// cache.minTTL (cache/store.go).
func minDelegationTTL(nsRecords []*dns.NS, dsRecords []*dns.DS) int {
	ttl := config.DefaultMaxCacheableTTL
	check := func(rrTTL uint32) {
		if rrTTL > 0 {
			t := int(rrTTL) //nolint:gosec // G115: DNS TTLs fit in int
			if t < ttl {
				ttl = t
			}
		}
	}
	for _, ns := range nsRecords {
		check(ns.Header().TTL)
	}
	for _, ds := range dsRecords {
		check(ds.Header().TTL)
	}
	if ttl <= 0 || ttl > config.DefaultMaxCacheableTTL {
		ttl = config.DefaultMaxCacheableTTL
	}
	if ttl < config.DefaultTTL {
		ttl = config.DefaultTTL
	}
	return ttl
}

// nsNamesFrom extracts the canonical NS target names from NS records.
func nsNamesFrom(nsRecords []*dns.NS) []string {
	names := make([]string, 0, len(nsRecords))
	for _, ns := range nsRecords {
		if ns.Ns != "" {
			names = append(names, dnsutil.Canonical(ns.Ns))
		}
	}
	return names
}

// packDS packs DS records into a DNS message wire.  The result is nil when ds
// is empty (used as the insecure-delegation marker in the delegations table).
func packDS(ds []*dns.DS) []byte {
	if len(ds) == 0 {
		return nil
	}
	msg := &dns.Msg{}
	for _, d := range ds {
		msg.Answer = append(msg.Answer, d)
	}
	if err := msg.Pack(); err != nil {
		return nil
	}
	return msg.Data
}

// unpackDS unpacks DS records from a DNS message wire produced by packDS.
// Returns nil when wire is empty or unpacking fails (the insecure-delegation
// case).
func unpackDS(wire []byte) []*dns.DS {
	if len(wire) == 0 {
		return nil
	}
	msg := &dns.Msg{Data: wire}
	if err := msg.Unpack(); err != nil {
		return nil
	}
	var ds []*dns.DS
	for _, rr := range msg.Answer {
		if d, ok := rr.(*dns.DS); ok {
			ds = append(ds, d)
		}
	}
	return ds
}

// storeDelegation persists a zone-cut delegation discovered during a recursive
// walk.  Only verified delegations (secure DS verified, or authenticated
// no-DS) are stored; unverifiable and poisoned delegations are skipped.
func (r *Recursive) storeDelegation(zone, parent string, nsRecords []*dns.NS, addrs []string, chain *dnssecChain, verdict defense.Verdict) {
	if r.db == nil {
		return
	}
	if verdict == defense.VerdictPoisoned {
		return
	}
	if chain.dsPresentButUnverified {
		return
	}

	zone = dnsutil.Canonical(zone)
	parent = dnsutil.Canonical(parent)
	nsNames := nsNamesFrom(nsRecords)
	if len(nsNames) == 0 {
		return
	}

	nsNamesStr := strings.Join(nsNames, "\n")
	addrsStr := strings.Join(addrs, "\n")
	ttl := minDelegationTTL(nsRecords, chain.childDS)
	ts := log.NowUnix()

	var dsWire []byte
	if len(chain.childDS) > 0 {
		dsWire = packDS(chain.childDS)
	}
	// dsWire is nil for insecure delegations (authenticated no-DS denial).

	if _, err := r.db.StmtDelegationStore.Exec(zone, parent, nsNamesStr, addrsStr, dsWire, ts, ttl, ts+int64(ttl)); err != nil {
		log.Debugf("RECURSION: store delegation %s: %v", zone, err)
	}
}

// lookupDelegation searches for the deepest fresh delegation whose zone is an
// ancestor of (or equal to) qname.  Parent-side qtypes (DS, NSEC, NSEC3) skip
// a delegation whose zone matches the qname exactly, because the parent — not
// the child — is authoritative for those records (RFC 4035 §1).
func (r *Recursive) lookupDelegation(qname string, qtype uint16) (*delegationRecord, bool) {
	if r.db == nil {
		return nil, false
	}

	zones := ancestorZones(qname)
	if len(zones) == 0 {
		return nil, false
	}

	// For parent-side qtypes at the qname exactly, skip the qname zone.
	if dns.EqualName(zones[0], dnsutil.Canonical(dnsutil.Fqdn(qname))) && parentSideType(qtype) {
		zones = zones[1:]
		if len(zones) == 0 {
			return nil, false
		}
	}

	// Bind zones to the IN clause; pad remaining placeholders with empty string.
	args := make([]any, database.DelegationLookupZones)
	for i, z := range zones {
		args[i] = z
	}
	for i := len(zones); i < database.DelegationLookupZones; i++ {
		args[i] = ""
	}

	row := r.db.StmtDelegationLookup.QueryRow(args...)
	var rec delegationRecord
	var nsNamesStr, addrsStr string
	var dsWire []byte
	if err := row.Scan(&rec.zone, &rec.parent, &nsNamesStr, &addrsStr, &dsWire, &rec.timestamp, &rec.ttl); err != nil {
		return nil, false
	}

	rec.nsNames = strings.Split(nsNamesStr, "\n")
	rec.addrs = strings.Split(addrsStr, "\n")
	if len(dsWire) > 0 {
		rec.ds = unpackDS(dsWire)
	}

	return &rec, true
}

// resolveDelegationAddrs resolves the NS names in a delegation record to
// "ip:port" addresses.  The NS-address cache is checked first (latency-sorted,
// probe-refreshed); the stored snapshot is used as a fallback when the cache
// is cold.
func (r *Recursive) resolveDelegationAddrs(record *delegationRecord) []string {
	var addrs []string
	for _, nsName := range record.nsNames {
		addrs = append(addrs, r.lookupNSAddrsFromCache(nsName, nil)...)
	}
	if len(addrs) > 0 {
		return addrs
	}
	return record.addrs
}

// applyDelegationStart seeds the walk state from a cached delegation record.
// The DNSSEC chain is rebuilt so that downstream validation proceeds exactly as
// if the walk had reached this zone organically.
func (r *Recursive) applyDelegationStart(nameservers *[]string, currentDomain *string, tldServers *[]string, chain *dnssecChain, record *delegationRecord) error {
	addrs := r.resolveDelegationAddrs(record)
	if len(addrs) == 0 {
		return fmt.Errorf("delegation %s: no addresses available", record.zone)
	}

	*nameservers = addrs
	*currentDomain = record.zone

	// Reconstruct the DNSSEC chain: the child DS was verified against the
	// parent's DNSKEYs during the original walk, so starting from this zone
	// is cryptographically equivalent to having walked there.
	// Only seed the DS — DNSKEYs are intentionally left nil so that the
	// first isDNSSECValid / ensureZoneDNSKEYs call queries the zone's
	// NS for fresh DNSKEYs and verifies them against the cached DS in-band.
	// Pre-seeding stale DNSKEYs from cache can produce false "bogus" errors
	// when the cached key tags don't match the answer's RRSIG.
	*chain = dnssecChain{childDS: record.ds}

	// A single-label zone is a TLD — save its servers for the hijack probe.
	if dnsutil.Labels(dnsutil.Fqdn(record.zone)) == 1 {
		*tldServers = addrs
	} else {
		*tldServers = nil
	}

	return nil
}
