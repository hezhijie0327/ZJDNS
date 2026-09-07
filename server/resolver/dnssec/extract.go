package dnssec

import (
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// Record extraction helpers.

// CollectRRSIGs collects all RRSIG records from multiple RR slices.
func CollectRRSIGs(rrSets ...[]dns.RR) []*dns.RRSIG {
	total := 0
	for _, rrs := range rrSets {
		total += len(rrs)
	}
	sigs := make([]*dns.RRSIG, 0, total)
	for _, rrs := range rrSets {
		for _, rr := range rrs {
			if rrsig, ok := rr.(*dns.RRSIG); ok {
				sigs = append(sigs, rrsig)
			}
		}
	}
	return sigs
}

// FindRRSIGs filters RRSIG records by owner name and type covered.
func FindRRSIGs(sigs []*dns.RRSIG, ownerName string, typeCovered uint16) []*dns.RRSIG {
	if len(sigs) == 0 {
		return nil
	}
	// ownerName is already canonical from the DNS wire / resolver pipeline.
	var result []*dns.RRSIG
	for _, rrsig := range sigs {
		if rrsig == nil {
			continue
		}
		// DNS-aware name equality (RFC 4343): presentation-form strings that
		// are identical per RFC 4034 §6.1 (escapes, trailing dot, case) must
		// match; EqualFold would drop valid RRSIGs.
		if rrsig.TypeCovered == typeCovered && dns.EqualName(rrsig.Header().Name, ownerName) {
			result = append(result, rrsig)
		}
	}
	return result
}

// FindDNSKEYs extracts DNSKEY records from an RR slice.
func FindDNSKEYs(rrs []dns.RR) []*dns.DNSKEY {
	var keys []*dns.DNSKEY
	for _, rr := range rrs {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, dnskey)
		}
	}
	return keys
}

// FindDS extracts DS records from an RR slice.
func FindDS(rrs []dns.RR) []*dns.DS {
	var records []*dns.DS
	for _, rr := range rrs {
		if ds, ok := rr.(*dns.DS); ok {
			records = append(records, ds)
		}
	}
	return records
}

// FindCDS extracts CDS records from an RR slice (RFC 7344).
// CDS has the same wire format as DS but is a distinct RR type.
func FindCDS(rrs []dns.RR) []*dns.CDS {
	var records []*dns.CDS
	for _, rr := range rrs {
		if cds, ok := rr.(*dns.CDS); ok {
			records = append(records, cds)
		}
	}
	return records
}

// FindCDNSKEY extracts CDNSKEY records from an RR slice (RFC 7344).
// CDNSKEY embeds DNSKEY — same wire format but distinct RR type.
func FindCDNSKEY(rrs []dns.RR) []*dns.CDNSKEY {
	var records []*dns.CDNSKEY
	for _, rr := range rrs {
		if cdnskey, ok := rr.(*dns.CDNSKEY); ok {
			records = append(records, cdnskey)
		}
	}
	return records
}

// findNSEC extracts NSEC records from an RR slice.
func findNSEC(rrs []dns.RR) []*dns.NSEC {
	var records []*dns.NSEC
	for _, rr := range rrs {
		if nsec, ok := rr.(*dns.NSEC); ok {
			records = append(records, nsec)
		}
	}
	return records
}

// findNSEC3 extracts NSEC3 records from an RR slice.
func findNSEC3(rrs []dns.RR) []*dns.NSEC3 {
	var records []*dns.NSEC3
	for _, rr := range rrs {
		if nsec3, ok := rr.(*dns.NSEC3); ok {
			records = append(records, nsec3)
		}
	}
	return records
}

// DNS canonical ordering (RFC 4034 §6.1).

// canonicalCompare compares two domain names per DNS canonical ordering
// (RFC 4034 §6.1). Returns -1 if a < b, 0 if equal, 1 if a > b.
func canonicalCompare(a, b string) int {
	a = dnsutil.Canonical(a)
	b = dnsutil.Canonical(b)

	// dns.CompareName panics on the root zone "." — handle explicitly.
	if a == "." || b == "." {
		if a == b {
			return 0
		}
		if a == "." {
			return -1
		}
		return 1
	}
	return dns.CompareName(a, b)
}

// isDomainInRange checks whether a domain falls within an NSEC coverage range.
func isDomainInRange(name, lower, upper string) bool {
	loName := canonicalCompare(lower, name)
	naUp := canonicalCompare(name, upper)
	loUp := canonicalCompare(lower, upper)

	if loName < 0 && naUp < 0 {
		return true
	}

	if loUp > 0 {
		return loName < 0 || naUp < 0
	}
	if loUp == 0 {
		// RFC 4034 §4.1: Next Domain == owner — the NSEC covers the entire
		// namespace except the owner name itself.
		return loName != 0
	}

	return false
}

// Key caching helpers.

// CacheZoneKeys stores verified DNSKEYs for a zone in the unified cache.
// The covering RRSIGs' remaining validity caps the stored TTL per RFC 4035
// §5.3.3 — a key must never be trusted past the expiration of the signature
// that authenticated it.
func (c *CryptoValidator) CacheZoneKeys(zone string, keys []*dns.DNSKEY, sigs []*dns.RRSIG) {
	if c == nil || c.cache == nil || len(keys) == 0 {
		return
	}
	zone = dnsutil.Canonical(zone)

	// The keys are shared read-only — clone with the capped TTL for storage
	// only; the zoneKeyMemo keeps the originals for in-memory verification.
	rrKeys := make([]dns.RR, 0, len(keys))
	minTTL := -1
	for _, k := range keys {
		if k == nil {
			continue
		}
		ttl := k.Hdr.TTL
		if t := sigValidityCap(sigs, k); t < ttl {
			ttl = t
		}
		stored := *k
		stored.Hdr.TTL = ttl
		rrKeys = append(rrKeys, &stored)
		if ttl > 0 && (minTTL < 0 || int(ttl) < minTTL) {
			minTTL = int(ttl)
		}
	}
	c.cache.Set(zone, dns.TypeDNSKEY, dns.ClassINET, nil, rrKeys, nil, nil, true, 0)
	// Memoise the unpacked form alongside the raw cache entry so hits skip
	// the Unpack + filter round trip entirely — bounded by the same capped
	// TTL as the cache entry.
	if c.zoneKeyMemo != nil && minTTL > 0 {
		c.zoneKeyMemo.Set(zone, zoneKeyMemoEntry{keys: keys, expiry: log.NowUnix() + int64(minTTL)})
	}
}

// sigValidityCap returns the largest TTL allowed for a key by the remaining
// validity of the RRSIGs covering it (RFC 4035 §5.3.3). Unbounded when no
// signature covers the key.
func sigValidityCap(sigs []*dns.RRSIG, _ *dns.DNSKEY) uint32 {
	now := uint32(log.NowUnix()) //nolint:gosec // G115: DNSSEC timestamp — protocol-bounded uint32
	minRemaining := ^uint32(0)
	for _, sig := range sigs {
		if sig == nil {
			continue
		}
		remaining := sig.Expiration - now
		if serialLess(remaining, 1<<31) && remaining < minRemaining { //nolint:gosec // G115: RFC 1982 arithmetic
			minRemaining = remaining
		}
	}
	if minRemaining == ^uint32(0) {
		return ^uint32(0)
	}
	return minRemaining
}

// ZoneKeys retrieves cached verified DNSKEYs for a zone.  The unpacked key
// set is memoised until its cache TTL elapses — the raw-cache path re-Unpacked
// and re-filtered the RR set on every call (per delegation change, per walk).
// The returned keys are SHARED read-only: callers must not mutate them.
func (c *CryptoValidator) ZoneKeys(zone string) []*dns.DNSKEY {
	if c == nil || c.cache == nil {
		return nil
	}
	zone = dnsutil.Canonical(zone)

	if c.zoneKeyMemo != nil {
		if e, ok := c.zoneKeyMemo.Get(zone); ok {
			if log.NowUnix() < e.expiry {
				return e.keys
			}
			c.zoneKeyMemo.Delete(zone)
		}
	}

	cachedEntry, found, expired := c.cache.Get(zone, dns.TypeDNSKEY, dns.ClassINET, nil)
	if !found || cachedEntry == nil || expired {
		return nil
	}
	// cache.Get returns a pool-owned TTLOffsets slice — release it on every
	// exit path, or every DNSKEY cache hit (a per-delegation-change hot path)
	// leaks a pooled slice to the GC (R3-M15, same family as dns64).
	defer cachedEntry.ReleaseOffsets()
	// _ = error: an unpack failure leaves Answer nil — treated as a miss.
	_ = cachedEntry.Unpack()

	records := zdnsutil.ProcessRecords(cachedEntry.Answer, 0, false, true)
	keys := FindDNSKEYs(records)
	if c.zoneKeyMemo != nil && len(keys) > 0 {
		remaining := cachedEntry.TTL - int(log.NowUnix()-cachedEntry.Timestamp)
		if remaining > 0 {
			c.zoneKeyMemo.Set(zone, zoneKeyMemoEntry{keys: keys, expiry: log.NowUnix() + int64(remaining)})
		}
	}
	return keys
}

// RootKeys returns deep copies of the root trust anchor DNSKEYs. Callers must
// not mutate the anchors — they are security-critical validation state.
func (c *CryptoValidator) RootKeys() []*dns.DNSKEY {
	keys := make([]*dns.DNSKEY, len(c.rootKeys))
	for i, k := range c.rootKeys {
		keys[i] = k.Clone().(*dns.DNSKEY)
	}
	return keys
}
