package dnssec

import (
	"zjdns/cache"

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
func (c *CryptoValidator) CacheZoneKeys(zone string, keys []*dns.DNSKEY) {
	if c == nil || c.cache == nil || len(keys) == 0 {
		return
	}
	zone = dnsutil.Canonical(zone)

	// cache.Set derives the entry TTL from the RR TTLs itself (minTTL, capped
	// at DefaultMaxCacheableTTL); the old ttl loop was dead code and the
	// intended DefaultDNSKeyCacheTTL cap was never applied.
	rrKeys := make([]dns.RR, 0, len(keys))
	for _, k := range keys {
		if k != nil {
			rrKeys = append(rrKeys, k)
		}
	}
	c.cache.Set(zone, dns.TypeDNSKEY, dns.ClassINET, nil, false, rrKeys, nil, nil, true, dns.RcodeSuccess)
}

// ZoneKeys retrieves cached verified DNSKEYs for a zone.
func (c *CryptoValidator) ZoneKeys(zone string) []*dns.DNSKEY {
	if c == nil || c.cache == nil {
		return nil
	}
	zone = dnsutil.Canonical(zone)

	cachedEntry, found, expired := c.cache.Get(zone, dns.TypeDNSKEY, dns.ClassINET, nil, false)
	if !found || cachedEntry == nil || expired {
		return nil
	}

	records := cache.ProcessRecords(cachedEntry.Answer, 0, false, true)
	return FindDNSKEYs(records)
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
