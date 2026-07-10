package security

import (
	"strings"
	"zjdns/cache"
	"zjdns/config"

	"codeberg.org/miekg/dns"
)

// Record extraction helpers.

// CollectRRSIGs collects all RRSIG records from multiple RR slices.
func CollectRRSIGs(slices ...[]dns.RR) []*dns.RRSIG {
	total := 0
	for _, rrs := range slices {
		total += len(rrs)
	}
	sigs := make([]*dns.RRSIG, 0, total)
	for _, rrs := range slices {
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
	normalized := strings.ToLower(ownerName)
	var result []*dns.RRSIG
	for _, rrsig := range sigs {
		if rrsig == nil {
			continue
		}
		if rrsig.TypeCovered == typeCovered && strings.EqualFold(rrsig.Header().Name, normalized) {
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

// DNS canonical ordering (RFC 4034 \xa76.1).

// canonicalCompare compares two domain names per DNS canonical ordering.
// Returns -1 if a < b, 0 if equal, 1 if a > b.
func canonicalCompare(a, b string) int {
	a = strings.ToLower(strings.TrimSuffix(a, "."))
	b = strings.ToLower(strings.TrimSuffix(b, "."))

	if a == "" && b == "" {
		return 0
	}
	if a == "" {
		return -1
	}
	if b == "" {
		return 1
	}

	la := strings.Split(a, ".")
	lb := strings.Split(b, ".")

	i, j := len(la)-1, len(lb)-1
	for i >= 0 && j >= 0 {
		if la[i] < lb[j] {
			return -1
		}
		if la[i] > lb[j] {
			return 1
		}
		i--
		j--
	}

	if i < 0 && j < 0 {
		return 0
	}
	if i < 0 {
		return -1
	}
	return 1
}

// isDomainInRange checks whether a domain falls within an NSEC coverage range.
func isDomainInRange(name, lower, upper string) bool {
	loName := canonicalCompare(lower, name)
	naUp := canonicalCompare(name, upper)
	loUp := canonicalCompare(lower, upper)

	if loName < 0 && naUp < 0 {
		return true
	}

	if loUp >= 0 {
		return loName < 0 || naUp < 0
	}

	return false
}

// Key caching helpers.

// CacheZoneKeys stores verified DNSKEYs for a zone in the unified cache.
func (c *CryptoValidator) CacheZoneKeys(zone string, keys []*dns.DNSKEY) {
	if c == nil || c.cache == nil || len(keys) == 0 {
		return
	}
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))

	ttl := config.DefaultDNSKeyCacheTTL
	for _, k := range keys {
		if k != nil && int(k.Header().TTL) > 0 && int(k.Header().TTL) < ttl {
			ttl = int(k.Header().TTL)
		}
	}
	rrKeys := make([]dns.RR, 0, len(keys))
	for _, k := range keys {
		if k != nil {
			rrKeys = append(rrKeys, k)
		}
	}
	c.cache.Set(zone, dns.TypeDNSKEY, dns.ClassINET, nil, false, rrKeys, nil, nil, true)
}

// ZoneKeys retrieves cached verified DNSKEYs for a zone.
func (c *CryptoValidator) ZoneKeys(zone string) []*dns.DNSKEY {
	if c == nil || c.cache == nil {
		return nil
	}
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))

	cachedEntry, found, expired := c.cache.Get(zone, dns.TypeDNSKEY, dns.ClassINET, nil, false)
	if !found || cachedEntry == nil || expired {
		return nil
	}

	records := cache.ProcessRecords(cachedEntry.Answer, 0, false, true)
	return FindDNSKEYs(records)
}

// RootKeys returns the root trust anchor DNSKEYs.
func (c *CryptoValidator) RootKeys() []*dns.DNSKEY {
	return c.rootKeys
}
