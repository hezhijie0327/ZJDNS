// RFC 8020 NXDOMAIN cut: a cached NXDOMAIN for a name denies its whole
// subtree.  The index is an exact-name set (RFC 8020 App. A: the SOA owner
// cannot locate the cut — only the denied name itself is known), probed by
// walking the query name's ancestors with zero-alloc label stripping.
//
// CNAME chains are excluded at record time: per RFC 6604 the NXDOMAIN of a
// chain belongs to its final target, so a chain response under the ORIGINAL
// qname (which exists — it resolved into the chain) must never cut that
// name's subtree.
package cache

import (
	"strings"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"

	"codeberg.org/miekg/dns"
)

// nxEntry is one cached denied name: the RFC 2308 negative expiry and the
// zone SOA the synthesized descendant responses lead with.
type nxEntry struct {
	exp int64 // log.NowUnix() expiry
	soa dns.RR
}

// nxNames indexes every cached NXDOMAIN name (IN class, pure negatives —
// never CNAME-chain responses).  Bounded by DefaultMaxNXDOMAINEntries.
func (s *Cache) initNXDOMAINNames() {
	s.nxNames = lrumap.NewSharded[string, nxEntry](config.DefaultMaxNXDOMAINEntries)
}

// indexNXDOMAIN records one denied name — called from Set for pure negative
// answers only (rcode NXDOMAIN, no CNAME chain, cacheable per RFC 2308).
func (s *Cache) indexNXDOMAIN(qname string, ttl int, authority []dns.RR, now int64) {
	e := nxEntry{exp: now + int64(ttl)}
	if soa := firstSOA(authority); soa != nil {
		e.soa = soa.Clone()
	}
	s.nxNames.Set(qname, e)
}

// NegativeAncestor walks qname's ancestors (excluding qname itself — exact
// negatives are served by the plain cache) and returns the SOA and remaining
// TTL of the closest cached NXDOMAIN (RFC 8020 §2: the subtree below a
// denied name is unreachable).  ok=false means no ancestor cut — resolve
// normally.
func (s *Cache) NegativeAncestor(qname string) (soa dns.RR, ttl int, ok bool) {
	now := log.NowUnix()
	name := qname
	for {
		idx := strings.IndexByte(name, '.')
		if idx < 0 || idx == len(name)-1 {
			return nil, 0, false // walked past "com."-style last ancestor
		}
		name = name[idx+1:]
		e, found := s.nxNames.Get(name)
		if !found || e.exp <= now {
			continue
		}
		remaining := int(e.exp - now)
		if e.soa == nil {
			return nil, remaining, true
		}
		return e.soa.Clone(), remaining, true
	}
}
