// Aggressive negative caching (RFC 8198): an in-memory index of RRSIG-verified
// NSEC/NSEC3 ranges fed by validated negative answers, and the synthesis of
// NXDOMAIN/NODATA responses for names those ranges already deny.
//
// Only records that individually passed signature verification are indexed —
// the raw authority section of a validated response may hold unverified
// extras, and synthesizing from those would manufacture unauthenticated
// denials (RFC 8198 App. B: "If the NSEC record has not been verified as
// secure, discard it").  The index is memory-only: a restart re-learns ranges
// as fresh negatives resolve.
package cache

import (
	"maps"
	"slices"
	"strings"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// nsecZoneKey identifies one zone's denial table: apex, class, and whether
// the zone is indexed in NSEC or NSEC3 form (a zone signs with one or the
// other; both tables are kept independently so a re-signing transition that
// briefly serves both stays correct).
type nsecZoneKey struct {
	apex  string // canonical SOA owner of the negative answer's zone
	class uint16
	nsec3 bool
}

// nsec3Params captures the hash parameters shared by every NSEC3 record of a
// zone (RFC 5155 §7.2 — records with differing parameters never mix).
type nsec3Params struct {
	hash       uint8
	iterations uint16
	salt       string
}

// nsecRange is one authenticated denial interval.  For NSEC zones owner/next
// are canonical names; for NSEC3 zones they are the lowercase owner-hash and
// next-hash labels (equal length → lexicographic compare is numeric compare).
type nsecRange struct {
	owner string
	next  string
	// soa is the zone SOA a synthesized response leads with; rrset holds the
	// typed *dns.NSEC / *dns.NSEC3 followed by its paired RRSIGs — the proof
	// records a synthesized response serves.  All clones, isolated from the
	// serve path's in-place TTL rewrites.
	soa    dns.RR
	rrset  []dns.RR
	ts     int64 // log.NowUnix() at index time
	ttl    int   // aggressive effective TTL (≤ DefaultAggressiveNegativeTTL)
	optOut bool  // NSEC3 only — an Opt-Out interval proves nothing (RFC 8198 §5.2)
}

// nsecZone is one zone's copy-on-write interval table.  Readers work on the
// immutable ranges slice under RLock; writers replace it wholesale.
type nsecZone struct {
	key    nsecZoneKey
	params nsec3Params
	ranges []*nsecRange // sorted by owner
	lastTS int64        // newest insert — zone-eviction heuristic
}

// wildcardZoneKey scopes one wildcard table to its apex and class — wildcard
// expansions are interval-kind agnostic (NSEC and NSEC3 zones share the
// literal "*.example.org." naming).
type wildcardZoneKey struct {
	apex  string
	class uint16
}

// wildcardTable caches validated wildcard-expanded RRsets (RFC 8198 §5.3),
// keyed by the literal wildcard name ("*.example.org.") and qtype, so a later
// query for any other name the cached NSEC ranges deny can be synthesized
// from the cache-deduced wildcard.
type wildcardTable map[wildcardKey]*wildcardEntry

// wildcardKey identifies one cached wildcard-expanded RRset.
type wildcardKey struct {
	name  string // canonical wildcard owner ("*.example.org.")
	qtype uint16
}

// wildcardEntry is one cached wildcard expansion: rrset holds the expanded
// records + their RRSIGs exactly as the authority emitted them (owners still
// carry the previously-expanded name — rewritten at synthesis time).
type wildcardEntry struct {
	rrset []dns.RR
	ts    int64
	ttl   int
}

// keyedWildcard pairs a wildcard cache key with its entry (index build helper).
type keyedWildcard struct {
	key wildcardKey
	e   *wildcardEntry
}

// nsec3OptOutFlag is RFC 5155 §6.1 bit 0x01 of the NSEC3 flags field.
const nsec3OptOutFlag = 0x01

// IndexNegative feeds one validated negative answer into the denial index.
// proof carries the RRSIG-verified NSEC/NSEC3 records (QueryResult.DenialProof);
// authority supplies the zone SOA and the paired RRSIGs.  Everything else —
// positivity, bogus results — is the caller's gate (StoreIfCacheable).
func (s *Cache) IndexNegative(qname string, qclass uint16, proof, authority []dns.RR) {
	if len(proof) == 0 {
		return
	}
	soa := firstSOA(authority)
	if soa == nil {
		return // RFC 2308 §6.1 — no SOA, no zone identity
	}
	apex := dnsutil.Canonical(soa.Hdr.Name)
	if !dnsutil.IsBelow(apex, qname) {
		return
	}
	// RFC 8198 §5.4: the effective TTL of aggressively served negatives is
	// the RFC 2308 §5 negative TTL capped at the 3-hour suggestion.
	negTTL := min(int(soa.Hdr.TTL), int(soa.Minttl), config.DefaultAggressiveNegativeTTL)
	now := log.NowUnix()

	var nsecRanges, nsec3Ranges []*nsecRange
	var params nsec3Params
	for _, rr := range proof {
		switch n := rr.(type) {
		case *dns.NSEC:
			if r := buildNSECRange(n, soa, authority, now, negTTL); r != nil {
				nsecRanges = append(nsecRanges, r)
			}
		case *dns.NSEC3:
			r, p := buildNSEC3Range(n, soa, authority, now, negTTL)
			if r != nil {
				nsec3Ranges = append(nsec3Ranges, r)
				if params == (nsec3Params{}) {
					params = p
				}
			}
		}
	}
	s.insertRanges(nsecZoneKey{apex: apex, class: qclass}, nsecRanges, nsec3Ranges, params, now)
}

// SynthesizeNegative answers a query from the denial index when a cached and
// verified NSEC/NSEC3 range already covers it (RFC 8198 §5).  Returns the
// rcode and the authority records (SOA + proof rrset, TTLs adjusted) for a
// synthesizable denial; ok=false otherwise — the caller must then resolve
// normally (RFC 8198 App. A: any synthesis gap falls back to resolution).
func (s *Cache) SynthesizeNegative(qname string, qtype, qclass uint16) (rcode uint16, authority []dns.RR, ok bool) {
	qname = dnsutil.Canonical(qname)
	now := log.NowUnix()

	// The most specific (longest) enclosing apex wins — e.g. a name under a
	// signed sub-zone must not be answered from the parent's delegation-level
	// table.  Zones are copy-on-write immutable — safe past the read lock.
	zone := s.nsecZoneFor(qname, qclass)
	if zone == nil {
		return 0, nil, false
	}
	ranges := zone.ranges
	params := zone.params
	nsec3 := zone.key.nsec3

	var r *nsecRange
	var isNODATA bool
	if nsec3 {
		r, isNODATA = synthesizeNSEC3(ranges, params, qname, qtype)
	} else {
		r, isNODATA = synthesizeNSEC(ranges, qname, qtype)
	}
	if r == nil {
		return 0, nil, false
	}
	remaining := r.ttl - int(now-r.ts)
	if remaining <= 0 {
		return 0, nil, false
	}
	auth := buildSynthesizedAuthority(r, remaining)
	if auth == nil {
		return 0, nil, false
	}
	rcode = dns.RcodeNameError
	if isNODATA {
		rcode = dns.RcodeSuccess
	}
	if log.IsDebug() {
		log.Debugf("CACHE: RFC 8198 synthesized %s for %s (type=%s) from cached NSEC proof", dns.RcodeToString[rcode], qname, dns.TypeToString[qtype])
	}
	return rcode, auth, true
}

// SynthesizeWildcard answers a query from the cache-deduced wildcard
// (RFC 8198 §5.3): the cached NSEC/NSEC3 ranges must prove that qname itself
// does not exist (RFC 4035 §5.4 covering / RFC 5155 §8.8 next-closer cover),
// and a previously seen wildcard expansion for "*.closest-encloser" must carry
// qtype (positive, records rewritten to qname per RFC 4035 §5.3.2) — or the
// wildcard's own denial records must prove qtype absent (NODATA, RFC 5155
// §8.7 / RFC 4035 §5.4 bitmap).  ok=false means fall back to resolution.
func (s *Cache) SynthesizeWildcard(qname string, qtype, qclass uint16) (answer, authority []dns.RR, ok bool) {
	qname = dnsutil.Canonical(qname)
	zone := s.nsecZoneFor(qname, qclass)
	if zone == nil {
		return nil, nil, false
	}
	now := log.NowUnix()
	if zone.key.nsec3 {
		return s.synthesizeWildcardNSEC3(qclass, zone, qname, qtype, now)
	}
	return s.synthesizeWildcardNSEC(qclass, zone, qname, qtype, now)
}

// synthesizeWildcardNSEC synthesizes from the cache-deduced wildcard of an
// NSEC zone: the covering interval proves qname nonexistent, the wildcard
// table carries the expansion (positive), or the exact NSEC at "*.CE" proves
// qtype absent (NODATA).
func (s *Cache) synthesizeWildcardNSEC(qclass uint16, zone *nsecZone, qname string, qtype uint16, now int64) (answer, authority []dns.RR, ok bool) {
	ranges := zone.ranges
	if _, exists := nsecExactIndex(ranges, qname); exists {
		return nil, nil, false // the name exists — no wildcard applies
	}
	var covering *nsecRange
	for _, i := range []int{nsecCoveringIndex(ranges, qname), len(ranges) - 1} {
		if i < 0 || i >= len(ranges) {
			continue
		}
		r, isNODATA, proven := nsecAppendixB(ranges[i], qname)
		if !proven || isNODATA {
			continue // ENTs exist — wildcards never match them
		}
		covering = r
		break
	}
	if covering == nil {
		return nil, nil, false
	}
	wildcard := "*." + nsecCommonAncestor(covering.owner, covering.next)
	// Positive: a previously seen expansion of this exact wildcard carries qtype.
	if we := s.wildcardEntryFor(zone.key.apex, qclass, wildcard, qtype); we != nil {
		if remaining := we.ttl - int(now-we.ts); remaining > 0 {
			return rewriteOwnerSet(we.rrset, qname, remaining),
				buildProofAuthority(covering, remaining), true
		}
	}
	// Wildcard NODATA: the exact NSEC at the wildcard owner (cached as an
	// interval of its own) without qtype or CNAME in its bitmap.
	if i, found := nsecExactIndex(ranges, wildcard); found {
		if r, isNODATA := nsecNODATA(ranges[i], qtype); isNODATA {
			remaining := r.ttl - int(now-r.ts)
			if remaining > 0 && r.soa != nil {
				auth := buildSynthesizedAuthority(covering, remaining)
				auth = append(auth, rewriteOwnerSet(r.rrset[1:], wildcard, remaining)...)
				return nil, auth, true
			}
		}
	}
	return nil, nil, false
}

// synthesizeWildcardNSEC3 synthesizes from the cache-deduced wildcard of an
// NSEC3 zone: the closest-encloser walk proves qname nonexistent (§8.8), the
// wildcard table carries the expansion (positive), or an exact NSEC3 at
// H("*.CE") proves qtype absent (NODATA, §8.7) — all in non-Opt-Out space.
func (s *Cache) synthesizeWildcardNSEC3(qclass uint16, zone *nsecZone, qname string, qtype uint16, now int64) (answer, authority []dns.RR, ok bool) {
	ranges := zone.ranges
	params := zone.params
	hashName := func(name string) string {
		if params.hash != dns.SHA1 || params.iterations > config.DefaultMaxNSEC3Iterations {
			return ""
		}
		return strings.ToLower(dnsutil.NSEC3Name(name, params.salt, params.iterations))
	}
	h := hashName(qname)
	if h == "" {
		return nil, nil, false
	}
	if _, exists := nsec3ExactIndex(ranges, h); exists {
		return nil, nil, false // the name exists — no wildcard applies
	}
	ce, cover, walkOK := nsec3ClosestEncloser(ranges, hashName, qname)
	if !walkOK || cover.optOut {
		return nil, nil, false
	}
	wildcard := "*." + ce
	// Positive: a previously seen expansion of this exact wildcard carries qtype.
	if we := s.wildcardEntryFor(zone.key.apex, qclass, wildcard, qtype); we != nil {
		if remaining := we.ttl - int(now-we.ts); remaining > 0 {
			return rewriteOwnerSet(we.rrset, qname, remaining),
				buildProofAuthority(cover, remaining), true
		}
	}
	// Wildcard NODATA (§8.7): the exact NSEC3 at H(wildcard) without qtype.
	wh := hashName(wildcard)
	if wh == "" {
		return nil, nil, false
	}
	if i, found := nsec3ExactIndex(ranges, wh); found {
		r := ranges[i]
		if !r.optOut {
			if nsec3, _ := r.rrset[0].(*dns.NSEC3); nsec3 != nil &&
				(slices.Contains(nsec3.TypeBitMap, dns.TypeSOA) ||
					!slices.Contains(nsec3.TypeBitMap, dns.TypeNS)) &&
				!slices.Contains(nsec3.TypeBitMap, dns.TypeCNAME) &&
				!slices.Contains(nsec3.TypeBitMap, qtype) {
				remaining := r.ttl - int(now-r.ts)
				if remaining > 0 && r.soa != nil {
					auth := buildSynthesizedAuthority(cover, remaining)
					auth = append(auth, rewriteOwnerSet(r.rrset[1:], nsec3.Hdr.Name, remaining)...)
					return nil, auth, true
				}
			}
		}
	}
	return nil, nil, false
}

// nsecZoneFor returns the zone table with the most specific apex containing
// qname (nil when none does).  Zones are copy-on-write immutable — safe to
// use after the read lock is released.
func (s *Cache) nsecZoneFor(qname string, qclass uint16) *nsecZone {
	if idx := s.nsecTLD.Load(); idx != nil {
		// Lock-free fast path: the index map and every zone table are
		// copy-on-write immutable.
		var zone *nsecZone
		for _, z := range (*idx)[nsecTLDKey(qname)] {
			if z.key.class != qclass || !dnsutil.IsBelow(z.key.apex, qname) {
				continue
			}
			if zone == nil || len(z.key.apex) > len(zone.key.apex) {
				zone = z
			}
		}
		return zone
	}
	// Index not built yet (no negative ever indexed) — nothing can match.
	return nil
}

// wildcardEntryFor returns the cached expansion for one wildcard name and
// qtype (nil when absent).  Tables are copy-on-write immutable — safe past
// the read lock.
func (s *Cache) wildcardEntryFor(apex string, qclass uint16, wildcard string, qtype uint16) *wildcardEntry {
	s.nsecMu.RLock()
	defer s.nsecMu.RUnlock()
	tbl := s.nsecWild[wildcardZoneKey{apex: apex, class: qclass}]
	if tbl == nil {
		return nil
	}
	return (*tbl)[wildcardKey{name: wildcard, qtype: qtype}]
}

// buildProofAuthority clones a range's NSEC/NSEC3 rrset (no SOA — the proof
// section of a synthesized POSITIVE response; the SOA marks a negative).
func buildProofAuthority(r *nsecRange, remaining int) []dns.RR {
	return rewriteOwnerSet(r.rrset, r.rrset[0].Header().Name, remaining)
}

// rewriteOwnerSet clones records with the owner name and TTL rewritten —
// the RFC 4035 §5.3.2 wildcard-expansion form (the RRSIG Labels field is
// untouched: validators strip qname's labels back to the wildcard name).
func rewriteOwnerSet(rrs []dns.RR, name string, ttl int) []dns.RR {
	out := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		c := rr.Clone()
		c.Header().Name = name
		c.Header().TTL = uint32(ttl) //nolint:gosec // G115: DNS TTL — protocol-bounded uint32
		out[i] = c
	}
	return out
}

// ── Wildcard index (RFC 8198 §5.3, RFC 4035 §5.3.4) ──────────────────────────

// IndexWildcard feeds one validated positive answer's wildcard expansions into
// the wildcard cache.  An RRset whose owner has more labels than its covering
// RRSIG's Labels field was created by wildcard expansion (RFC 4035 §5.3.4) —
// the expanded records plus their RRSIGs are cached under the literal wildcard
// name so other names the cached NSEC ranges deny can be synthesized from it.
func (s *Cache) IndexWildcard(qname string, qclass uint16, answer, authority []dns.RR) {
	if len(answer) == 0 {
		return
	}
	soa := firstSOA(authority)
	if soa == nil {
		return
	}
	apex := dnsutil.Canonical(soa.Hdr.Name)
	if !dnsutil.IsBelow(apex, qname) {
		return
	}
	now := log.NowUnix()

	var entries []keyedWildcard
	seen := make(map[wildcardKey]bool)
	for _, rr := range answer {
		typ := dns.RRToType(rr)
		if typ == dns.TypeRRSIG {
			continue
		}
		owner := rr.Header().Name
		ownerLabels := dnsutil.Labels(dnsutil.Canonical(owner))
		for _, cand := range authority {
			sig, ok := cand.(*dns.RRSIG)
			// RFC 4035 §5.3.4: owner labels > RRSIG Labels ⇔ wildcard expansion.
			if !ok || sig.TypeCovered != typ || !dns.EqualName(sig.Header().Name, owner) || ownerLabels <= int(sig.Labels) {
				continue
			}
			wildcard := "*." + wildcardAncestor(owner, int(sig.Labels))
			if wildcard == "*." || !dnsutil.IsBelow(apex, wildcard) {
				break
			}
			key := wildcardKey{name: wildcard, qtype: typ}
			if seen[key] {
				break
			}
			// Positive expansions honor the RRset's own (already
			// RFC 4035 §5.3.3-capped) TTL — the paired RRSIG remaining
			// validity keeps the cached expansion from outliving its proof.
			rrset, ttl := pairedRRset(rr, authority, typ, now,
				min(int(rr.Header().TTL), config.DefaultMaxCacheableTTL))
			if len(rrset) < 2 {
				break // no RRSIG paired — impossible for validated data
			}
			seen[key] = true
			entries = append(entries, keyedWildcard{
				key: key,
				e:   &wildcardEntry{rrset: rrset, ts: now, ttl: ttl},
			})
			break // one (rrset, RRSIG) pair per record is enough
		}
	}
	if len(entries) == 0 {
		return
	}
	s.insertWildcardEntries(wildcardZoneKey{apex: apex, class: qclass}, entries, now)
}

// wildcardAncestor keeps the rightmost labels count of owner — the wildcard's
// parent name its RRSIG Labels field points at (RFC 4034 §3.1.8.1: Labels
// counts neither the "*" nor the root).  Returns "" when labels covers the
// whole name (the wildcard would sit above the zone apex).
func wildcardAncestor(owner string, labels int) string {
	full := strings.Split(dnsutil.Canonical(owner), ".")
	full = full[:len(full)-1] // drop the empty string after the trailing dot
	if labels <= 0 || labels >= len(full) {
		return ""
	}
	return strings.Join(full[len(full)-labels:], ".") + "."
}

// insertWildcardEntries merges validated wildcard expansions into the zone's
// wildcard table (copy-on-write, oldest-evicting at the range cap).
func (s *Cache) insertWildcardEntries(key wildcardZoneKey, entries []keyedWildcard, now int64) {
	s.nsecMu.Lock()
	defer s.nsecMu.Unlock()
	if s.nsecWild == nil {
		s.nsecWild = make(map[wildcardZoneKey]*wildcardTable)
	}
	if len(s.nsecWild) >= config.DefaultAggressiveNSECZones {
		s.evictWildcardZoneLocked()
	}
	tbl := s.nsecWild[key]
	if tbl != nil {
		snapshot := make(wildcardTable, len(*tbl))
		maps.Copy(snapshot, *tbl)
		tbl = &snapshot
	} else {
		t := make(wildcardTable, len(entries))
		tbl = &t
	}
	for _, kw := range entries {
		(*tbl)[kw.key] = kw.e
	}
	for k, e := range *tbl {
		if e.ts+int64(e.ttl) <= now { //nolint:gosec // G115: unix seconds fit int64
			delete(*tbl, k)
		}
	}
	for len(*tbl) > config.DefaultAggressiveNSECRangePerZone {
		var oldest wildcardKey
		oldestTS := now
		first := true
		for k, e := range *tbl {
			if first || e.ts < oldestTS {
				oldest, oldestTS, first = k, e.ts, false
			}
		}
		delete(*tbl, oldest)
	}
	s.nsecWild[key] = tbl
}

// evictWildcardZoneLocked drops an arbitrary wildcard table when the zone cap
// is reached (map iteration order is random — every table is equally fresh;
// entries are TTL-bound and re-learned from traffic).
func (s *Cache) evictWildcardZoneLocked() {
	for k := range s.nsecWild {
		delete(s.nsecWild, k)
		return
	}
}

// buildNSECRange pairs one verified NSEC with its RRSIGs and the negative TTL.
func buildNSECRange(n *dns.NSEC, soa dns.RR, authority []dns.RR, now int64, negTTL int) *nsecRange {
	rrset, ttl := pairedRRset(n, authority, dns.TypeNSEC, now, negTTL)
	if rrset == nil {
		return nil
	}
	return &nsecRange{
		owner: dnsutil.Canonical(n.Header().Name),
		next:  dnsutil.Canonical(n.NextDomain),
		soa:   soa.Clone(),
		rrset: rrset,
		ts:    now,
		ttl:   ttl,
	}
}

// buildNSEC3Range pairs one verified NSEC3 with its RRSIGs, rejecting records
// with unsupported or over-capped hash parameters (they can never be queried
// back — hashing with different parameters cannot match the zone's owners).
func buildNSEC3Range(n *dns.NSEC3, soa dns.RR, authority []dns.RR, now int64, negTTL int) (*nsecRange, nsec3Params) {
	params := nsec3Params{hash: n.Hash, iterations: n.Iterations, salt: n.Salt}
	if n.Hash != dns.SHA1 || n.Iterations > config.DefaultMaxNSEC3Iterations {
		return nil, params
	}
	rrset, ttl := pairedRRset(n, authority, dns.TypeNSEC3, now, negTTL)
	if rrset == nil {
		return nil, params
	}
	return &nsecRange{
		owner:  zdnsutil.NSEC3HashLabel(n.Header().Name),
		next:   strings.ToLower(n.NextDomain),
		soa:    soa.Clone(),
		rrset:  rrset,
		ts:     now,
		ttl:    ttl,
		optOut: n.Flags&nsec3OptOutFlag != 0,
	}, params
}

// pairedRRset clones rr plus the RRSIGs from authority that cover it, and
// caps the interval TTL by the paired signatures' remaining validity — an
// aggressively served proof must never outlive the signature that backs it.
func pairedRRset(rr dns.RR, authority []dns.RR, covered uint16, now int64, negTTL int) (rrset []dns.RR, ttl int) {
	name := rr.Header().Name
	rrset = make([]dns.RR, 0, 2)
	rrset = append(rrset, rr.Clone())
	ttl = negTTL
	for _, cand := range authority {
		sig, ok := cand.(*dns.RRSIG)
		if !ok || sig.TypeCovered != covered || !dns.EqualName(sig.Header().Name, name) {
			continue
		}
		rrset = append(rrset, sig.Clone())
		// The proof holds while ANY paired signature is unexpired.
		if remaining64 := int64(sig.Expiration) - now; remaining64 > 0 && remaining64 < int64(ttl) {
			ttl = int(remaining64) //nolint:gosec // G115: DNS TTL — protocol-bounded by uint32 seconds
		}
	}
	return rrset, ttl
}

// insertRanges replaces the affected zone tables with copy-on-write updated,
// owner-sorted versions.  nsecRanges and nsec3Ranges carry the new intervals
// (either may be empty when the answer proved nothing indexable).
func (s *Cache) insertRanges(key nsecZoneKey, nsecRanges, nsec3Ranges []*nsecRange, params nsec3Params, now int64) {
	if len(nsecRanges) == 0 && len(nsec3Ranges) == 0 {
		return
	}
	s.nsecMu.Lock()
	defer s.nsecMu.Unlock()
	if s.nsecZones == nil {
		s.nsecZones = make(map[nsecZoneKey]*nsecZone)
	}
	if len(s.nsecZones) >= config.DefaultAggressiveNSECZones {
		s.evictNSECZoneLocked(now)
	}
	if len(nsecRanges) > 0 {
		s.nsecZones[key] = upsertNSECZone(s.nsecZones[key], key, nsec3Params{}, nsecRanges, now, false)
	}
	if len(nsec3Ranges) > 0 {
		k := key
		k.nsec3 = true
		s.nsecZones[k] = upsertNSECZone(s.nsecZones[k], k, params, nsec3Ranges, now, true)
	}
	s.rebuildNSECIndexLocked()
}

// rebuildNSECIndexLocked regenerates the TLD index for nsecZoneFor — called
// with nsecMu held after any zone-table mutation (inserts are rare relative
// to reads, so a wholesale rebuild is the cheap side of the trade).
func (s *Cache) rebuildNSECIndexLocked() {
	idx := make(map[string][]*nsecZone, len(s.nsecZones))
	for _, z := range s.nsecZones {
		k := nsecTLDKey(z.key.apex)
		idx[k] = append(idx[k], z)
	}
	s.nsecTLD.Store(&idx)
}

// nsecTLDKey returns the rightmost two labels of a canonical name — the
// narrowest suffix every zone containing that name must share.
func nsecTLDKey(name string) string {
	i := strings.LastIndexByte(name, '.')
	if i <= 0 {
		return name
	}
	j := strings.LastIndexByte(name[:i], '.')
	return name[j+1:]
}

// upsertNSECZone merges newRanges into the zone's interval table (nil builds
// one), keeping the slice sorted by owner and bounded by
// DefaultAggressiveNSECRangePerZone.  NSEC tables sort by DNS canonical
// ordering; NSEC3 tables by hash string (equal-length base32hex — lexicographic
// compare is numeric compare).
func upsertNSECZone(existing *nsecZone, key nsecZoneKey, params nsec3Params, newRanges []*nsecRange, now int64, nsec3 bool) *nsecZone {
	z := existing
	if z == nil {
		z = &nsecZone{key: key, params: params}
	} else {
		// Copy-on-write: readers may hold the old slice under RLock.
		z = &nsecZone{key: z.key, params: z.params, ranges: slices.Clone(z.ranges)}
		// NSEC3 parameter transition (zone re-signed with new hash params):
		// mixed-parameter intervals cannot be queried coherently — start a
		// fresh table for the new parameters and let the old entries expire.
		if params != (nsec3Params{}) && z.params != params {
			z.ranges = nil
			z.params = params
		}
	}
	z.ranges = append(z.ranges, newRanges...)
	// Stable sort: within one owner the appended (newest) interval sorts
	// last, which the dedup below relies on.
	slices.SortStableFunc(z.ranges, func(a, b *nsecRange) int {
		if nsec3 {
			return strings.Compare(a.owner, b.owner)
		}
		return zdnsutil.CanonicalCompare(a.owner, b.owner)
	})
	z.ranges = pruneNSECRange(z.ranges, now)
	if len(z.ranges) > config.DefaultAggressiveNSECRangePerZone {
		z.ranges = z.ranges[len(z.ranges)-config.DefaultAggressiveNSECRangePerZone:]
	}
	z.lastTS = now
	return z
}

// pruneNSECRange removes expired intervals and duplicate owners (the newest
// interval for an owner wins — e.g. a re-queried name refreshing its proof).
func pruneNSECRange(ranges []*nsecRange, now int64) []*nsecRange {
	out := ranges[:0:0]
	for _, r := range ranges {
		if r.ts+int64(r.ttl) <= now {
			continue
		}
		if len(out) > 0 && out[len(out)-1].owner == r.owner {
			out[len(out)-1] = r // sorted by owner: last of a run is the newest
			continue
		}
		out = append(out, r)
	}
	return out
}

// evictNSECZoneLocked drops the least recently fed zone table when the zone
// cap is reached.
func (s *Cache) evictNSECZoneLocked(now int64) {
	var oldest nsecZoneKey
	oldestTS := now
	first := true
	for k, z := range s.nsecZones {
		if first || z.lastTS < oldestTS {
			oldest, oldestTS, first = k, z.lastTS, false
		}
	}
	delete(s.nsecZones, oldest)
	s.rebuildNSECIndexLocked()
}

// ── NSEC synthesis (RFC 8198 §5.1, RFC 4035 §5.4, RFC 8198 App. B) ──────────

// synthesizeNSEC applies RFC 4035 §5.4 over the cached interval table and
// classifies the outcome per RFC 8198 Appendix B (NXDOMAIN vs ENT-NODATA).
func synthesizeNSEC(ranges []*nsecRange, qname string, qtype uint16) (*nsecRange, bool) {
	// Exact match — the name exists: NODATA when the bitmap lacks the qtype
	// (and CNAME, RFC 6840 §4.3).
	if i, ok := nsecExactIndex(ranges, qname); ok {
		return nsecNODATA(ranges[i], qtype)
	}

	// Covering candidates: the interval whose owner is the largest one below
	// qname, plus the table's last interval (its RFC 8198 App. B wrap-around
	// leg covers names sorting before every owner).
	for _, i := range []int{nsecCoveringIndex(ranges, qname), len(ranges) - 1} {
		if i < 0 || i >= len(ranges) {
			continue
		}
		r, isNODATA, proven := nsecAppendixB(ranges[i], qname)
		if !proven {
			continue
		}
		if isNODATA {
			return r, true
		}
		// RFC 4035 §5.4 step 6: NXDOMAIN additionally requires proof that no
		// wildcard covers the name — "*.closest-encloser" must fall inside a
		// cached interval, else a wildcard might exist and match.
		if nsecWildcardDenied(ranges, r) {
			return r, false
		}
	}
	return nil, false
}

// nsecExactIndex binary-searches the canonically sorted table for owner ==
// name.
func nsecExactIndex(ranges []*nsecRange, name string) (int, bool) {
	return slices.BinarySearchFunc(ranges, name, func(r *nsecRange, n string) int {
		return zdnsutil.CanonicalCompare(r.owner, n)
	})
}

// nsecCoveringIndex returns the index of the interval with the largest owner
// ≤ qname, or -1 when qname sorts before every owner.
func nsecCoveringIndex(ranges []*nsecRange, qname string) int {
	i, _ := nsecExactIndex(ranges, qname)
	return i - 1
}

// nsecAppendixB classifies what the covering interval proves about qname
// (RFC 8198 Appendix B).  Returns (range, ENT-NODATA, proven).
func nsecAppendixB(r *nsecRange, qname string) (*nsecRange, bool, bool) {
	owner, next := r.owner, r.next
	// "If the given name sorts before or matches the NSEC owner name,
	// discard" — a match was already handled as the exact-match NODATA case.
	if zdnsutil.CanonicalCompare(qname, owner) <= 0 {
		return nil, false, false
	}
	// "If the given name is a subdomain of the NSEC owner name and the NS bit
	// is present and the SOA bit is absent, then discard — the NSEC is from a
	// parent zone" (delegation intervals prove nothing below the cut).
	if dnsutil.IsBelow(owner, qname) {
		if nsec, _ := r.rrset[0].(*dns.NSEC); nsec != nil &&
			slices.Contains(nsec.TypeBitMap, dns.TypeNS) &&
			!slices.Contains(nsec.TypeBitMap, dns.TypeSOA) {
			return nil, false, false
		}
	}
	// Interval membership, split by wrap-around shape.
	if zdnsutil.CanonicalCompare(owner, next) < 0 {
		// Normal shape: qname must sort strictly before next.
		if zdnsutil.CanonicalCompare(qname, next) >= 0 {
			return nil, false, false
		}
	} else {
		// Wrap-around: only the (apex, next) leg is used — qname must be
		// next itself or below it.
		if !dnsutil.IsBelow(next, qname) {
			return nil, false, false
		}
	}
	// "If the next domain name is a subdomain of the given name, you have an
	// ENT" — a name below qname exists, so qname exists as an empty
	// non-terminal: NODATA, no wildcard check needed (wildcards never match
	// existing names).
	if next != qname && dnsutil.IsBelow(qname, next) {
		return r, true, true
	}
	return r, false, true
}

// nsecWildcardDenied checks that "*.closest-encloser" of the covering
// interval is itself covered by a cached interval (RFC 4035 §5.4 step 6) —
// the same set-level check the response validator performs.
func nsecWildcardDenied(ranges []*nsecRange, covering *nsecRange) bool {
	wildcard := "*." + nsecCommonAncestor(covering.owner, covering.next)
	for _, r := range ranges {
		if zdnsutil.DomainInRange(wildcard, r.owner, r.next) {
			return true
		}
	}
	return false
}

// nsecNODATA reports whether an exact-owner NSEC denies qtype at that name.
func nsecNODATA(r *nsecRange, qtype uint16) (*nsecRange, bool) {
	nsec, _ := r.rrset[0].(*dns.NSEC)
	if nsec == nil {
		return nil, false
	}
	// RFC 9824 §5.1 compact denial: the NXNAME bit means the name itself
	// does not exist (the authority answered NODATA for a nonexistent name).
	// The authority already expanded — and declined — any matching wildcard,
	// so this is a direct NXDOMAIN without the §5.4 wildcard check.
	if slices.Contains(nsec.TypeBitMap, dns.TypeNXNAME) {
		return r, false
	}
	// RFC 6840 §4.1: an NS-without-SOA bitmap is a delegation point's record —
	// it proves "no DS at the cut" and nothing about the other types the child
	// zone may serve at this very name (e.g. a DS negative indexed it).
	if slices.Contains(nsec.TypeBitMap, dns.TypeNS) && !slices.Contains(nsec.TypeBitMap, dns.TypeSOA) {
		return nil, false
	}
	if slices.Contains(nsec.TypeBitMap, dns.TypeCNAME) {
		return nil, false // a CNAME exists — the name resolves (RFC 6840 §4.3)
	}
	if slices.Contains(nsec.TypeBitMap, qtype) {
		return nil, false // the qtype exists — never a denial
	}
	return r, true
}

// nsecCommonAncestor returns the longest common label suffix of two names —
// the closest encloser of everything inside a covering interval.
func nsecCommonAncestor(a, b string) string {
	la := dnsutil.Split(dnsutil.Canonical(a))
	lb := dnsutil.Split(dnsutil.Canonical(b))
	i, j := len(la)-1, len(lb)-1
	for i >= 0 && j >= 0 && la[i] == lb[j] {
		i--
		j--
	}
	suffix := la[i+1:]
	if len(suffix) == 0 {
		return "."
	}
	var sb strings.Builder
	for _, l := range suffix {
		sb.WriteString(l)
		sb.WriteByte('.')
	}
	return sb.String()
}

// ── NSEC3 synthesis (RFC 8198 §5.2, RFC 5155 §8) ─────────────────────────────

// synthesizeNSEC3 classifies qname against the zone's cached NSEC3 table:
// an exact hash match yields NODATA (RFC 5155 §8.5), and a full
// closest-encloser proof — next-closer cover plus wildcard cover, all in
// non-Opt-Out space (RFC 8198 §5.2) — yields NXDOMAIN (RFC 5155 §8.4).
func synthesizeNSEC3(ranges []*nsecRange, params nsec3Params, qname string, qtype uint16) (*nsecRange, bool) {
	hashName := func(name string) string {
		if params.hash != dns.SHA1 || params.iterations > config.DefaultMaxNSEC3Iterations {
			return ""
		}
		return strings.ToLower(dnsutil.NSEC3Name(name, params.salt, params.iterations))
	}

	// RFC 5155 §8.5: exact match on H(qname).
	h := hashName(qname)
	if h == "" {
		return nil, false
	}
	if i, ok := nsec3ExactIndex(ranges, h); ok {
		r := ranges[i]
		if r.optOut {
			return nil, false // Opt-Out space proves nothing (RFC 8198 §5.2)
		}
		nsec3, _ := r.rrset[0].(*dns.NSEC3)
		if nsec3 == nil {
			return nil, false
		}
		// RFC 9824 §5.1 compact denial — the name does not exist.
		if slices.Contains(nsec3.TypeBitMap, dns.TypeNXNAME) {
			return r, false
		}
		// RFC 6840 §4.1: a delegation point's NSEC3 (NS set, SOA absent)
		// proves no DS at the cut — not the child zone's types at this name.
		if slices.Contains(nsec3.TypeBitMap, dns.TypeNS) && !slices.Contains(nsec3.TypeBitMap, dns.TypeSOA) {
			return nil, false
		}
		if slices.Contains(nsec3.TypeBitMap, dns.TypeCNAME) || slices.Contains(nsec3.TypeBitMap, qtype) {
			return nil, false
		}
		return r, true
	}

	// RFC 5155 §8.3/§8.4: closest-encloser walk.
	ce, cover, ok := nsec3ClosestEncloser(ranges, hashName, qname)
	if !ok {
		return nil, false
	}
	// RFC 5155 §8.4 step 2: the wildcard at the closest encloser must be
	// covered too — otherwise it might exist and match.
	wc := nsec3Covering(ranges, hashName("*."+ce))
	if wc == nil || wc.optOut || cover.optOut {
		return nil, false
	}
	return cover, false
}

// nsec3ClosestEncloser implements the RFC 5155 §8.3 closest-encloser walk over
// the cached table: it returns the closest encloser (the longest ancestor of
// qname with an exact NSEC3) and the interval covering the "next closer" name
// toward qname — the proof that qname itself does not exist (§8.4/§8.8).
func nsec3ClosestEncloser(ranges []*nsecRange, hashName func(string) string, qname string) (ce string, nextCloserCover *nsecRange, ok bool) {
	sname := qname
	var covered *nsecRange
	for {
		hs := hashName(sname)
		if hs == "" {
			return "", nil, false
		}
		if _, exact := nsec3ExactIndex(ranges, hs); exact {
			if covered == nil {
				return "", nil, false // match without prior cover — incomplete proof (§8.3)
			}
			return sname, covered, true
		}
		covered = nsec3Covering(ranges, hs)
		idx := strings.IndexByte(sname, '.')
		if idx < 0 || idx == len(sname)-1 {
			return "", nil, false
		}
		sname = sname[idx+1:]
	}
}

// nsec3ExactIndex binary-searches the hash-sorted table for an owner equal to
// h, also returning the insertion point for the covering search.
func nsec3ExactIndex(ranges []*nsecRange, h string) (int, bool) {
	return slices.BinarySearchFunc(ranges, h, func(r *nsecRange, hash string) int {
		return strings.Compare(r.owner, hash)
	})
}

// nsec3Covering returns the interval whose (owner, next) hash range contains
// h, or nil.  NSEC3 intervals live on a mod-2^160 ring: a wrap-around
// interval (next ≤ owner) covers h > owner as well as h < next.
func nsec3Covering(ranges []*nsecRange, h string) *nsecRange {
	if len(ranges) == 0 {
		return nil
	}
	i, _ := nsec3ExactIndex(ranges, h)
	if i > 0 {
		r := ranges[i-1] // owner < h by insertion order
		if h < r.next || r.next <= r.owner {
			return r
		}
	}
	// Head leg of a wrap-around interval: h sorts before every owner but is
	// still inside [0, next) of the last interval.
	if h < ranges[0].owner {
		last := ranges[len(ranges)-1]
		if last.next <= last.owner && h < last.next {
			return last
		}
	}
	return nil
}

// ── Synthesized response material ────────────────────────────────────────────

// buildSynthesizedAuthority clones the range's proof with the remaining
// aggressive TTL: SOA first (carrying the RFC 2308 §5 negative TTL the next
// cache hop applies), then the NSEC/NSEC3 rrset with its RRSIGs
// (RFC 8198 §5.4: NSEC TTLs reduced to the negative TTL).
func buildSynthesizedAuthority(r *nsecRange, remaining int) []dns.RR {
	if r.soa == nil {
		return nil
	}
	auth := make([]dns.RR, 0, len(r.rrset)+1)
	soaCopy := r.soa.Clone()
	soaCopy.Header().TTL = uint32(remaining) //nolint:gosec // G115: DNS TTL — protocol-bounded uint32
	auth = append(auth, soaCopy)
	for _, rr := range r.rrset {
		c := rr.Clone()
		c.Header().TTL = uint32(remaining) //nolint:gosec // G115: DNS TTL — protocol-bounded uint32
		auth = append(auth, c)
	}
	return auth
}

// firstSOA returns the first SOA record of the slice, or nil.
func firstSOA(rrs []dns.RR) *dns.SOA {
	for _, rr := range rrs {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa
		}
	}
	return nil
}
