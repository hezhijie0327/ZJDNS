// cacheKey: the composite cache lookup key, its deterministic spill-store
// encoding, and ECS-based key derivation with fallback prefixes.
package cache

import (
	"zjdns/config"
)

// cacheKey is the exact cache key: (qname, qtype, qclass, ECS address,
// ECS prefix) as one comparable struct — constructed in place on the lookup
// path with zero allocations.  ecsAddr holds the address bytes with
// ecsLen 4 = IPv4 (first 4 bytes), 16 = IPv6, 0 = no ECS.  The key excludes
// the client's DO bit: outbound queries always carry DO=1 (RFC 6840 §5.9)
// and DO=0 filtering happens at serve time — a DO-split key would store the
// identical raw wire twice per name.
type cacheKey struct {
	qname   string
	qtype   uint16
	qclass  uint16
	ecsPref uint8
	ecsLen  uint8
	ecsAddr [16]byte
}

// ECS fallback prefix boundaries — standard CIDR granularities most commonly
// used by CDN and authoritative DNS operators (RFC 7871).
var (
	ipv4FallbackPrefixes = []int{24, 16, 8, 0}
	ipv6FallbackPrefixes = []int{56, 48, 32, 0}
)

// hashCacheKey hashes a cacheKey for the sharded LRU's shard pick — a
// hand-rolled FNV-1a over the qname folded with the fixed fields.  It
// replaces maphash.Comparable on the per-hit path: every cache hit pays
// this hash, and DNS-name-length strings hash faster byte-wise than via
// the generic comparable reflection path.
func hashCacheKey(k cacheKey) uint64 {
	const (
		fnvOffset uint64 = 14695981039346656037
		fnvPrime  uint64 = 1099511628211
	)
	h := fnvOffset
	for i := 0; i < len(k.qname); i++ {
		h ^= uint64(k.qname[i])
		h *= fnvPrime
	}
	h ^= uint64(k.qtype) | uint64(k.qclass)<<16 | uint64(k.ecsPref)<<32 | uint64(k.ecsLen)<<40
	h *= fnvPrime
	for _, b := range k.ecsAddr {
		h ^= uint64(b)
		h *= fnvPrime
	}
	return h
}

// encode renders the deterministic spill-store form of the key:
// qname \x00 qtype(2) qclass(2) ecsLen ecsAddr[:ecsLen] ecsPref.
// Used only at the spill boundary (eviction write, promotion read) — one
// small allocation per miss-path spill touch.
func (k cacheKey) encode() string {
	buf := make([]byte, 0, len(k.qname)+7+int(k.ecsLen))
	buf = append(buf, k.qname...)
	buf = append(buf, 0, byte(k.qtype>>8), byte(k.qtype), byte(k.qclass>>8), byte(k.qclass), k.ecsLen) //nolint:gosec // G115: qtype/qclass are protocol-bounded uint16 wire fields
	buf = append(buf, k.ecsAddr[:k.ecsLen]...)
	return string(append(buf, k.ecsPref))
}

// decodeCacheKey parses the spill-store key form; ok=false on malformed or
// pre-struct-key (string-built) records — those stay on disk unread until
// compaction reclaims them.
func decodeCacheKey(s string) (cacheKey, bool) {
	var k cacheKey
	zero := 0
	for zero < len(s) && s[zero] != 0 {
		zero++
	}
	if zero == 0 || zero >= len(s)-5 { // need name + type/class/len/prefix
		return k, false
	}
	k.qname = s[:zero]
	rest := s[zero+1:]
	k.qtype = uint16(rest[0])<<8 | uint16(rest[1])  //nolint:gosec // G115: DNS type fits uint16
	k.qclass = uint16(rest[2])<<8 | uint16(rest[3]) //nolint:gosec // G115: DNS class fits uint16
	l := int(rest[4])
	if l != 0 && l != 4 && l != 16 || 5+l >= len(rest) {
		return k, false
	}
	k.ecsLen = uint8(l) //nolint:gosec // G115: bounded to 0/4/16 above
	copy(k.ecsAddr[:l], rest[5:5+l])
	k.ecsPref = rest[5+l]
	return k, true
}

// setECS fills the ECS part from the client option (nil → no ECS) with the
// FULL (unmasked) address — the exact-match key form; fallback candidates
// derive masked copies via mask.
func (k *cacheKey) setECS(ecs *config.ECSOption) {
	if ecs == nil || len(ecs.Address) == 0 {
		k.ecsLen, k.ecsPref = 0, 0
		return
	}
	if v4 := ecs.Address.To4(); v4 != nil {
		k.ecsLen = 4
		copy(k.ecsAddr[:4], v4)
	} else {
		k.ecsLen = 16
		copy(k.ecsAddr[:], ecs.Address.To16())
	}
	k.ecsPref = ecs.SourcePrefix
}

// mask zeroes the address bits below prefix in place (inline CIDR mask —
// the former maskIP + net.IP.String() allocated per fallback candidate).
func (k *cacheKey) mask(prefix int) {
	bits := int(k.ecsLen) * 8
	if prefix >= bits {
		return
	}
	for i := 0; i < int(k.ecsLen); i++ {
		r := prefix - i*8
		if r <= 0 {
			k.ecsAddr[i] = 0
		} else if r < 8 {
			k.ecsAddr[i] &= byte(0xFF) << (8 - r)
		}
	}
}
