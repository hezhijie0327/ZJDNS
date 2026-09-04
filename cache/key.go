// cacheKey: the composite cache lookup key, its deterministic spill-store
// encoding, and ECS-based key derivation with fallback prefixes.
package cache

import (
	"zjdns/config"
)

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

// ── Store interface ──────────────────────────────────────────────────────────

// Get retrieves a cached DNS response by decompressing and unpacking the stored
// wire format. Returns the entry, whether it was found, and whether it's expired.
// The caller must pass a canonical qname (dnsutil.Canonical).
//
// On a memory miss the disk spill tier is consulted; a fresh spill hit is
// promoted back into memory (which may itself evict the LRU tail — that
// entry spills to disk in turn).
