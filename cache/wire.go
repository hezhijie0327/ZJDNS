// DNS wire-format helpers for pre-packed cache entries: TTL-offset
// pooling and scanning, DNSSEC detection, zstd frame detection, and RR
// section utilities.
package cache

import (
	"encoding/binary"
	"sync"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
)

// decompressBufPool reuses byte slices for zstd decompression on the
// cache-hit hot path, reducing GC pressure (P3).
var decompressBufPool = sync.Pool{
	New: func() any { b := make([]byte, decompressBufCap); return &b },
}

// ttloOffsetsPool reuses the per-hit TTL-offset slice (2 bytes per RR).
// Stored as *[]uint16 to avoid interface boxing (SA6002).
var ttloOffsetsPool = sync.Pool{New: func() any { s := make([]uint16, 0, 8); return &s }}

// AcquireTTLOffsets returns a slice of length n from the pool.  The pool
// entries are NOT zeroed on reuse — callers must overwrite every element
// before use (Get writes all n offsets before serving).
func AcquireTTLOffsets(n int) []uint16 {
	s := *ttloOffsetsPool.Get().(*[]uint16)
	if cap(s) < n {
		return make([]uint16, n)
	}
	return s[:n]
}

// ReleaseTTLOffsets returns a pooled offset slice.  Slices grown beyond the
// pool cap are dropped rather than grown in place.
func ReleaseTTLOffsets(s []uint16) {
	if cap(s) <= maxTTLOffsets {
		ttloOffsetsPool.Put(&s)
	}
}

// isZstdCompressed reports whether data starts with the zstd frame magic
// (0x28 0xB5 0x2F 0xFD).  Used to distinguish compressed from raw BLOBs
// without a prefix byte, preserving backward compatibility with entries
// written before threshold compression was introduced.
func isZstdCompressed(data []byte) bool {
	return len(data) >= 4 &&
		data[0] == 0x28 && data[1] == 0xB5 && data[2] == 0x2F && data[3] == 0xFD
}

// scanTTLOffsets walks the answer, authority and additional sections of a
// packed DNS message and returns the byte offset of every TTL field.  The
// question section (bytes 12..questionEnd) is skipped.  The returned slice
// is pool-owned — release with ReleaseTTLOffsets when done.
func scanTTLOffsets(wire []byte, questionEnd int) []uint16 {
	offsets := AcquireTTLOffsets(0)
	pos := questionEnd
	for pos+10 <= len(wire) {
		// Skip the owner name (may include compression pointers).
		off, ok := zdnsutil.SkipWireName(wire, pos)
		if !ok || off+10 > len(wire) {
			break
		}
		ttlOff := off + 4                         // TYPE(2) + CLASS(2) = 4 bytes after name
		offsets = append(offsets, uint16(ttlOff)) //nolint:gosec // G115: wire format offset bounded by message size
		rdLen := int(binary.BigEndian.Uint16(wire[off+8:]))
		pos = off + 10 + rdLen // name + TYPE/CLASS/TTL/RDLENGTH(10) + RDATA
	}
	return offsets
}

// WireHasDNSSEC reports whether a packed DNS message contains DNSSEC record
// types (RRSIG/NSEC/NSEC3/DNSKEY/DS) in its answer, authority or additional
// sections.  Used by the Response middleware fast path: entries store
// whatever the DO=1 upstream returned (the key never splits on the client's
// DO bit), and a DO=0 client must not receive those proofs — if the wire
// carries any, the response takes the unpack+filter path instead of being
// served directly.
func WireHasDNSSEC(wire []byte) bool {
	// buildEntry only guarantees len >= 3 — a corrupt/truncated wire must
	// not index out of range (M-low).
	if len(wire) < 12 {
		return false
	}
	// Skip the 12-byte header + question section.
	pos := 12
	questions := int(binary.BigEndian.Uint16(wire[4:6]))
	for range questions {
		off, ok := zdnsutil.SkipWireName(wire, pos)
		if !ok {
			return false
		}
		pos = off + 4 // QTYPE(2) + QCLASS(2)
	}
	// Walk the RR sections checking TYPE codes.
	for pos+10 <= len(wire) {
		off, ok := zdnsutil.SkipWireName(wire, pos)
		if !ok || off+10 > len(wire) {
			return false
		}
		switch binary.BigEndian.Uint16(wire[off:]) {
		case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeDNSKEY, dns.TypeDS:
			return true
		}
		rdLen := int(binary.BigEndian.Uint16(wire[off+8:]))
		pos = off + 10 + rdLen // name + TYPE/CLASS/TTL/RDLENGTH(10) + RDATA
	}
	return false
}

// New creates a two-tier cache with the given entry and latency capacities
// (<= 0 applies the config defaults).  A non-empty spill path enables the
// disk tier for that store: the spill file is opened and its hottest
// entries (by store timestamp) are loaded into memory, up to the mem cap;
// the rest stay on disk and are promoted back on a memory miss.

// minTTL returns the smallest positive TTL across all RR sections, falling
// back to DefaultTTL when no TTLs are found.  The result is capped at
// config.DefaultMaxCacheableTTL to prevent unbounded caching (RFC 8767 §4).
func minTTL(sections ...[]dns.RR) int {
	minT := -1
	for _, rrs := range sections {
		for _, rr := range rrs {
			if rr == nil {
				continue
			}
			if t := rr.Header().TTL; t&0x80000000 != 0 {
				// RFC 2181 §8: TTL values with the most significant bit set
				// are treated as if the entire value were zero — an
				// attacker-controlled huge TTL must not be cached for its
				// raw value (previously capped at 7 days).
				return 0
			} else if t > 0 && (minT < 0 || int(t) < minT) {
				minT = int(t)
			}
		}
	}
	if minT <= 0 {
		return config.DefaultTTL
	}
	if minT > config.DefaultMaxCacheableTTL {
		return config.DefaultMaxCacheableTTL
	}
	return minT
}

// cloneRRsNoOPT returns a deep copy of rrs excluding OPT pseudo-records.
// These carry transport-layer padding which has no semantic value but can
// occupy up to 468 bytes per encrypted response. The input slice belongs to
// the caller, so filtering must not modify it in place.
func cloneRRsNoOPT(rrs []dns.RR) []dns.RR {
	n := 0
	for _, rr := range rrs {
		if dns.RRToType(rr) != dns.TypeOPT {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	out := make([]dns.RR, n)
	j := 0
	for _, rr := range rrs {
		if dns.RRToType(rr) != dns.TypeOPT {
			out[j] = rr.Clone()
			j++
		}
	}
	return out
}
