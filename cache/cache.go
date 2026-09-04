// Package cache provides the DNS response cache interface, backed by an in-memory LRU map.
package cache

import (
	"encoding/binary"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/stats"
	"zjdns/internal/ttl"

	"codeberg.org/miekg/dns"
)

// StoreReader is the read-only subset of Store.  Consumers that only need
// cache lookups should depend on this interface rather than the full Store.
type StoreReader interface {
	Get(qname string, qtype, qclass uint16, ecs *config.ECSOption) (*Entry, bool, bool)
	// GetTypes retrieves the entries for exactly two qtypes of one qname in
	// a single query, in qtypes order.  ECS is not supported (callers never
	// carry it); entries are matched on the empty ECS candidate.  Returns
	// parallel slices of entry / found / expired.
	GetTypes(qname string, qclass uint16, qtypes [2]uint16) (entries [2]*Entry, found, expired [2]bool)
	LatencyLastProbe(ip string) (int64, bool)
}

// StoreWriter is the write subset of Store.  Consumers that only need to
// populate cache entries or record metrics should depend on this interface.
type StoreWriter interface {
	Set(qname string, qtype, qclass uint16, ecs *config.ECSOption,
		answer, authority, additional []dns.RR, validated bool, rcode uint16)
	RecordRequest(r *stats.RequestRecord)
	UpdateLatency(ip string, latencyMS int)
	UpdateLatencyBatch(values map[string]int)
}

// StoreLifecycle is the lifecycle subset of Store (housekeeping + shutdown).
type StoreLifecycle interface {
	FlushDB(target string) (int64, error)
	Clear() (int64, error)
	PruneQueryJournal(retentionSec int64) (int64, error)
	Stats() []string
	StatsRcode() []string
	Close() error
}

// Store defines the full cache storage interface, composed from its role
// interfaces so consumers can depend on only the methods they need (C5).
type Store interface {
	StoreReader
	StoreWriter
	StoreLifecycle
}

// Entry holds a cached DNS response with timing metadata.
// When ResponseWire is non-nil the entry was stored in pre-packed format:
// the caller should adjust TTLs via TTLOffsets and serve directly, skipping
// Unpack+Pack.  Answer/Authority/Additional are nil until Unpack is called
// (the latency-sorting path in Get unpacks; everyone else serves the wire).
type Entry struct {
	Answer     []dns.RR `json:"answer"`
	Authority  []dns.RR `json:"authority"`
	Additional []dns.RR `json:"additional"`
	Timestamp  int64    `json:"timestamp"`
	TTL        int      `json:"ttl"`
	Validated  bool     `json:"validated"`

	// Pre-packed response (format 0x02): complete DNS response message as
	// wire format, with TTLs at their original values.  TTLOffsets contains
	// the byte offsets of each TTL field within ResponseWire.
	ResponseWire []byte
	TTLOffsets   []uint16

	// HasDNSSEC reports whether ResponseWire carries DNSSEC record types
	// (RRSIG/NSEC/NSEC3/DNSKEY/DS) — precomputed at Set() time (BLOB header
	// flag bit) so the DO=0 serve gate skips the per-hit wire scan.
	HasDNSSEC bool
}

// Unpack populates Answer, Authority and Additional by unpacking the
// pre-packed ResponseWire.  Callers that need the parsed RRs (tests,
// latency sorting) call this once; the cache-hit hot path uses
// ResponseWire directly via buildFromPrePacked and skips Unpack entirely.
func (e *Entry) Unpack() error {
	if e.ResponseWire == nil || len(e.Answer) > 0 {
		return nil
	}
	msg := new(dns.Msg)
	msg.Data = e.ResponseWire
	if err := msg.Unpack(); err != nil {
		return err
	}
	e.Answer = msg.Answer
	e.Authority = msg.Ns
	e.Additional = msg.Extra
	return nil
}

// rebuildResponseWire repacks Answer/Authority/Additional into ResponseWire
// and re-scans TTL offsets.  Called after latency-sorting Answer so the
// pre-packed wire reflects the new order.
func (e *Entry) rebuildResponseWire() {
	msg := new(dns.Msg)
	msg.Data = e.ResponseWire
	_ = msg.Unpack() // extract original header + question
	msg.Answer = e.Answer
	msg.Ns = e.Authority
	msg.Extra = e.Additional
	if err := msg.Pack(); err != nil {
		return
	}

	// Skip 12-byte header + question section to find the first RR.  A
	// label-aware walk, not a zero-byte scan: QNAME label content may
	// legally contain NUL octets (RFC 1035 §3.1), which stopped the scan
	// mid-name and produced a misaligned offset table (R3-L24).
	pos := dns.MsgHeaderSize
	off, ok := zdnsutil.SkipWireName(msg.Data, pos)
	if !ok {
		return
	}
	questionEnd := off + 4 // QTYPE(2) + QCLASS(2)

	// Scan TTL offsets in the answer, authority and additional sections.
	offsets := make([]uint16, 0, 8)
	pos = questionEnd
	for pos+10 <= len(msg.Data) {
		// Skip owner name.
		off := pos
		for off < len(msg.Data) {
			l := msg.Data[off]
			if l == 0 {
				off++
				break
			}
			if l&0xC0 == 0xC0 {
				off += 2
				break
			}
			off += int(l) + 1
		}
		if off+10 > len(msg.Data) {
			break
		}
		ttlOff := off + 4
		offsets = append(offsets, uint16(ttlOff)) //nolint:gosec // G115: wire format offset bounded by message size
		rdLen := int(binary.BigEndian.Uint16(msg.Data[off+8:]))
		pos = off + 10 + rdLen
	}

	// The old offsets (pool-owned from Get) are replaced — return them.
	ReleaseTTLOffsets(e.TTLOffsets)
	e.ResponseWire = msg.Data
	e.TTLOffsets = offsets
}

// ReleaseOffsets returns the entry's pooled TTL-offset slice to the pool.
// Idempotent: it clears TTLOffsets, so every consumer exit path may call it
// unconditionally without risking a double-put of the same slice into the
// pool (two owners of one backing array).
func (e *Entry) ReleaseOffsets() {
	if e.TTLOffsets == nil {
		return
	}
	ReleaseTTLOffsets(e.TTLOffsets)
	e.TTLOffsets = nil
}

// IsExpired reports whether the entry's TTL has elapsed.
func (e *Entry) IsExpired() bool {
	return e != nil && ttl.IsExpired(e.Timestamp, e.TTL)
}

// CanServeExpired reports whether the expired entry is within the maxAge window.
func (e *Entry) CanServeExpired(maxAge int) bool {
	return e != nil && ttl.CanServeExpired(e.Timestamp, e.TTL, maxAge)
}

// RemainingTTL returns the remaining TTL, or a cyclical stale TTL if expired.
func (e *Entry) RemainingTTL() uint32 {
	if e == nil {
		return 0
	}
	return ttl.RemainingTTL(e.Timestamp, e.TTL, uint32(config.DefaultStaleTTL))
}

// ShouldPrefetch reports whether the entry is due for refresh based on a
// percentage threshold of its original TTL.
func (e *Entry) ShouldPrefetch(thresholdPercent int) bool {
	if e == nil {
		return false
	}
	return ttl.ShouldPrefetch(e.Timestamp, e.TTL, thresholdPercent)
}

// WireRcode extracts the response rcode from the entry's pre-packed wire
// header, including extended rcodes (>= 16): the low 4 bits live in the
// header flags byte, the extended bits in the OPT record's TTL high byte
// (RFC 6891 §6.1.3).  Reading only the low nibble would misclassify e.g.
// BADVERS (16) as NOERROR, breaking RCODE-match checks (RFC 10029 §3.4).
func (e *Entry) WireRcode() uint16 {
	wire := e.ResponseWire
	if len(wire) < 4 {
		return 0
	}
	rcode := uint16(wire[3] & 0x0F) //nolint:gosec // G115: DNS rcode — protocol-bounded byte
	// Scan the wire for the OPT record.  The cached wire's question section
	// is uncompressed (canonical qname built by Set), so a plain label walk
	// finds its end.
	pos := dns.MsgHeaderSize
	for pos < len(wire) {
		l := int(wire[pos])
		if l == 0 {
			pos += 1 + 4 // root label + QTYPE(2) + QCLASS(2)
			break
		}
		if l&0xC0 == 0xC0 {
			return rcode // compression pointer in the question — not the cache format
		}
		pos += l + 1
	}
	for pos+11 <= len(wire) {
		off := pos
		// Name: labels or a compression pointer.
		for off < len(wire) {
			b := wire[off]
			if b&0xC0 == 0xC0 {
				off += 2
				break
			}
			if b == 0 {
				off++
				break
			}
			off += int(b) + 1
		}
		if off+10 > len(wire) {
			break
		}
		typ := binary.BigEndian.Uint16(wire[off:])
		if typ == dns.TypeOPT {
			rcode |= uint16(wire[off+4]) << 4 // OPT TTL byte 0 = extended rcode (RFC 6891 §6.1.3)
			return rcode
		}
		pos = off + 10 + int(binary.BigEndian.Uint16(wire[off+8:]))
	}
	return rcode
}

// WireAuthoritative reads the AA flag from the entry's pre-packed wire
// header (bit 2 of the flags byte) — the cached wire preserves the AA of the
// response as received, needed for flag-match checks (RFC 10029 §3.4).
func (e *Entry) WireAuthoritative() bool {
	wire := e.ResponseWire
	return len(wire) >= 4 && wire[2]&0x04 != 0
}
