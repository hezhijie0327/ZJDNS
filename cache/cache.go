// Package cache provides the DNS response cache interface, backed by an in-memory LRU map.
package cache

import (
	"encoding/binary"
	"sync"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/ttl"

	"codeberg.org/miekg/dns"
)

// RequestRecord captures per-request metadata. Every request updates the
// in-memory stats counters; non-hit results also enter the per-RCODE top-N
// domain journal (see cache/statsjournal.go).
type RequestRecord struct {
	Qname        string // normalized FQDN
	Qtype        uint16
	Qclass       uint16
	Protocol     string // 'udp','tcp','tls','quic','https','http3','dtls','dnscrypt','dnscrypt-tcp','tlcp','http-tlcp','dtlcp'
	Result       string // 'hit','miss','stale','zone','error','blocked','badcookie'
	ResponseTime int64  // milliseconds
	Rcode        int    // DNS response code
	Server       string // upstream server identifier
	Poisoned     bool   // true when DNS poison was detected
	DNSSECStatus string // 'secure','insecure','bogus', or ''
}

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
	RecordRequest(r *RequestRecord)
	UpdateLatency(ip string, latencyMS int)
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

// requestRecordPool reuses RequestRecord values on the per-query hot path.
// RecordRequest reads all fields synchronously, so callers may release
// immediately after the call.
var requestRecordPool = sync.Pool{New: func() any { return new(RequestRecord) }}

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

// AcquireRequestRecord returns a zeroed RequestRecord from the pool.
func AcquireRequestRecord() *RequestRecord { return requestRecordPool.Get().(*RequestRecord) }

// ReleaseRequestRecord returns a record to the pool after RecordRequest.
func ReleaseRequestRecord(r *RequestRecord) {
	*r = RequestRecord{}
	requestRecordPool.Put(r)
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

// processRR applies DNSSEC filtering, copies, and adjusts TTL on a single
// resource record. Returns nil if the record should be excluded.
func processRR(rr dns.RR, value int64, isElapsed, includeDNSSEC bool) dns.RR {
	if !includeDNSSEC {
		switch rr.(type) {
		case *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.DNSKEY, *dns.DS:
			return nil
		}
	}
	// Fast path: no TTL adjustment and no DNSSEC filtering — return as-is
	// to avoid heap-allocating a clone (common on cache-miss → serve path).
	if value == 0 && !isElapsed {
		return rr
	}
	newRR := rr.Clone()
	if newRR == nil {
		return nil
	}
	if isElapsed {
		remaining := max(int64(newRR.Header().TTL)-value, 0)
		newRR.Header().TTL = uint32(remaining) //nolint:gosec // G115: DNS TTL subtraction — protocol-bounded uint32
	} else if value > 0 {
		newRR.Header().TTL = uint32(value) //nolint:gosec // G115: DNS TTL — protocol-bounded uint32
	}
	return newRR
}

// ProcessRecords adjusts TTLs on resource records and optionally filters
// DNSSEC record types. The returned slice shares backing arrays with the
// input — callers must not mutate the returned records.
func ProcessRecords(rrs []dns.RR, value int64, isElapsed, includeDNSSEC bool) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	// Fast path: TTL unchanged (value == 0) — no RR clones needed.
	// isElapsed is irrelevant when the TTL adjustment is zero.
	if value == 0 {
		if includeDNSSEC {
			return rrs
		}
		if !hasDNSSECRecords(rrs) {
			return rrs
		}
	}
	result := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if nr := processRR(rr, value, isElapsed, includeDNSSEC); nr != nil {
			result = append(result, nr)
		}
	}
	return result
}

// hasDNSSECRecords checks whether the slice contains any DNSSEC record types
// that would be filtered by ProcessRecords when includeDNSSEC is false.
func hasDNSSECRecords(rrs []dns.RR) bool {
	for _, rr := range rrs {
		switch rr.(type) {
		case *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.DNSKEY, *dns.DS:
			return true
		}
	}
	return false
}
