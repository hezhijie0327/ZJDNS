// Package cache provides the DNS response cache interface and in-memory
// implementation with optional disk persistence.
package cache

import (
	"encoding/gob"
	"fmt"
	"hash/fnv"
	"net"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns"

	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/ttl"
)

const (
	resultBufferCapacity = config.DefaultCacheKeyBufferSize
	maxResultLength      = config.DefaultCacheKeyMaxLength

	cacheKeyDNSPrefix    = "dns:"
	cacheSnapshotVersion = 3
)

var cacheSnapshotMagic = "ZJDNS-CACHE-V" + strconv.Itoa(cacheSnapshotVersion)

// Store defines the cache storage interface.
type Store interface {
	Get(key string) (*Entry, bool, bool)
	Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *config.ECSOption)
	SetWithDNSSEC(key string, answer, authority, additional []dns.RR, validated bool, dnssecValidated bool, ecs *config.ECSOption)
	SetEntry(key string, entry *Entry)
	ReverseLookup(ip net.IP) []LookupResult
	Close() error
}

// Entry holds a cached DNS response with timing and EDNS metadata.
type Entry struct {
	Answer          []*CompactRecord `json:"answer"`
	Authority       []*CompactRecord `json:"authority"`
	Additional      []*CompactRecord `json:"additional"`
	ECSAddress      string           `json:"ecs_address,omitempty"`
	Timestamp       int64            `json:"timestamp"`
	AccessTime      int64            `json:"access_time"`
	TTL             int              `json:"ttl"`
	ECSFamily       uint16           `json:"ecs_family,omitempty"`
	ECSSourcePrefix uint8            `json:"ecs_source_prefix,omitempty"`
	ECSScopePrefix  uint8            `json:"ecs_scope_prefix,omitempty"`
	Validated       bool             `json:"validated"`
	DNSSECValidated bool             `json:"dnssec_validated,omitempty"`
	Payload         []byte           `json:"payload,omitempty"`
}

// CompactRecord is a space-efficient representation of a DNS resource record.
type CompactRecord struct {
	Text    string `json:"text"`
	OrigTTL uint32 `json:"orig_ttl"`
	Type    uint16 `json:"type"`
	RR      dns.RR `json:"-"`
}

// LookupResult holds a PTR reverse-lookup result.
type LookupResult struct {
	Name string
	TTL  uint32
}

// IsExpired reports whether the entry's TTL has elapsed.
func (c *Entry) IsExpired() bool {
	return c != nil && ttl.IsExpired(c.Timestamp, c.TTL)
}

// CanServeExpired reports whether the expired entry is within the maxAge window.
func (c *Entry) CanServeExpired(maxAge int) bool {
	return c != nil && ttl.CanServeExpired(c.Timestamp, c.TTL, maxAge)
}

// RemainingTTL returns the remaining TTL, or a cyclical stale TTL if expired.
func (c *Entry) RemainingTTL() uint32 {
	if c == nil {
		return 0
	}
	return ttl.RemainingTTL(c.Timestamp, c.TTL, uint32(config.DefaultStaleTTL))
}

// ECSOption returns the EDNS Client Subnet stored in the entry, if any.
func (c *Entry) ECSOption() *config.ECSOption {
	if c == nil || c.ECSAddress == "" {
		return nil
	}
	if ip := net.ParseIP(c.ECSAddress); ip != nil {
		return &config.ECSOption{Family: c.ECSFamily, SourcePrefix: c.ECSSourcePrefix, ScopePrefix: c.ECSScopePrefix, Address: ip}
	}
	return nil
}

// ShouldPrefetch reports whether the entry is due for refresh based on a
// percentage threshold of its original TTL.
func (c *Entry) ShouldPrefetch(thresholdPercent int) bool {
	if c == nil {
		return false
	}
	return ttl.ShouldPrefetch(c.Timestamp, c.TTL, thresholdPercent)
}

// BuildCacheKey constructs a deterministic cache key from a DNS question name,
// type, class, optional ECS option, and DNSSEC flag.
func BuildCacheKey(qname string, qtype, qclass uint16, ecs *config.ECSOption, clientRequestedDNSSEC bool) string {
	var buf strings.Builder
	buf.Grow(resultBufferCapacity)
	buf.WriteString(cacheKeyDNSPrefix)
	buf.WriteString(dnsutil.NormalizeDomain(qname))
	buf.WriteByte(byte(config.DefaultCacheKeySeparator))
	writeUint(&buf, uint64(qtype))
	buf.WriteByte(byte(config.DefaultCacheKeySeparator))
	writeUint(&buf, uint64(qclass))
	if ecs != nil {
		buf.WriteString(config.DefaultCacheKeyECSPrefix)
		buf.WriteString(ecs.Address.String())
		buf.WriteByte(byte(config.DefaultCacheKeyECSDelim))
		writeUint(&buf, uint64(ecs.SourcePrefix))
	}
	if clientRequestedDNSSEC {
		buf.WriteString(config.DefaultCacheKeyDNSSECSuffix)
	}
	result := buf.String()
	if len(result) > maxResultLength {
		h := fnv.New64a()
		h.Write([]byte(result))
		return fmt.Sprintf(config.DefaultCacheKeyHashFormat, h.Sum(nil))
	}
	return result
}

// writeUint appends the decimal representation of n to b without allocating
// an intermediate string (avoids the allocation of strconv.FormatUint).
func writeUint(b *strings.Builder, n uint64) {
	var buf [20]byte // max uint64 is 20 decimal digits
	i := len(buf)
	for {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
		if n == 0 {
			break
		}
	}
	b.Write(buf[i:])
}

// newCompactRecord creates a CompactRecord from a DNS resource record.
func newCompactRecord(rr dns.RR) *CompactRecord {
	if rr == nil {
		return nil
	}
	// RR field intentionally not stored — expand() re-parses from Text;
	// storing the original dns.RR pointer would waste memory with no benefit.
	return &CompactRecord{Text: rr.String(), OrigTTL: rr.Header().TTL, Type: dns.RRToType(rr)}
}

// ExpandRecords converts a slice of CompactRecords to DNS resource records.
func ExpandRecords(crs []*CompactRecord) []dns.RR {
	if len(crs) == 0 {
		return nil
	}
	result := make([]dns.RR, 0, len(crs))
	for _, cr := range crs {
		if rr := expand(cr); rr != nil {
			result = append(result, rr)
		}
	}
	return result
}

// processRR applies DNSSEC filtering, copies, and adjusts TTL on a single
// resource record. Returns nil if the record should be excluded.
func processRR(rr dns.RR, value int64, isElapsed bool, includeDNSSEC bool) dns.RR {
	if rr == nil {
		return nil
	}
	if !includeDNSSEC {
		switch rr.(type) {
		case *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.DNSKEY, *dns.DS:
			return nil
		}
	}
	newRR := func() dns.RR { r, _ := dns.New(rr.String()); return r }()
	if newRR == nil {
		return nil
	}
	if isElapsed {
		remaining := int64(newRR.Header().TTL) - value
		if remaining < 0 {
			remaining = 0
		}
		newRR.Header().TTL = uint32(remaining)
	} else if value > 0 {
		newRR.Header().TTL = uint32(value)
	}
	return newRR
}

// ExpandAndProcessRecords combines expansion of CompactRecords with TTL
// adjustment and optional DNSSEC filtering in a single pass, avoiding the
// double-allocation of calling ExpandRecords then ProcessRecords separately.
func ExpandAndProcessRecords(crs []*CompactRecord, value int64, isElapsed bool, includeDNSSEC bool) []dns.RR {
	if len(crs) == 0 {
		return nil
	}
	result := make([]dns.RR, 0, len(crs))
	for _, cr := range crs {
		if rr := processRR(expand(cr), value, isElapsed, includeDNSSEC); rr != nil {
			result = append(result, rr)
		}
	}
	return result
}

// ProcessRecords adjusts TTLs on resource records and optionally filters
// DNSSEC record types.
func ProcessRecords(rrs []dns.RR, value int64, isElapsed bool, includeDNSSEC bool) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	result := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if nr := processRR(rr, value, isElapsed, includeDNSSEC); nr != nil {
			result = append(result, nr)
		}
	}
	return result
}

func init() {
	gob.Register(&persistedCacheSnapshot{})
	gob.Register(&persistedCacheItem{})
	gob.Register(&Entry{})
	gob.Register(&CompactRecord{})
}
