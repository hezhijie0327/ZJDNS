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
	"time"

	"github.com/miekg/dns"

	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
)

const (
	resultBufferCapacity = config.DefaultCacheKeyBufferSize
	maxResultLength      = config.DefaultCacheKeyMaxLength

	cacheKeyDNSPrefix    = "dns:"
	cacheSnapshotVersion = 2
)

var cacheSnapshotMagic = "ZJDNS-CACHE-V" + strconv.Itoa(cacheSnapshotVersion)

// Store defines the cache storage interface.
type Store interface {
	Get(key string) (*CacheEntry, bool, bool)
	Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *edns.ECSOption)
	SetWithDNSSEC(key string, answer, authority, additional []dns.RR, validated bool, dnssecValidated bool, ecs *edns.ECSOption)
	SetEntry(key string, entry *CacheEntry)
	ReverseLookup(ip net.IP) []LookupResult
	Close() error
}

// CacheEntry holds a cached DNS response with timing and EDNS metadata.
type CacheEntry struct {
	Answer          []*CompactRecord `json:"answer"`
	Authority       []*CompactRecord `json:"authority"`
	Additional      []*CompactRecord `json:"additional"`
	ECSAddress      string           `json:"ecs_address,omitempty"`
	Timestamp       int64            `json:"timestamp"`
	AccessTime      int64            `json:"access_time"`
	RefreshTime     int64            `json:"refresh_time,omitempty"`
	TTL             int              `json:"ttl"`
	OriginalTTL     int              `json:"original_ttl"`
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
func (c *CacheEntry) IsExpired() bool {
	return c != nil && time.Now().Unix()-c.Timestamp > int64(c.TTL)
}

// ShouldRefresh reports whether the entry has passed both TTL and original TTL.
func (c *CacheEntry) ShouldRefresh() bool {
	return c != nil && c.IsExpired() && time.Now().Unix()-c.Timestamp > int64(max(c.OriginalTTL, c.TTL))
}

// CanServeExpired reports whether the expired entry is within the maxAge window.
func (c *CacheEntry) CanServeExpired(maxAge int) bool {
	return c != nil && c.IsExpired() && time.Now().Unix()-c.Timestamp-int64(c.TTL) <= int64(maxAge)
}

// GetRemainingTTL returns the remaining TTL, or DefaultStaleTTL if expired.
func (c *CacheEntry) GetRemainingTTL() uint32 {
	if c == nil {
		return 0
	}
	remaining := int64(c.TTL) - (time.Now().Unix() - c.Timestamp)
	if remaining > 0 {
		return uint32(remaining)
	}
	return uint32(config.DefaultStaleTTL)
}

// ECSOption returns the EDNS Client Subnet stored in the entry, if any.
func (c *CacheEntry) ECSOption() *edns.ECSOption {
	if c == nil || c.ECSAddress == "" {
		return nil
	}
	if ip := net.ParseIP(c.ECSAddress); ip != nil {
		return &edns.ECSOption{Family: c.ECSFamily, SourcePrefix: c.ECSSourcePrefix, ScopePrefix: c.ECSScopePrefix, Address: ip}
	}
	return nil
}

// ShouldPrefetch reports whether the entry is due for refresh based on a
// percentage threshold of its original TTL.
func (c *CacheEntry) ShouldPrefetch(thresholdPercent int) bool {
	if c == nil || c.IsExpired() || thresholdPercent <= 0 {
		return false
	}
	if thresholdPercent > 100 {
		thresholdPercent = 100
	}
	remaining := int64(c.TTL) - (time.Now().Unix() - c.Timestamp)
	if remaining <= 0 {
		return false
	}
	original := int64(c.OriginalTTL)
	if original <= 0 {
		original = int64(c.TTL)
	}
	if original <= 0 {
		return false
	}
	return remaining <= (original*int64(thresholdPercent)+99)/100
}

// BuildCacheKey constructs a deterministic cache key from a DNS question,
// optional ECS option, and DNSSEC flag.
func BuildCacheKey(question dns.Question, ecs *edns.ECSOption, clientRequestedDNSSEC bool) string {
	var buf strings.Builder
	buf.Grow(resultBufferCapacity)
	buf.WriteString(cacheKeyDNSPrefix)
	buf.WriteString(dnsutil.NormalizeDomain(question.Name))
	buf.WriteByte(byte(config.DefaultCacheKeySeparator))
	buf.WriteString(strconv.FormatUint(uint64(question.Qtype), 10))
	buf.WriteByte(byte(config.DefaultCacheKeySeparator))
	buf.WriteString(strconv.FormatUint(uint64(question.Qclass), 10))
	if ecs != nil {
		buf.WriteString(config.DefaultCacheKeyECSPrefix)
		buf.WriteString(ecs.Address.String())
		buf.WriteByte(byte(config.DefaultCacheKeyECSDelim))
		buf.WriteString(strconv.FormatUint(uint64(ecs.SourcePrefix), 10))
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

// createCompactRecord creates a CompactRecord from a DNS resource record.
func createCompactRecord(rr dns.RR) *CompactRecord {
	if rr == nil {
		return nil
	}
	return &CompactRecord{Text: rr.String(), OrigTTL: rr.Header().Ttl, Type: rr.Header().Rrtype, RR: rr}
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
	newRR := dns.Copy(rr)
	if newRR == nil {
		return nil
	}
	if isElapsed {
		remaining := int64(newRR.Header().Ttl) - value
		if remaining < 0 {
			remaining = 0
		}
		newRR.Header().Ttl = uint32(remaining)
	} else if value > 0 {
		newRR.Header().Ttl = uint32(value)
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
	gob.Register(&CacheEntry{})
	gob.Register(&CompactRecord{})
}
