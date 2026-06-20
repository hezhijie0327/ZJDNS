// Package cache provides the DNS response cache interface and in-memory
// implementation with optional disk persistence.
package cache

import (
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"zjdns/edns"
	"zjdns/internal/dnsutil"
)

const (
	// StaleTTL is the TTL in seconds returned for expired cache entries.
	StaleTTL = 30
	// StaleMaxAge is the maximum age in seconds an expired entry may be served.
	StaleMaxAge = 45 * 86400

	resultBufferCapacity = 128
	maxResultLength      = 512

	cacheKeyDNSPrefix    = "dns:"
	cacheSnapshotVersion = 2
)

var cacheSnapshotMagic = "ZJDNS-CACHE-V" + strconv.Itoa(cacheSnapshotVersion)

// Store defines the cache storage interface.
type Store interface {
	Get(key string) (*CacheEntry, bool, bool)
	Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *edns.ECSOption)
	SetEntry(key string, entry *CacheEntry)
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

// GetRemainingTTL returns the remaining TTL, or StaleTTL if expired.
func (c *CacheEntry) GetRemainingTTL() uint32 {
	if c == nil {
		return 0
	}
	remaining := int64(c.TTL) - (time.Now().Unix() - c.Timestamp)
	if remaining > 0 {
		return uint32(remaining)
	}
	return uint32(StaleTTL)
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
	buf.WriteByte(':')
	buf.WriteString(strconv.FormatUint(uint64(question.Qtype), 10))
	buf.WriteByte(':')
	buf.WriteString(strconv.FormatUint(uint64(question.Qclass), 10))
	if ecs != nil {
		buf.WriteString(":ecs:")
		buf.WriteString(ecs.Address.String())
		buf.WriteByte('/')
		buf.WriteString(strconv.FormatUint(uint64(ecs.SourcePrefix), 10))
	}
	if clientRequestedDNSSEC {
		buf.WriteString(":dnssec")
	}
	result := buf.String()
	if len(result) > maxResultLength {
		hash := sha256.Sum256([]byte(result))
		return fmt.Sprintf("h:%x", hash[:16])
	}
	return result
}

// CreateCompactRecord creates a CompactRecord from a DNS resource record.
func CreateCompactRecord(rr dns.RR) *CompactRecord {
	if rr == nil {
		return nil
	}
	return &CompactRecord{Text: rr.String(), OrigTTL: rr.Header().Ttl, Type: rr.Header().Rrtype, RR: rr}
}

// ExpandRecord converts a CompactRecord back to a DNS resource record.
func ExpandRecord(cr *CompactRecord) dns.RR {
	if cr == nil || cr.Text == "" {
		return nil
	}
	rr, _ := dns.NewRR(cr.Text)
	return rr
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

// ExpandAndProcessRecords combines expansion of CompactRecords with TTL
// adjustment and optional DNSSEC filtering in a single pass, avoiding the
// double-allocation of calling ExpandRecords then ProcessRecords separately.
func ExpandAndProcessRecords(crs []*CompactRecord, value int64, isElapsed bool, includeDNSSEC bool) []dns.RR {
	if len(crs) == 0 {
		return nil
	}
	result := make([]dns.RR, 0, len(crs))
	for _, cr := range crs {
		rr := expand(cr)
		if rr == nil {
			continue
		}
		if !includeDNSSEC {
			switch rr.(type) {
			case *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.DNSKEY, *dns.DS:
				continue
			}
		}
		newRR := dns.Copy(rr)
		if newRR == nil {
			continue
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
		result = append(result, newRR)
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
		if rr == nil {
			continue
		}
		if !includeDNSSEC {
			switch rr.(type) {
			case *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.DNSKEY, *dns.DS:
				continue
			}
		}
		newRR := dns.Copy(rr)
		if newRR != nil {
			if isElapsed {
				remaining := int64(newRR.Header().Ttl) - value
				if remaining < 0 {
					remaining = 0
				}
				newRR.Header().Ttl = uint32(remaining)
			} else if value > 0 {
				newRR.Header().Ttl = uint32(value)
			}
			result = append(result, newRR)
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
