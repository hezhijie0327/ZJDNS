// Package database provides a unified BadgerDB key-value store backing all
// ZJDNS subsystems (cache, zone, ruleset). It manages the DB lifecycle and
// provides shared key construction, encoding, and decoding utilities.
//
// All keys use pure binary encoding (BigEndian for numeric fields) with \x00
// field separators.
package database

import (
	"encoding/binary"
	"math"
)

// Key prefix constants.
const (
	prefixEntry      = "e:"
	eipPrefix        = "e:ip:"
	prefixQueryStats = "s:"
	prefixZone       = "z:"
	prefixRuleSet    = "r:"
)

// Sequence keys for auto-incrementing IDs via badger.Sequence.
const (
	seqEntry = "seq:entry"
)

// ── Key Construction ─────────────────────────────────────────────────────────

// EntryKey builds the primary cache key for a DNS response entry.
//
//	Layout: e:{qname}\x00{ecs_addr}\x00{ecsPrefix:2B BE}\x00{dnssec:1B}\x00{qtype:2B BE}\x00{qclass:2B BE}
func EntryKey(qname, ecsAddr string, ecsPrefix int, dnssecOK bool, qtype, qclass uint16) []byte {
	dnssec := byte('0')
	if dnssecOK {
		dnssec = '1'
	}
	return entryKeyBytes(qname, ecsAddr, ecsPrefix, dnssec, qtype, qclass)
}

// EntryKeyPrefix returns the prefix for all cache entry keys.
// EntryKeyPrefix returns the prefix for all cache entry keys (including the e:ip: sub-space).
func EntryKeyPrefix() []byte { return []byte(prefixEntry) }

// EIPPrefix returns the prefix for the e:ip: sub-space (reverse index + latency).
func EIPPrefix() []byte { return []byte(eipPrefix) }

func entryKeyBytes(qname, ecsAddr string, ecsPrefix int, dnssec byte, qtype, qclass uint16) []byte {
	totalLen := len(prefixEntry) + len(qname) + 1 + len(ecsAddr) + 1 + 2 + 1 + 1 + 1 + 2 + 1 + 2
	buf := make([]byte, totalLen)
	off := 0
	off += copy(buf[off:], prefixEntry)
	off += copy(buf[off:], qname)
	buf[off] = 0
	off++
	off += copy(buf[off:], ecsAddr)
	buf[off] = 0
	off++
	binary.BigEndian.PutUint16(buf[off:], uint16(ecsPrefix)) //nolint:gosec // G115: ECS prefix fits uint16
	off += 2
	buf[off] = 0
	off++
	buf[off] = dnssec
	off++
	buf[off] = 0
	off++
	binary.BigEndian.PutUint16(buf[off:], qtype)
	off += 2
	buf[off] = 0
	off++
	binary.BigEndian.PutUint16(buf[off:], qclass)
	return buf
}

// EIPReverseKey builds a reverse-lookup key under the e:ip: sub-space.
//
//	Layout: e:ip:{ip}\x00{entry_id:8B BE}\x00{name}
func EIPReverseKey(ip string, entryID uint64, name string) []byte {
	totalLen := len(eipPrefix) + len(ip) + 1 + 8 + 1 + len(name)
	buf := make([]byte, totalLen)
	off := 0
	off += copy(buf[off:], eipPrefix)
	off += copy(buf[off:], ip)
	buf[off] = 0
	off++
	binary.BigEndian.PutUint64(buf[off:], entryID)
	off += 8
	buf[off] = 0
	off++
	copy(buf[off:], name)
	return buf
}

// EIPReversePrefix returns the prefix for all reverse-lookup entries for an IP.
func EIPReversePrefix(ip string) []byte {
	buf := make([]byte, len(eipPrefix)+len(ip)+1)
	off := copy(buf, eipPrefix)
	off += copy(buf[off:], ip)
	buf[off] = 0
	return buf
}

// EIPLatencyKey builds a latency key under the e:ip: sub-space.
//
//	Layout: e:ip:{ip}\x00_lat
func EIPLatencyKey(ip string) []byte {
	buf := make([]byte, len(eipPrefix)+len(ip)+5) // +5 for \x00_lat
	off := copy(buf, eipPrefix)
	off += copy(buf[off:], ip)
	buf[off] = 0
	off++
	buf[off] = '_'
	off++
	buf[off] = 'l'
	off++
	buf[off] = 'a'
	off++
	buf[off] = 't'
	return buf
}

// QueryStatsKey builds a per-day aggregated stats key.
//
//	Layout: s:{stat_day:8B BE}\x00{result}\x00{protocol}\x00{rcode:2B BE}\x00{dnssec}\x00{poisoned:1B}
func QueryStatsKey(statDay int64, result, protocol string, rcode int, dnssec string, poisoned bool) []byte {
	poisonedByte := byte('0')
	if poisoned {
		poisonedByte = '1'
	}
	totalLen := len(prefixQueryStats) + 8 + 1 + len(result) + 1 + len(protocol) + 1 + 2 + 1 + len(dnssec) + 1 + 1
	buf := make([]byte, totalLen)
	off := 0
	off += copy(buf[off:], prefixQueryStats)
	binary.BigEndian.PutUint64(buf[off:], uint64(statDay)) //nolint:gosec // G115: protocol-bounded value fits target type
	off += 8
	buf[off] = 0
	off++
	off += copy(buf[off:], result)
	buf[off] = 0
	off++
	off += copy(buf[off:], protocol)
	buf[off] = 0
	off++
	binary.BigEndian.PutUint16(buf[off:], uint16(rcode)) //nolint:gosec // G115: DNS rcode fits uint16
	off += 2
	buf[off] = 0
	off++
	off += copy(buf[off:], dnssec)
	buf[off] = 0
	off++
	buf[off] = poisonedByte
	return buf
}

// QueryStatsPrefix returns the prefix for all query_stats keys.
func QueryStatsPrefix() []byte { return []byte(prefixQueryStats) }

// ZoneEntryKey builds a zone rule entry key.
//
//	Layout: z:{is_wildcard:1B}\x00{qname}\x00{qtype:2B BE}\x00{qclass:2B BE}\x00{match_tags}
func ZoneEntryKey(isWildcard bool, qname string, qtype, qclass uint16, matchTags string) []byte {
	w := byte('0')
	if isWildcard {
		w = '1'
	}
	totalLen := len(prefixZone) + 1 + 1 + len(qname) + 1 + 2 + 1 + 2 + 1 + len(matchTags)
	buf := make([]byte, totalLen)
	off := 0
	off += copy(buf[off:], prefixZone)
	buf[off] = w
	off++
	buf[off] = 0
	off++
	off += copy(buf[off:], qname)
	buf[off] = 0
	off++
	binary.BigEndian.PutUint16(buf[off:], qtype)
	off += 2
	buf[off] = 0
	off++
	binary.BigEndian.PutUint16(buf[off:], qclass)
	off += 2
	buf[off] = 0
	off++
	copy(buf[off:], matchTags)
	return buf
}

// ZoneExactPrefix returns the prefix for exact-match zone lookups.
func ZoneExactPrefix(qname string, qtype, qclass uint16) []byte {
	totalLen := 4 + len(qname) + 1 + 2 + 1 + 2 + 1
	buf := make([]byte, totalLen)
	off := 0
	off += copy(buf[off:], "z:0\x00")
	off += copy(buf[off:], qname)
	buf[off] = 0
	off++
	binary.BigEndian.PutUint16(buf[off:], qtype)
	off += 2
	buf[off] = 0
	off++
	binary.BigEndian.PutUint16(buf[off:], qclass)
	off += 2
	buf[off] = 0
	return buf
}

// ZoneWildcardPrefix returns the prefix for wildcard zone lookups on a suffix.
func ZoneWildcardPrefix(suffix string) []byte {
	buf := make([]byte, 4+len(suffix)+1)
	off := copy(buf, "z:1\x00")
	off += copy(buf[off:], suffix)
	buf[off] = 0
	return buf
}

// RuleSetKey builds a ruleset entry key.
//
//	Layout: r:{type}\x00{value}\x00{tag}
func RuleSetKey(kind, value, tag string) []byte {
	totalLen := len(prefixRuleSet) + len(kind) + 1 + len(value) + 1 + len(tag)
	buf := make([]byte, totalLen)
	off := 0
	off += copy(buf[off:], prefixRuleSet)
	off += copy(buf[off:], kind)
	buf[off] = 0
	off++
	off += copy(buf[off:], value)
	buf[off] = 0
	off++
	copy(buf[off:], tag)
	return buf
}

// RuleSetTypePrefix returns the prefix for all rules of a given type.
func RuleSetTypePrefix(kind string) []byte {
	buf := make([]byte, len(prefixRuleSet)+len(kind)+1)
	off := copy(buf, prefixRuleSet)
	off += copy(buf[off:], kind)
	buf[off] = 0
	return buf
}

// RuleSetTypeValuePrefix returns the prefix for domain rule lookups.
func RuleSetTypeValuePrefix(kind, value string) []byte {
	buf := make([]byte, len(prefixRuleSet)+len(kind)+1+len(value)+1)
	off := 0
	off += copy(buf[off:], prefixRuleSet)
	off += copy(buf[off:], kind)
	buf[off] = 0
	off++
	off += copy(buf[off:], value)
	buf[off] = 0
	return buf
}

// ── Value Encoding ────────────────────────────────────────────────────────────

// EncodeEntryValue packs cache entry metadata + wire format.
//
//	Layout: [0:8]id uint64 BE, [8:16]ts int64 BE, [16:20]ttl int32 BE, [20:]msg_wire
func EncodeEntryValue(id uint64, ts int64, ttl int32, msgWire []byte) []byte {
	buf := make([]byte, 20+len(msgWire))
	binary.BigEndian.PutUint64(buf[0:8], id)
	binary.BigEndian.PutUint64(buf[8:16], uint64(ts))   //nolint:gosec // G115: protocol-bounded value fits target type
	binary.BigEndian.PutUint32(buf[16:20], uint32(ttl)) //nolint:gosec // G115: protocol-bounded value fits target type
	copy(buf[20:], msgWire)
	return buf
}

// DecodeEntryValue unpacks a cache entry value.
func DecodeEntryValue(data []byte) (id uint64, ts int64, ttl int32, msgWire []byte) {
	if len(data) < 20 {
		return 0, 0, 0, nil
	}
	id = binary.BigEndian.Uint64(data[0:8])
	ts = int64(binary.BigEndian.Uint64(data[8:16]))   //nolint:gosec // G115: protocol-bounded value fits target type
	ttl = int32(binary.BigEndian.Uint32(data[16:20])) //nolint:gosec // G115: protocol-bounded value fits target type
	msgWire = data[20:]
	return id, ts, ttl, msgWire
}

// EncodePtrMapValue packs a ptr_map entry value (TTL only; expiry via WithTTL).
//
//	Layout: [0:4]ttl int32 BE
func EncodePtrMapValue(ttl int32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf[0:4], uint32(ttl)) //nolint:gosec // G115: protocol-bounded value fits target type
	return buf
}

// DecodePtrMapValue unpacks a ptr_map value.
func DecodePtrMapValue(data []byte) (ttl int32) {
	if len(data) < 4 {
		return 0
	}
	ttl = int32(binary.BigEndian.Uint32(data[0:4])) //nolint:gosec // G115: protocol-bounded value fits target type
	return ttl
}

// EncodeLatencyValue packs an IP latency measurement (value only; expiry via WithTTL).
//
//	Layout: [0:2]latency_ms uint16 BE
func EncodeLatencyValue(latencyMS int) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf[0:2], uint16(latencyMS)) //nolint:gosec // G115: latency fits uint16
	return buf
}

// DecodeLatencyValue unpacks a latency value.
func DecodeLatencyValue(data []byte) (latencyMS int) {
	if len(data) < 2 {
		return 0
	}
	latencyMS = int(binary.BigEndian.Uint16(data[0:2]))
	return latencyMS
}

// EncodeQueryStatsValue packs aggregated stat counters.
//
//	Layout: [0:8]query_count int64 BE, [8:16]total_ms int64 BE
func EncodeQueryStatsValue(queryCount, totalMS int64) []byte {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:8], uint64(queryCount)) //nolint:gosec // G115: stats counter
	binary.BigEndian.PutUint64(buf[8:16], uint64(totalMS))   //nolint:gosec // G115: stats counter
	return buf
}

// DecodeQueryStatsValue unpacks a stats value.
func DecodeQueryStatsValue(data []byte) (queryCount, totalMS int64) {
	if len(data) < 16 {
		return 0, 0
	}
	queryCount = int64(binary.BigEndian.Uint64(data[0:8])) //nolint:gosec // G115: stats counter
	totalMS = int64(binary.BigEndian.Uint64(data[8:16]))   //nolint:gosec // G115: stats counter
	return queryCount, totalMS
}

// EncodeZoneValue packs zone rule response data.
//
//	Layout: [0:2]rcode uint16 BE, then 3× length-prefixed blobs (uint32 LE len + data)
func EncodeZoneValue(rcode int, answer, authority, additional []byte) []byte {
	size := 2 + 4 + len(answer) + 4 + len(authority) + 4 + len(additional)
	buf := make([]byte, size)
	binary.BigEndian.PutUint16(buf[0:2], uint16(rcode)) //nolint:gosec // G115: DNS rcode fits uint16
	off := 2
	off = putBytesLE(buf, off, answer)
	off = putBytesLE(buf, off, authority)
	_ = putBytesLE(buf, off, additional)
	return buf
}

// DecodeZoneValue unpacks a zone value.
func DecodeZoneValue(data []byte) (rcode int, answer, authority, additional []byte) {
	if len(data) < 2 {
		return 0, nil, nil, nil
	}
	rcode = int(binary.BigEndian.Uint16(data[0:2]))
	off := 2
	answer, off = getBytesLE(data, off)
	authority, off = getBytesLE(data, off)
	additional, _ = getBytesLE(data, off)
	return rcode, answer, authority, additional
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func putBytesLE(buf []byte, off int, b []byte) int {
	binary.LittleEndian.PutUint32(buf[off:off+4], uint32(len(b))) //nolint:gosec // G115: protocol-bounded value fits target type
	off += 4
	copy(buf[off:], b)
	return off + len(b)
}

func getBytesLE(data []byte, off int) (b []byte, newOff int) {
	if off+4 > len(data) {
		return nil, off
	}
	n := int(binary.LittleEndian.Uint32(data[off : off+4]))
	off += 4
	if off+n > len(data) {
		return nil, off
	}
	b = make([]byte, n)
	copy(b, data[off:off+n])
	return b, off + n
}

// ── Key Parsing ───────────────────────────────────────────────────────────────

// ParseStatDay extracts stat_day from a query_stats key for pruning.
// Key format: s:{stat_day:8B BE}\x00...
func ParseStatDay(key []byte) (int64, bool) {
	if len(key) < 2+8 {
		return 0, false
	}
	if string(key[:2]) != prefixQueryStats {
		return 0, false
	}
	return int64(binary.BigEndian.Uint64(key[2:10])), true //nolint:gosec // G115: protocol-bounded value fits target type
}

// ParseStatDayFromKey is like ParseStatDay but ensures the key prefix matches.
func ParseStatDayFromKey(key []byte) int64 {
	v, _ := ParseStatDay(key)
	return v
}

// StatsKeyDayCutoff returns the key prefix for stat_day values up to cutoff.
func StatsKeyDayCutoff(cutoff int64) []byte {
	buf := make([]byte, 2+8)
	copy(buf[:2], prefixQueryStats)
	binary.BigEndian.PutUint64(buf[2:10], uint64(cutoff)) //nolint:gosec // G115: protocol-bounded value fits target type
	return buf
}

// MaxKey returns a key that sorts after all keys with the given prefix.
func MaxKey(prefix []byte) []byte {
	maxKey := make([]byte, len(prefix))
	copy(maxKey, prefix)
	for i := len(maxKey) - 1; i >= 0; i-- {
		if maxKey[i] < math.MaxUint8 {
			maxKey[i]++
			return maxKey[:i+1]
		}
	}
	return append(prefix, 0xFF)
}

// UserMetaValidated returns the UserMeta byte for the validated flag.
func UserMetaValidated(validated bool) byte {
	if validated {
		return 1
	}
	return 0
}
