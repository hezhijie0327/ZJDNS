// Package database provides a unified BadgerDB key-value store backing all
// ZJDNS subsystems (cache, zone, ruleset). It manages the DB lifecycle and
// provides shared key construction, encoding, and decoding utilities.
package database

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Key prefix constants — each "table" gets its own prefix byte.
// '\x00' is the field separator; it's the smallest byte value so
// prefix scans stop cleanly at the boundary.
const (
	prefixEntry      = "e:" // DNS response cache
	prefixPtrMap     = "p:" // IP → domain reverse lookup
	prefixLatency    = "l:" // per-IP probe latency
	prefixQueryStats = "s:" // per-day aggregated query counters
	prefixQueryLog   = "q:" // query audit log
	prefixZone       = "z:" // zone-file rule entries
	prefixRuleSet    = "r:" // CIDR/domain ruleset entries
)

// Sequence keys for auto-incrementing IDs via badger.Sequence.
const (
	seqEntry = "seq:entry"
	seqQLog  = "seq:qlog"
)

// ── Key Construction ─────────────────────────────────────────────────────────

// EntryKey builds the primary cache key for a DNS response entry.
//
//	Layout: e:{qname}\x00{ecs_addr}\x00{ecs_prefix:04x}\x00{dnssec_ok}\x00{qtype:04x}\x00{qclass:04x}
func EntryKey(qname, ecsAddr string, ecsPrefix int, dnssecOK bool, qtype, qclass uint16) []byte {
	dnssec := '0'
	if dnssecOK {
		dnssec = '1'
	}
	return entryKeyBytes(qname, ecsAddr, ecsPrefix, dnssec, qtype, qclass)
}

// EntryKeyPrefix returns the prefix for all cache entry keys.
func EntryKeyPrefix() []byte { return []byte(prefixEntry) }

// entryKeyBytes is the shared implementation — avoids allocation for the
// caller when the dnssecOK is already a rune.
func entryKeyBytes(qname, ecsAddr string, ecsPrefix int, dnssec rune, qtype, qclass uint16) []byte {
	// Pre-allocate: 2 (prefix) + qname + 1 (sep) + ecsAddr + 1 (sep) +
	// 4 (ecsPrefix hex) + 1 (sep) + 1 (dnssec) + 1 (sep) +
	// 4 (qtype hex) + 1 (sep) + 4 (qclass hex)
	return fmt.Appendf(nil, "%s%s\x00%s\x00%04x\x00%c\x00%04x\x00%04x",
		prefixEntry, qname, ecsAddr, ecsPrefix, dnssec, qtype, qclass)
}

// PtrMapKey builds a reverse-lookup key.
//
//	Layout: p:{rdata_ip}\x00{entry_id:016x}\x00{name}
func PtrMapKey(ip string, entryID uint64, name string) []byte {
	return fmt.Appendf(nil, "%s%s\x00%016x\x00%s", prefixPtrMap, ip, entryID, name)
}

// PtrMapIPPrefix returns the prefix for all ptr_map entries for a given IP.
func PtrMapIPPrefix(ip string) []byte {
	return []byte(prefixPtrMap + ip + "\x00")
}

// LatencyKey builds an IP latency key.
//
//	Layout: l:{rdata_ip}
func LatencyKey(ip string) []byte {
	return []byte(prefixLatency + ip)
}

// QueryStatsKey builds a per-day aggregated stats key.
//
//	Layout: s:{stat_day:08x}\x00{result}\x00{protocol}\x00{rcode:04x}\x00{dnssec}\x00{poisoned}
func QueryStatsKey(statDay int64, result, protocol string, rcode int, dnssec string, poisoned int) []byte {
	return fmt.Appendf(nil, "%s%08x\x00%s\x00%s\x00%04x\x00%s\x00%d",
		prefixQueryStats, statDay, result, protocol, rcode, dnssec, poisoned)
}

// QueryStatsPrefix returns the prefix for all query_stats keys.
func QueryStatsPrefix() []byte { return []byte(prefixQueryStats) }

// QueryLogKey builds a query audit log key.
//
//	Layout: q:{timestamp:016x}\x00{seq:016x}
func QueryLogKey(timestamp int64, seq uint64) []byte {
	return fmt.Appendf(nil, "%s%016x\x00%016x", prefixQueryLog, timestamp, seq)
}

// QueryLogPrefix returns the prefix for all query_log keys.
func QueryLogPrefix() []byte { return []byte(prefixQueryLog) }

// ZoneEntryKey builds a zone rule entry key.
//
//	Layout: z:{is_wildcard}\x00{qname}\x00{qtype:04x}\x00{qclass:04x}\x00{match_tags}
func ZoneEntryKey(isWildcard bool, qname string, qtype, qclass uint16, matchTags string) []byte {
	w := '0'
	if isWildcard {
		w = '1'
	}
	return fmt.Appendf(nil, "%s%c\x00%s\x00%04x\x00%04x\x00%s",
		prefixZone, w, qname, qtype, qclass, matchTags)
}

// ZoneExactPrefix returns the prefix for exact-match zone lookups.
func ZoneExactPrefix(qname string, qtype, qclass uint16) []byte {
	return fmt.Appendf(nil, "z:0\x00%s\x00%04x\x00%04x\x00", qname, qtype, qclass)
}

// ZoneWildcardPrefix returns the prefix for wildcard zone lookups on a suffix.
func ZoneWildcardPrefix(suffix string) []byte {
	return []byte("z:1\x00" + suffix + "\x00")
}

// RuleSetKey builds a ruleset entry key.
//
//	Layout: r:{type}\x00{value}\x00{tag}
func RuleSetKey(kind, value, tag string) []byte {
	return fmt.Appendf(nil, "%s%s\x00%s\x00%s", prefixRuleSet, kind, value, tag)
}

// RuleSetTypePrefix returns the prefix for all rules of a given type.
func RuleSetTypePrefix(kind string) []byte {
	return []byte(prefixRuleSet + kind + "\x00")
}

// RuleSetTypeValuePrefix returns the prefix for domain rule lookups.
func RuleSetTypeValuePrefix(kind, value string) []byte {
	return []byte(prefixRuleSet + kind + "\x00" + value + "\x00")
}

// ── Value Encoding ────────────────────────────────────────────────────────────

// EncodeEntryValue packs cache entry metadata + compressed wire format.
//
//	Layout: [0:8]id uint64 BE, [8:16]ts int64 BE, [16:20]ttl int32 BE, [20:]zstd_wire
//
// The validated flag is stored in the Entry.UserMeta byte, not in the value.
func EncodeEntryValue(id uint64, ts int64, ttl int32, msgWire []byte) []byte {
	buf := make([]byte, 20+len(msgWire))
	binary.BigEndian.PutUint64(buf[0:8], id)
	binary.BigEndian.PutUint64(buf[8:16], uint64(ts))   //nolint:gosec // G115: protocol-bounded value fits target type
	binary.BigEndian.PutUint32(buf[16:20], uint32(ttl)) //nolint:gosec // G115: protocol-bounded value fits target type
	copy(buf[20:], msgWire)
	return buf
}

// DecodeEntryValue unpacks a cache entry value. Returns zero values and false if
// the data is too short.
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

// EncodePtrMapValue packs a ptr_map entry value.
//
//	Layout: [0:4]ttl int32 BE, [4:12]expires_at int64 BE
func EncodePtrMapValue(ttl int32, expiresAt int64) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint32(buf[0:4], uint32(ttl))        //nolint:gosec // G115: protocol-bounded value fits target type
	binary.BigEndian.PutUint64(buf[4:12], uint64(expiresAt)) //nolint:gosec // G115: protocol-bounded value fits target type
	return buf
}

// DecodePtrMapValue unpacks a ptr_map value.
func DecodePtrMapValue(data []byte) (ttl int32, expiresAt int64) {
	if len(data) < 12 {
		return 0, 0
	}
	ttl = int32(binary.BigEndian.Uint32(data[0:4]))        //nolint:gosec // G115: protocol-bounded value fits target type
	expiresAt = int64(binary.BigEndian.Uint64(data[4:12])) //nolint:gosec // G115: protocol-bounded value fits target type
	return ttl, expiresAt
}

// EncodeLatencyValue packs an IP latency measurement.
//
//	Layout: [0:2]qtype uint16 BE, [2:6]latency_ms int32 BE, [6:14]last_probe int64 BE
func EncodeLatencyValue(qtype uint16, latencyMS int, lastProbe int64) []byte {
	buf := make([]byte, 14)
	binary.BigEndian.PutUint16(buf[0:2], qtype)
	binary.BigEndian.PutUint32(buf[2:6], uint32(latencyMS))  //nolint:gosec // G115: protocol-bounded value fits target type
	binary.BigEndian.PutUint64(buf[6:14], uint64(lastProbe)) //nolint:gosec // G115: protocol-bounded value fits target type
	return buf
}

// DecodeLatencyValue unpacks a latency value.
func DecodeLatencyValue(data []byte) (qtype uint16, latencyMS int, lastProbe int64) {
	if len(data) < 14 {
		return 0, 0, 0
	}
	qtype = binary.BigEndian.Uint16(data[0:2])
	latencyMS = int(binary.BigEndian.Uint32(data[2:6]))
	lastProbe = int64(binary.BigEndian.Uint64(data[6:14])) //nolint:gosec // G115: protocol-bounded value fits target type
	return qtype, latencyMS, lastProbe
}

// EncodeQueryStatsValue packs aggregated stat counters.
//
//	Layout: [0:8]query_count int64 BE, [8:16]total_ms int64 BE
func EncodeQueryStatsValue(queryCount, totalMS int64) []byte {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:8], uint64(queryCount)) //nolint:gosec // G115: protocol-bounded value fits target type //nolint:gosec // G115: stats counter
	binary.BigEndian.PutUint64(buf[8:16], uint64(totalMS))   //nolint:gosec // G115: protocol-bounded value fits target type //nolint:gosec // G115: stats counter
	return buf
}

// DecodeQueryStatsValue unpacks a stats value.
func DecodeQueryStatsValue(data []byte) (queryCount, totalMS int64) {
	if len(data) < 16 {
		return 0, 0
	}
	queryCount = int64(binary.BigEndian.Uint64(data[0:8])) //nolint:gosec // G115: protocol-bounded value fits target type //nolint:gosec // G115: stats counter
	totalMS = int64(binary.BigEndian.Uint64(data[8:16]))   //nolint:gosec // G115: protocol-bounded value fits target type //nolint:gosec // G115: stats counter
	return queryCount, totalMS
}

// EncodeQueryLogValue packs an audit log entry. Variable-length strings are
// length-prefixed with uint16 LE (strings are short — max 255 chars for
// protocol, 65k for qname).
//
//	Layout: [0:8]ts BE, [8:10]qtype BE, [10:12]qclass BE, [12:14]rcode BE,
//	        [14:18]response_ms BE, [18:19]poisoned byte, [19:20]dnssecLen byte,
//	        then dnssec bytes, [dnssecOff:]: qnameLen uint16 LE, qname,
//	        protocolLen uint16 LE, protocol, resultLen uint16 LE, result,
//	        serverLen uint16 LE, server
func EncodeQueryLogValue(ts int64, qname string, qtype, qclass uint16, protocol, result string,
	rcode int, responseMS int64, server string, poisoned int, dnssecStatus string,
) []byte {
	// Calculate total size: 20-byte fixed header + variable strings
	size := 20 + len(dnssecStatus) + 2 + len(qname) + 2 + len(protocol) + 2 + len(result) + 2 + len(server)
	buf := make([]byte, size)

	binary.BigEndian.PutUint64(buf[0:8], uint64(ts)) //nolint:gosec // G115: protocol-bounded value fits target type //nolint:gosec // G115: protocol-bounded value
	binary.BigEndian.PutUint16(buf[8:10], qtype)
	binary.BigEndian.PutUint16(buf[10:12], qclass)
	binary.BigEndian.PutUint16(buf[12:14], uint16(rcode))      //nolint:gosec // G115: protocol-bounded value fits target type //nolint:gosec // G115: DNS rcode fits uint16
	binary.BigEndian.PutUint32(buf[14:18], uint32(responseMS)) //nolint:gosec // G115: protocol-bounded value fits target type
	buf[18] = byte(poisoned)                                   //nolint:gosec // G115: protocol-bounded value fits target type
	buf[19] = byte(len(dnssecStatus))                          //nolint:gosec // G115: protocol-bounded value fits target type
	off := 20
	copy(buf[off:], dnssecStatus)
	off += len(dnssecStatus)

	off = putStringLE(buf, off, qname)
	off = putStringLE(buf, off, protocol)
	off = putStringLE(buf, off, result)
	_ = putStringLE(buf, off, server)
	return buf
}

// DecodeQueryLogValue unpacks a query log value.
//
//nolint:gocritic // 11 return values from packed binary; a struct would add allocation overhead
//nolint:gocritic // 11 return values from packed binary
func DecodeQueryLogValue(data []byte) (ts int64, qname string, qtype, qclass uint16, protocol, result string,
	//nolint:gocritic // 11 return values from packed binary; a struct would add allocation overhead
	rcode, responseMS int, server string, poisoned int, dnssecStatus string,
) {
	if len(data) < 20 {
		return ts, qname, qtype, qclass, protocol, result, rcode, responseMS, server, poisoned, dnssecStatus
	}
	ts = int64(binary.BigEndian.Uint64(data[0:8])) //nolint:gosec // G115: protocol-bounded value fits target type //nolint:gosec // G115: protocol-bounded value
	qtype = binary.BigEndian.Uint16(data[8:10])
	qclass = binary.BigEndian.Uint16(data[10:12])
	rcode = int(binary.BigEndian.Uint16(data[12:14]))
	responseMS = int(binary.BigEndian.Uint32(data[14:18]))
	poisoned = int(data[18])
	dnssecLen := int(data[19])
	off := 20
	if off+dnssecLen <= len(data) {
		dnssecStatus = string(data[off : off+dnssecLen])
		off += dnssecLen
	}

	qname, off = getStringLE(data, off)
	protocol, off = getStringLE(data, off)
	result, off = getStringLE(data, off)
	server, _ = getStringLE(data, off)
	return ts, qname, qtype, qclass, protocol, result, rcode, responseMS, server, poisoned, dnssecStatus
}

// EncodeZoneValue packs zone rule response data.
//
//	Layout: [0:2]rcode uint16 BE, then 3× length-prefixed zstd blobs (uint32 LE len + data)
func EncodeZoneValue(rcode int, answer, authority, additional []byte) []byte {
	size := 2 + 4 + len(answer) + 4 + len(authority) + 4 + len(additional)
	buf := make([]byte, size)
	binary.BigEndian.PutUint16(buf[0:2], uint16(rcode)) //nolint:gosec // G115: protocol-bounded value fits target type //nolint:gosec // G115: DNS rcode fits uint16
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

// putStringLE writes a uint16 length (LE) followed by the string bytes.
// Returns the new offset.
func putStringLE(buf []byte, off int, s string) int {
	binary.LittleEndian.PutUint16(buf[off:off+2], uint16(len(s))) //nolint:gosec // G115: string length fits uint16 for DNS names
	off += 2
	copy(buf[off:], s)
	return off + len(s)
}

// getStringLE reads a uint16 length (LE) followed by string bytes.
// Returns the string and new offset.
func getStringLE(data []byte, off int) (s string, newOff int) {
	if off+2 > len(data) {
		return "", off
	}
	n := int(binary.LittleEndian.Uint16(data[off : off+2]))
	off += 2
	if off+n > len(data) {
		return "", off
	}
	s = string(data[off : off+n])
	return s, off + n
}

// putBytesLE writes a uint32 length (LE) followed by the bytes.
func putBytesLE(buf []byte, off int, b []byte) int {
	binary.LittleEndian.PutUint32(buf[off:off+4], uint32(len(b))) //nolint:gosec // G115: protocol-bounded value fits target type
	off += 4
	copy(buf[off:], b)
	return off + len(b)
}

// getBytesLE reads a uint32 length (LE) followed by bytes.
func getBytesLE(data []byte, off int) (b []byte, newOff int) {
	if off+4 > len(data) {
		return nil, off
	}
	n := int(binary.LittleEndian.Uint32(data[off : off+4]))
	off += 4
	if off+n > len(data) {
		return nil, off
	}
	// Return a copy so the caller owns the memory.
	b = make([]byte, n)
	copy(b, data[off:off+n])
	return b, off + n
}

// ── Key Parsing ───────────────────────────────────────────────────────────────

// ParseEntryKeyTimestamp extracts the timestamp from an entry key by reading
// the value (which requires a DB lookup). This is a stub — the actual extraction
// happens during prefix scan eviction where we decode values.
//
// For eviction sorting, we collect (key, timestamp) pairs during iteration.

// ParseStatDay extracts stat_day from a query_stats key for pruning.
// Key format: s:{stat_day:08x}\x00...
func ParseStatDay(key []byte) (int64, bool) {
	s := string(key)
	if !strings.HasPrefix(s, prefixQueryStats) {
		return 0, false
	}
	// stat_day is 8 hex chars after the 2-byte prefix.
	if len(s) < 2+8 {
		return 0, false
	}
	v, err := strconv.ParseInt(s[2:10], 16, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// ParseQueryLogTimestamp extracts the timestamp from a query_log key.
// Key format: q:{timestamp:016x}\x00{seq:016x}
func ParseQueryLogTimestamp(key []byte) (int64, bool) {
	s := string(key)
	if !strings.HasPrefix(s, prefixQueryLog) {
		return 0, false
	}
	if len(s) < 2+16 {
		return 0, false
	}
	v, err := strconv.ParseInt(s[2:18], 16, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// ParseStatDayFromKey is like ParseStatDay but ensures correct hex format.
func ParseStatDayFromKey(key []byte) int64 {
	v, _ := ParseStatDay(key)
	return v
}

// StatsKeyDayCutoff returns the key prefix for stat_day values up to cutoff.
// Used for range-based deletion during pruning.
func StatsKeyDayCutoff(cutoff int64) []byte {
	return fmt.Appendf(nil, "%s%08x", prefixQueryStats, cutoff)
}

// QueryLogTimestampCutoff returns the key prefix for timestamps up to cutoff.
func QueryLogTimestampCutoff(cutoff int64) []byte {
	return fmt.Appendf(nil, "%s%016x", prefixQueryLog, cutoff)
}

// MaxKey returns a key that sorts after all keys with the given prefix.
func MaxKey(prefix []byte) []byte {
	maxKey := make([]byte, len(prefix))
	copy(maxKey, prefix)
	// Append 0xFF bytes until we pass any possible key length.
	// In practice, a single \xff after the prefix is enough since separator is \x00.
	for i := len(maxKey) - 1; i >= 0; i-- {
		if maxKey[i] < math.MaxUint8 {
			maxKey[i]++
			return maxKey[:i+1]
		}
	}
	return append(prefix, 0xFF)
}

// BoolToInt converts a bool to 0 or 1 for storage in metadata or value fields.
func BoolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// UserMetaValidated returns the UserMeta byte for the validated flag.
func UserMetaValidated(validated bool) byte {
	if validated {
		return 1
	}
	return 0
}
