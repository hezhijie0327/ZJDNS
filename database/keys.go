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
	prefixEntry = "e:"
	eipPrefix   = "e:ip:"
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
	if ecsPrefix < 0 {
		ecsPrefix = 0
	} else if ecsPrefix > math.MaxUint16 {
		ecsPrefix = math.MaxUint16
	}
	binary.BigEndian.PutUint16(buf[off:], uint16(ecsPrefix))
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
	if latencyMS < 0 {
		latencyMS = 0
	} else if latencyMS > math.MaxUint16 {
		latencyMS = math.MaxUint16
	}
	binary.BigEndian.PutUint16(buf[0:2], uint16(latencyMS))
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

// ── Helpers ───────────────────────────────────────────────────────────────────
// UserMetaValidated returns the UserMeta byte for the validated flag.
func UserMetaValidated(validated bool) byte {
	if validated {
		return 1
	}
	return 0
}
