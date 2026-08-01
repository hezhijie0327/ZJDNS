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
	eipLatencyPrefix = "e:lat:"

	// PrefixDNSCrypt is the key prefix for server-scoped DNSCrypt state.
	// s: = server scope (vs e: = cache data).
	PrefixDNSCrypt = "s:dnscrypt:"
)

// Sequence keys for auto-incrementing IDs via badger.Sequence.
const (
	seqEntry = "seq:entry"
)

// DNSCrypt state value sizes (binary, BigEndian).
const (
	dnscryptIdentitySize = 96 // ed25519 sk(64) + ed25519 pk(32)
	dnscryptWindowSize   = 76 // serial(4) + not_before(4) + not_after(4) + resolver_sk(32) + resolver_pk(32)
)

// userMetaValidated is the UserMeta bit for the validated flag.
const userMetaValidated = 1 << 0

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

// EIPLatencyKey builds a latency key. It lives in its own e:lat: namespace,
// NOT under e:ip: — the e:ip: sub-space is scanned by EIPReversePrefix and
// latency keys there would be misparsed as reverse-lookup entries.
//
//	Layout: e:lat:{ip}
func EIPLatencyKey(ip string) []byte {
	buf := make([]byte, len(eipLatencyPrefix)+len(ip))
	off := copy(buf, eipLatencyPrefix)
	copy(buf[off:], ip)
	return buf
}

// ── Value Encoding ────────────────────────────────────────────────────────────

// EncodePtrMapValue packs a ptr_map entry value: the record TTL plus the
// write timestamp so the remaining TTL can be derived exactly on read
// (the old value stored only the TTL, so ReverseLookup always fell into the
// stale branch). Negative TTLs are clamped to 0 — a wire TTL >= 2^31 would
// otherwise round-trip as a negative int32.
//
//	Layout: [0:4]ttl int32 BE, [4:12]write_unix int64 BE
func EncodePtrMapValue(ttl int32, now int64) []byte {
	if ttl < 0 {
		ttl = 0
	}
	buf := make([]byte, 12)
	binary.BigEndian.PutUint32(buf[0:4], uint32(ttl))  //nolint:gosec // G115: protocol-bounded value fits target type
	binary.BigEndian.PutUint64(buf[4:12], uint64(now)) //nolint:gosec // G115: unix timestamp — protocol-bounded int64
	return buf
}

// DecodePtrMapValue unpacks a ptr_map value's TTL.
func DecodePtrMapValue(data []byte) (ttl int32) {
	if len(data) < 4 {
		return 0
	}
	ttl = int32(binary.BigEndian.Uint32(data[0:4])) //nolint:gosec // G115: protocol-bounded value fits target type
	return ttl
}

// DecodePtrMapTimestamp unpacks a ptr_map value's write timestamp. Returns 0
// for values written by older versions (4-byte layout) — callers fall back
// to the entry's ExpiresAt in that case.
func DecodePtrMapTimestamp(data []byte) int64 {
	if len(data) < 12 {
		return 0
	}
	return int64(binary.BigEndian.Uint64(data[4:12])) //nolint:gosec // G115: unix timestamp — protocol-bounded int64
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

// EncodeDNSCryptIdentity encodes an Ed25519 signing key pair.
//
//	Layout: [0:64]sk [64:96]pk
//
// Returns nil if sk is not 64 bytes or pk is not 32 bytes.
func EncodeDNSCryptIdentity(sk, pk []byte) []byte {
	if len(sk) != 64 || len(pk) != 32 {
		return nil
	}
	buf := make([]byte, dnscryptIdentitySize)
	copy(buf[0:64], sk)
	copy(buf[64:96], pk)
	return buf
}

// DecodeDNSCryptIdentity decodes an Ed25519 signing key pair.
func DecodeDNSCryptIdentity(data []byte) (sk, pk []byte) {
	if len(data) < dnscryptIdentitySize {
		return nil, nil
	}
	sk = make([]byte, 64)
	pk = make([]byte, 32)
	copy(sk, data[0:64])
	copy(pk, data[64:96])
	return sk, pk
}

// EncodeDNSCryptWindow encodes a single DNSCrypt certificate window.
//
//	Layout: [0:4]serial [4:8]not_before [8:12]not_after [12:44]resolver_sk [44:76]resolver_pk
//
// Returns nil if resolverSk or resolverPk is not 32 bytes.
func EncodeDNSCryptWindow(serial, notBefore, notAfter uint32, resolverSk, resolverPk []byte) []byte {
	if len(resolverSk) != 32 || len(resolverPk) != 32 {
		return nil
	}
	buf := make([]byte, dnscryptWindowSize)
	binary.BigEndian.PutUint32(buf[0:4], serial)
	binary.BigEndian.PutUint32(buf[4:8], notBefore)
	binary.BigEndian.PutUint32(buf[8:12], notAfter)
	copy(buf[12:44], resolverSk)
	copy(buf[44:76], resolverPk)
	return buf
}

// DecodeDNSCryptWindow decodes a single DNSCrypt certificate window.
func DecodeDNSCryptWindow(data []byte) (serial, notBefore, notAfter uint32, resolverSk, resolverPk []byte) {
	if len(data) < dnscryptWindowSize {
		return 0, 0, 0, nil, nil
	}
	serial = binary.BigEndian.Uint32(data[0:4])
	notBefore = binary.BigEndian.Uint32(data[4:8])
	notAfter = binary.BigEndian.Uint32(data[8:12])
	resolverSk = make([]byte, 32)
	resolverPk = make([]byte, 32)
	copy(resolverSk, data[12:44])
	copy(resolverPk, data[44:76])
	return serial, notBefore, notAfter, resolverSk, resolverPk
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// UserMetaValidated returns the UserMeta byte for the validated flag.
func UserMetaValidated(validated bool) byte {
	if validated {
		return userMetaValidated
	}
	return 0
}
