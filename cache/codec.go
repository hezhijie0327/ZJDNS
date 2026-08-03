package cache

import (
	"bytes"
	"encoding/binary"
	"io"
	"zjdns/internal/log"
)

// cacheCodec implements lrumap.Codec for the DNS response cache. The on-disk
// layout is owned by lrumap (version header + framed key/value pairs); this
// codec owns the per-field encoding only.
type cacheCodec struct{}

// ptrCodec implements lrumap.Codec for the PTR reverse index
// (ip → derived records).
type ptrCodec struct{}

// latencyCodec implements lrumap.Codec for the IP latency cache
// (ip → {ms, expiresAt}).
type latencyCodec struct{}

// cachePersistVersion gates the cache persist format. v1 was the old
// PersistFile layout; v2 is the codec-based framing — older files are skipped
// (cold start).
const cachePersistVersion = 2

const (
	ptrPersistVersion     = 1
	latencyPersistVersion = 1
)

func (cacheCodec) Version() uint16 { return cachePersistVersion }

// EncodeKey serializes the typed cache key — no hand-rolled binary key
// encoding; the codec keeps the string fields length-prefixed.
func (cacheCodec) EncodeKey(k entryKey) []byte { return encodeEntryKey(k) }

// DecodeKey parses the layout produced by EncodeKey.
func (cacheCodec) DecodeKey(b []byte) (entryKey, error) { return decodeEntryKey(b) }

// encodeEntryKey serializes an entryKey — shared by the cache codec and the
// PTR codec (ptrRecord.ownerKey).
func encodeEntryKey(k entryKey) []byte {
	var buf bytes.Buffer
	writeBytes(&buf, []byte(k.qname))
	writeBytes(&buf, []byte(k.ecsAddr))
	writeU16(&buf, k.ecsPrefix)
	if k.dnssecOK {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	writeU16(&buf, k.qtype)
	writeU16(&buf, k.qclass)
	return buf.Bytes()
}

// decodeEntryKey parses the layout produced by encodeEntryKey.
func decodeEntryKey(b []byte) (entryKey, error) {
	var k entryKey
	off := 0
	var raw []byte
	var err error
	if raw, off, err = takeBytes(b, off); err != nil {
		return k, err
	}
	k.qname = string(raw)
	if raw, off, err = takeBytes(b, off); err != nil {
		return k, err
	}
	k.ecsAddr = string(raw)
	if off+2 > len(b) {
		return k, io.ErrUnexpectedEOF
	}
	k.ecsPrefix = binary.BigEndian.Uint16(b[off:])
	off += 2
	if off+1 > len(b) {
		return k, io.ErrUnexpectedEOF
	}
	k.dnssecOK = b[off] == 1
	off++
	if off+4 > len(b) {
		return k, io.ErrUnexpectedEOF
	}
	k.qtype = binary.BigEndian.Uint16(b[off:])
	k.qclass = binary.BigEndian.Uint16(b[off+2:])
	return k, nil
}

// EncodeValue serializes one cached response: wire value + timing metadata.
func (cacheCodec) EncodeValue(v cacheEntry) []byte {
	var buf bytes.Buffer
	buf.Grow(4 + len(v.value) + 9)
	writeBytes(&buf, v.value)
	writeU64(&buf, uint64(v.expiresAt)) //nolint:gosec // G115: unix timestamp — protocol-bounded int64
	if v.validated {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	return buf.Bytes()
}

// DecodeValue parses the layout produced by EncodeValue. Entries that expired
// while on disk are skipped (include=false).
func (cacheCodec) DecodeValue(b []byte) (cacheEntry, bool, error) {
	var e cacheEntry
	off := 0
	var err error
	if e.value, off, err = takeBytes(b, off); err != nil {
		return e, false, err
	}
	if off+9 > len(b) {
		return e, false, io.ErrUnexpectedEOF
	}
	e.expiresAt = int64(binary.BigEndian.Uint64(b[off:])) //nolint:gosec // G115: unix timestamp — protocol-bounded int64
	e.validated = b[off+8] == 1
	if e.expiresAt > 0 && e.expiresAt < log.NowUnix() {
		return e, false, nil
	}
	return e, true, nil
}

// ── PTR codec ─────────────────────────────────────────────────────────────

func (ptrCodec) Version() uint16 { return ptrPersistVersion }

func (ptrCodec) EncodeKey(ip string) []byte { return []byte(ip) }

func (ptrCodec) DecodeKey(b []byte) (string, error) { return string(b), nil }

// EncodeValue serializes one IP's derived records. Per record:
// name + ttl + ts + expiresAt + ownerKey (entryKey encoding).
func (ptrCodec) EncodeValue(recs []*ptrRecord) []byte {
	var buf bytes.Buffer
	writeU16(&buf, uint16(len(recs))) //nolint:gosec // G115: records per IP are bounded (< 64K)
	for _, r := range recs {
		writeBytes(&buf, []byte(r.name))
		writeU32(&buf, uint32(r.ttl))       //nolint:gosec // G115: DNS TTL — protocol-bounded
		writeU64(&buf, uint64(r.ts))        //nolint:gosec // G115: unix timestamp — protocol-bounded
		writeU64(&buf, uint64(r.expiresAt)) //nolint:gosec // G115: unix timestamp — protocol-bounded int64
		writeBytes(&buf, encodeEntryKey(r.ownerKey))
	}
	return buf.Bytes()
}

// DecodeValue parses the layout produced by EncodeValue. Records that
// expired while on disk are dropped; an entry with no live records left is
// skipped (include=false).
func (ptrCodec) DecodeValue(b []byte) ([]*ptrRecord, bool, error) {
	now := log.NowUnix()
	if len(b) < 2 {
		return nil, false, io.ErrUnexpectedEOF
	}
	count := int(binary.BigEndian.Uint16(b[:2])) //nolint:gosec // G115: protocol-bounded uint16
	off := 2
	recs := make([]*ptrRecord, 0, count)
	for range count {
		var raw []byte
		var err error
		r := &ptrRecord{}
		if raw, off, err = takeBytes(b, off); err != nil {
			return nil, false, err
		}
		r.name = string(raw)
		if off+20 > len(b) {
			return nil, false, io.ErrUnexpectedEOF
		}
		r.ttl = int32(binary.BigEndian.Uint32(b[off:]))          //nolint:gosec // G115: DNS TTL — protocol-bounded
		r.ts = int64(binary.BigEndian.Uint64(b[off+4:]))         //nolint:gosec // G115: unix timestamp — protocol-bounded
		r.expiresAt = int64(binary.BigEndian.Uint64(b[off+12:])) //nolint:gosec // G115: unix timestamp — protocol-bounded
		off += 20
		if raw, off, err = takeBytes(b, off); err != nil {
			return nil, false, err
		}
		if r.ownerKey, err = decodeEntryKey(raw); err != nil {
			return nil, false, err
		}
		if r.expiresAt > 0 && r.expiresAt < now {
			continue
		}
		recs = append(recs, r)
	}
	if len(recs) == 0 {
		return nil, false, nil // all records expired while on disk
	}
	return recs, true, nil
}

// ── Latency codec ─────────────────────────────────────────────────────────

func (latencyCodec) Version() uint16 { return latencyPersistVersion }

func (latencyCodec) EncodeKey(ip string) []byte { return []byte(ip) }

func (latencyCodec) DecodeKey(b []byte) (string, error) { return string(b), nil }

// EncodeValue serializes one latency measurement: ms + expiry.
func (latencyCodec) EncodeValue(v latencyEntry) []byte {
	var buf bytes.Buffer
	buf.Grow(16)
	writeU64(&buf, uint64(v.value))     //nolint:gosec // G115: bit-pattern copy of int
	writeU64(&buf, uint64(v.expiresAt)) //nolint:gosec // G115: unix timestamp — protocol-bounded int64
	return buf.Bytes()
}

// DecodeValue parses the layout produced by EncodeValue; expired
// measurements are skipped.
func (latencyCodec) DecodeValue(b []byte) (latencyEntry, bool, error) {
	if len(b) < 16 {
		return latencyEntry{}, false, io.ErrUnexpectedEOF
	}
	v := latencyEntry{
		value:     int(binary.BigEndian.Uint64(b[:8])),   //nolint:gosec // G115: bit-pattern copy of int
		expiresAt: int64(binary.BigEndian.Uint64(b[8:])), //nolint:gosec // G115: unix timestamp — protocol-bounded
	}
	if v.expiresAt > 0 && v.expiresAt < log.NowUnix() {
		return v, false, nil
	}
	return v, true, nil
}

// ── Primitive writers ──────────────────────────────────────────────────

func writeU16(buf *bytes.Buffer, v uint16) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	buf.Write(b[:])
}

func writeU32(buf *bytes.Buffer, v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	buf.Write(b[:])
}

func writeU64(buf *bytes.Buffer, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	buf.Write(b[:])
}

func writeBytes(buf *bytes.Buffer, b []byte) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b))) //nolint:gosec // G115: keys/values bounded by uint32
	buf.Write(hdr[:])
	buf.Write(b)
}

// takeBytes reads a length-prefixed byte slice, returning the new offset.
func takeBytes(raw []byte, off int) (b []byte, next int, err error) {
	if off+4 > len(raw) {
		return nil, 0, io.ErrUnexpectedEOF
	}
	n := int(binary.BigEndian.Uint32(raw[off:])) //nolint:gosec // G115: protocol-bounded uint32
	off += 4
	if off+n > len(raw) {
		return nil, 0, io.ErrUnexpectedEOF
	}
	return raw[off : off+n], off + n, nil
}
