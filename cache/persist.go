package cache

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"zjdns/internal/persist"
)

// PersistFile is the on-disk persist format for the cache: cache records
// only (DNSCrypt state lives in its own file — see server/protocol/dnscrypt).
type PersistFile struct {
	Version uint16
	Entries []PersistEntry
}

// PersistEntry is a single cached DNS response in wire format. Cache-key
// fields are typed — no hand-rolled binary key encoding; callers use them
// directly as an in-memory map key.
type PersistEntry struct {
	Qname     string // query name (canonical, with trailing dot)
	ECSAddr   string // ECS client address; empty = no ECS
	ECSPrefix uint16 // ECS source prefix length
	DNSsecOK  bool   // query had the DNSSEC OK bit
	Qtype     uint16
	Qclass    uint16
	Value     []byte // DNS wire format
	ExpiresAt int64  // unix seconds; 0 = never expires
	Validated bool   // DNSSEC validation status
}

// Persist file version and magic — "ZJDNS" is the project name.
const (
	fileVersion = 1
	fileMagic   = "ZJDNS"
)

// ErrBadMagic is returned when the file does not carry the ZJDNS magic.
var ErrBadMagic = errors.New("cache: bad magic")

// Load reads the cache persist file. A missing file is not an error: it
// returns a nil PersistFile (cold start). Corrupt files are surfaced as
// errors — silently discarding them would hide data loss.
func Load(path string) (*PersistFile, error) {
	raw, err := persist.Load(path)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil //nolint:nilnil // cold start — missing file is not an error
	}
	f, err := decode(raw)
	if err != nil {
		return nil, fmt.Errorf("cache: decode %s: %w", path, err)
	}
	return f, nil
}

// Save encodes and persists the file (zstd + atomic write via internal/persist).
func (f *PersistFile) Save(path string) error {
	if err := persist.Save(path, encode(f)); err != nil {
		return err
	}
	return nil
}

// ── Encoding ────────────────────────────────────────────────────────────

// encode serializes f into the binary layout.
//
//	[5B magic][2B version][8B entry_count]
//	per Entry: [2B qname_len][qname][1B has_ecs]
//	           (if has_ecs) [2B ecs_addr_len][ecs_addr][2B ecs_prefix]
//	           [1B dnssec][2B qtype][2B qclass][4B value_len][value][8B expires_at][1B validated]
func encode(f *PersistFile) []byte {
	var buf bytes.Buffer
	buf.Grow(16 + 32) // header + per-entry overhead
	buf.WriteString(fileMagic)
	writeU16(&buf, fileVersion)
	writeU64(&buf, uint64(len(f.Entries))) //nolint:gosec // G115: slice len bounded by memory
	for _, e := range f.Entries {
		writeBytesU16(&buf, []byte(e.Qname))
		if e.ECSAddr == "" {
			buf.WriteByte(0)
		} else {
			buf.WriteByte(1)
			writeBytesU16(&buf, []byte(e.ECSAddr))
			writeU16(&buf, e.ECSPrefix)
		}
		if e.DNSsecOK {
			buf.WriteByte(1)
		} else {
			buf.WriteByte(0)
		}
		writeU16(&buf, e.Qtype)
		writeU16(&buf, e.Qclass)
		writeBytesU32(&buf, e.Value)
		writeU64(&buf, uint64(e.ExpiresAt)) //nolint:gosec // G115: unix timestamp — protocol-bounded int64
		if e.Validated {
			buf.WriteByte(1)
		} else {
			buf.WriteByte(0)
		}
	}
	return buf.Bytes()
}

// decode parses the binary layout produced by encode.
func decode(raw []byte) (*PersistFile, error) {
	if len(raw) < len(fileMagic)+2+8 {
		return nil, io.ErrUnexpectedEOF
	}
	if string(raw[:len(fileMagic)]) != fileMagic {
		return nil, ErrBadMagic
	}
	off := len(fileMagic)
	version := binary.BigEndian.Uint16(raw[off:])
	off += 2
	if version != fileVersion {
		return nil, fmt.Errorf("cache: unsupported version %d", version)
	}
	count := binary.BigEndian.Uint64(raw[off:])
	off += 8
	if count > uint64(len(raw)) { // each entry needs at least 8+1 bytes of header
		return nil, fmt.Errorf("cache: entry count %d exceeds data size", count)
	}

	f := &PersistFile{Version: version, Entries: make([]PersistEntry, 0, count)}
	for range count { //nolint:gosec // count bounded by file size above
		var e PersistEntry
		var err error
		var qname []byte
		if qname, off, err = takeBytesU16(raw, off); err != nil {
			return nil, err
		}
		e.Qname = string(qname)
		if off >= len(raw) {
			return nil, io.ErrUnexpectedEOF
		}
		if raw[off] == 1 {
			off++
			var addr []byte
			if addr, off, err = takeBytesU16(raw, off); err != nil {
				return nil, err
			}
			e.ECSAddr = string(addr)
			if off+2 > len(raw) {
				return nil, io.ErrUnexpectedEOF
			}
			e.ECSPrefix = binary.BigEndian.Uint16(raw[off:])
			off += 2
		} else {
			off++
		}
		if off+5 > len(raw) {
			return nil, io.ErrUnexpectedEOF
		}
		e.DNSsecOK = raw[off] == 1
		off++
		e.Qtype = binary.BigEndian.Uint16(raw[off:])
		e.Qclass = binary.BigEndian.Uint16(raw[off+2:])
		off += 4
		if e.Value, off, err = takeBytesU32(raw, off); err != nil {
			return nil, err
		}
		if off+9 > len(raw) {
			return nil, io.ErrUnexpectedEOF
		}
		e.ExpiresAt = int64(binary.BigEndian.Uint64(raw[off:])) //nolint:gosec // G115: unix timestamp — protocol-bounded int64
		off += 8
		e.Validated = raw[off] == 1
		off++
		f.Entries = append(f.Entries, e)
	}
	return f, nil
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

func writeBytesU16(buf *bytes.Buffer, b []byte) {
	writeU16(buf, uint16(len(b))) //nolint:gosec // G115: cache keys are < 64KB
	buf.Write(b)
}

func writeBytesU32(buf *bytes.Buffer, b []byte) {
	writeU32(buf, uint32(len(b))) //nolint:gosec // G115: values bounded by uint32 address space
	buf.Write(b)
}

// takeBytesU16 reads a length-prefixed byte slice, returning the new offset.
func takeBytesU16(raw []byte, off int) (b []byte, next int, err error) {
	if off+2 > len(raw) {
		return nil, 0, io.ErrUnexpectedEOF
	}
	n := int(binary.BigEndian.Uint16(raw[off:])) //nolint:gosec // G115: protocol-bounded uint16
	off += 2
	if off+n > len(raw) {
		return nil, 0, io.ErrUnexpectedEOF
	}
	return raw[off : off+n], off + n, nil
}

// takeBytesU32 reads a length-prefixed byte slice, returning the new offset.
func takeBytesU32(raw []byte, off int) (b []byte, next int, err error) {
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
