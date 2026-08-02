package cache

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
)

// PersistFile is the on-disk persist format for the cache: cache records plus
// the DNSCrypt state that rides along in the same file. Both are optional —
// a PersistFile with zero Entries and nil DNSCrypt is valid.
//
// The cache is the only reader and writer: New() loads it, Close() and
// DNSCrypt key rotation save it. Load/Save are the whole API — no KV
// operations, callers own their in-memory data.
type PersistFile struct {
	Version  uint16
	Entries  []PersistEntry
	DNSCrypt *DNSCrypt
}

// PersistEntry is a single cached DNS response in wire format. Cache-key fields are
// typed — no hand-rolled binary key encoding; callers use them directly as an
// in-memory map key.
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

// DNSCrypt is the server-scoped DNSCrypt state.
type DNSCrypt struct {
	Identity []byte // EncodeDNSCryptIdentity result (sk+pk)
	Windows  []Window
}

// Window is one DNSCrypt certificate window.
type Window struct {
	Serial     uint32
	NotBefore  uint32
	NotAfter   uint32
	ResolverSK []byte
	ResolverPK []byte
}

// Persist file version and magic — "ZJDNS" is the project name.
const (
	fileVersion = 1
	fileMagic   = "ZJDNS"
	zstdLevel   = zstd.SpeedFastest
)

// ErrBadMagic is returned when the file does not carry the ZJDNS magic.
var ErrBadMagic = errors.New("cache: bad magic")

// Load reads, decompresses, and decodes the persist file at path.
// A missing file is not an error: it returns a nil PersistFile (cold start).
// Corrupt files are surfaced as errors — silently discarding them would
// hide data loss.
func Load(path string) (*PersistFile, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is operator-configured persist file
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil //nolint:nilnil // cold start — missing file is not an error
		}
		return nil, fmt.Errorf("cache: read %s: %w", path, err)
	}

	raw, err := zstdDecompress(data)
	if err != nil {
		return nil, fmt.Errorf("cache: decompress %s: %w", path, err)
	}
	f, err := decode(raw)
	if err != nil {
		return nil, fmt.Errorf("cache: decode %s: %w", path, err)
	}
	return f, nil
}

// Save encodes, compresses, and atomically writes the file to path
// (write temp + rename, so a crash never leaves a truncated file).
func (f *PersistFile) Save(path string) error {
	raw := encode(f)
	compressed, err := zstdCompress(raw)
	if err != nil {
		return fmt.Errorf("cache: compress: %w", err)
	}
	if err := atomicWrite(path, compressed); err != nil {
		return fmt.Errorf("cache: write %s: %w", path, err)
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
//	[1B has_dnscrypt]
//	if has_dnscrypt:
//	  [4B identity_len][identity]
//	  [2B window_count]
//	  per Window: [4B serial][4B not_before][4B not_after][32B sk][32B pk]
func encode(f *PersistFile) []byte {
	var buf bytes.Buffer
	buf.Grow(16 + 32 + 17 + 80) // header + per-entry overhead + dnscrypt overhead
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

	if f.DNSCrypt == nil {
		buf.WriteByte(0)
		return buf.Bytes()
	}
	buf.WriteByte(1)
	writeBytesU32(&buf, f.DNSCrypt.Identity)
	writeU16(&buf, uint16(len(f.DNSCrypt.Windows))) //nolint:gosec // G115: window count capped at 2 by DNSCrypt rotation
	for _, w := range f.DNSCrypt.Windows {
		writeU32(&buf, w.Serial)
		writeU32(&buf, w.NotBefore)
		writeU32(&buf, w.NotAfter)
		buf.Write(w.ResolverSK)
		buf.Write(w.ResolverPK)
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

	if off >= len(raw) {
		return nil, io.ErrUnexpectedEOF
	}
	if raw[off] == 0 {
		return f, nil
	}
	off++
	dc := &DNSCrypt{}
	var err error
	if dc.Identity, off, err = takeBytesU32(raw, off); err != nil {
		return nil, err
	}
	if off+2 > len(raw) {
		return nil, io.ErrUnexpectedEOF
	}
	wcount := int(binary.BigEndian.Uint16(raw[off:])) //nolint:gosec // G115: protocol-bounded uint16
	off += 2
	for range wcount {
		if off+32 > len(raw) {
			return nil, io.ErrUnexpectedEOF
		}
		w := Window{
			Serial:     binary.BigEndian.Uint32(raw[off:]),
			NotBefore:  binary.BigEndian.Uint32(raw[off+4:]),
			NotAfter:   binary.BigEndian.Uint32(raw[off+8:]),
			ResolverSK: raw[off+12 : off+44],
			ResolverPK: raw[off+44 : off+76],
		}
		off += 76
		dc.Windows = append(dc.Windows, w)
	}
	f.DNSCrypt = dc
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

// ── zstd ───────────────────────────────────────────────────────────────

// zstdCompress compresses raw with the fastest level — the persist file is
// written at shutdown and on DNSCrypt rotation only, so latency is irrelevant.
func zstdCompress(raw []byte) ([]byte, error) {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstdLevel))
	if err != nil {
		return nil, err
	}
	defer func() { _ = enc.Close() }()
	return enc.EncodeAll(raw, nil), nil
}

// zstdDecompress decompresses raw.
func zstdDecompress(raw []byte) ([]byte, error) {
	dec, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	return dec.DecodeAll(raw, nil)
}

// ── Atomic write ───────────────────────────────────────────────────────

// atomicWrite writes data to path via a temp file in the same directory and
// an atomic rename, so a crash mid-write never leaves a truncated persist
// file. The directory must exist.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".zjdns-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}
