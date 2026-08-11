// Package spillfile provides an append-only, disk-backed key-value store
// used as the second tier of the DNS cache.  Records are tail-appended to a
// log file; a lazily maintained in-memory index maps keys to record offsets.
// The file is rewritten atomically (temp + rename) by Compact when expired
// or superseded records accumulate.
//
// Record layout (all big-endian):
//
//	[2B key_len][key][8B ts][4B ttl][1B flags][4B wire_len][wire]
//
// flags bit 0 = validated.  The key is stored verbatim — the store is
// opaque to the wire bytes, so entries, latency and delegation stores can
// share it.  A superseded key (Put twice) keeps one index entry; the
// duplicate record stays on disk until the next Compact.
package spillfile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
)

// indexEntry locates one record in the file.
type indexEntry struct {
	ts        int64
	ttl       int
	validated bool
	wireOff   int64
	wireLen   int32
}

// Entry is a snapshot of one indexed record, used by callers for startup
// ordering and compaction decisions.
type Entry struct {
	Key       string
	Ts        int64
	Ttl       int
	Validated bool
	WireOff   int64
	WireLen   int32
}

// Store is a single-file append-only key-value store.
type Store struct {
	f    *os.File
	path string

	mu    sync.Mutex // guards index and tail
	index map[string]indexEntry
	tail  int64 // next append offset (== physical EOF)
}

// Magic distinguishes a spill file from any other state file.  Deliberately
// distinct from the retired snapfile magic ("ZJNS") — an old snapshot must
// never be parsed as a record stream.
const Magic = "ZJSP"

// Version is the file layout version.
const Version = 1

// Corruption guards — record lengths come from the file, so a corrupt or
// tampered spill file must not drive an unbounded allocation (M3).
const (
	maxKeyLen  = 1 << 16 // 64 KiB — uint16 key length field bound
	maxWireLen = 1 << 24 // 16 MiB — DNS responses are far smaller

	headerLen       = len(Magic) + 1    // magic + version
	recordHeaderLen = 2 + 8 + 4 + 1 + 4 // key_len + ts + ttl + flags + wire_len
)

// Open opens the spill file at path and rebuilds the in-memory index by
// scanning it.  A missing file is created empty (cold start).  A foreign
// header or corrupt record returns an error — callers should treat the
// store as unusable rather than overwrite a possibly-salvageable file.
// A truncated trailing record is dropped (the file is cut back to the last
// complete record) since appends are atomic per record.
func Open(path string) (*Store, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644) //nolint:gosec // G304: path from trusted config
	if err != nil {
		return nil, err
	}
	st := &Store{f: f, path: path, index: make(map[string]indexEntry)}
	if err := st.scan(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return st, nil
}

// Create truncates path and returns an empty store (used by tests and Clear).
func Create(path string) (*Store, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o644) //nolint:gosec // G304: path from trusted config
	if err != nil {
		return nil, err
	}
	st := &Store{f: f, path: path, index: make(map[string]indexEntry)}
	if err := st.writeHeader(); err != nil {
		_ = f.Close()
		return nil, err
	}
	st.tail = int64(headerLen)
	return st, nil
}

// writeHeader writes the magic + version header at offset 0.
func (s *Store) writeHeader() error {
	header := make([]byte, headerLen)
	copy(header, Magic)
	header[len(Magic)] = Version
	_, err := s.f.WriteAt(header, 0)
	return err
}

// scan rebuilds the index from the file, dropping a truncated trailing
// record and any record that follows a corrupt one (append-order trust).
func (s *Store) scan() error {
	var header [headerLen]byte
	n, err := io.ReadFull(s.f, header[:])
	if err == io.EOF {
		// Fresh empty file — initialise the header.
		if err := s.writeHeader(); err != nil {
			return err
		}
		s.tail = int64(headerLen)
		return nil
	}
	if err != nil || n != headerLen {
		return fmt.Errorf("spillfile: corrupt header (%d bytes)", n)
	}
	if string(header[:len(Magic)]) != Magic || header[len(Magic)] != Version {
		return errors.New("spillfile: foreign or corrupt header")
	}

	s.tail = int64(headerLen)
	var (
		keyLenBuf  [2]byte
		tsBuf      [8]byte
		ttlBuf     [4]byte
		flagBuf    [1]byte
		wireLenBuf [4]byte
	)
	for {
		off := s.tail
		if _, err := io.ReadFull(s.f, keyLenBuf[:]); err != nil {
			return s.truncateAt(off) // clean EOF or partial record — both drop the tail
		}
		keyLen := int(binary.BigEndian.Uint16(keyLenBuf[:]))
		if keyLen == 0 || keyLen > maxKeyLen {
			return s.truncateAt(off)
		}
		key := make([]byte, keyLen)
		if _, err := io.ReadFull(s.f, key); err != nil {
			return s.truncateAt(off)
		}
		if _, err := io.ReadFull(s.f, tsBuf[:]); err != nil {
			return s.truncateAt(off)
		}
		if _, err := io.ReadFull(s.f, ttlBuf[:]); err != nil {
			return s.truncateAt(off)
		}
		if _, err := io.ReadFull(s.f, flagBuf[:]); err != nil {
			return s.truncateAt(off)
		}
		if _, err := io.ReadFull(s.f, wireLenBuf[:]); err != nil {
			return s.truncateAt(off)
		}
		wireLen := int(binary.BigEndian.Uint32(wireLenBuf[:]))
		if wireLen > maxWireLen {
			return s.truncateAt(off)
		}
		// Wire bytes are not needed to rebuild the index — skip without
		// allocating (large spill files would transiently double memory).
		if _, err := io.CopyN(io.Discard, s.f, int64(wireLen)); err != nil {
			return s.truncateAt(off)
		}

		keyStr := string(key)
		ts := int64(binary.BigEndian.Uint64(tsBuf[:])) //nolint:gosec // G115: unix seconds fit int64
		ttl := int(binary.BigEndian.Uint32(ttlBuf[:]))
		validated := flagBuf[0]&1 != 0
		wireOff := off + int64(recordHeaderLen+keyLen)
		if old, dup := s.index[keyStr]; !dup || ts > old.ts || (ts == old.ts && wireOff > old.wireOff) {
			s.index[keyStr] = indexEntry{ts: ts, ttl: ttl, validated: validated, wireOff: wireOff, wireLen: int32(wireLen)}
		}
		s.tail = wireOff + int64(wireLen)
	}
}

// truncateAt cuts the file back to off, dropping a trailing partial or
// corrupt record, and returns nil (scan continues from the good prefix).
func (s *Store) truncateAt(off int64) error {
	if err := s.f.Truncate(off); err != nil {
		return err
	}
	s.tail = off
	return nil
}

// recordBytes serialises one record (see package doc for the layout).
func recordBytes(key string, ts int64, ttl int, validated bool, wire []byte) []byte {
	rec := make([]byte, 0, recordHeaderLen+len(key)+len(wire))
	var buf [8]byte
	binary.BigEndian.PutUint16(buf[:2], uint16(len(key))) //nolint:gosec // G115: key length bounded by maxKeyLen
	rec = append(rec, buf[:2]...)
	rec = append(rec, key...)
	binary.BigEndian.PutUint64(buf[:], uint64(ts)) //nolint:gosec // G115: unix seconds fit uint64
	rec = append(rec, buf[:8]...)
	binary.BigEndian.PutUint32(buf[:4], uint32(ttl)) //nolint:gosec // G115: TTL bounded by config cap
	rec = append(rec, buf[:4]...)
	flags := byte(0)
	if validated {
		flags = 1
	}
	rec = append(rec, flags)
	binary.BigEndian.PutUint32(buf[:4], uint32(len(wire))) //nolint:gosec // G115: wire length bounded by maxWireLen
	rec = append(rec, buf[:4]...)
	rec = append(rec, wire...)
	return rec
}

// Put appends one record to the log and updates the index.  The write is
// synchronous to the page cache (no per-write fsync — call Flush for
// durability).  A later Put of the same key supersedes the index entry.
func (s *Store) Put(key string, ts int64, ttl int, validated bool, wire []byte) error {
	if key == "" || len(key) > maxKeyLen || len(wire) > maxWireLen {
		return fmt.Errorf("spillfile: record out of bounds: key=%d wire=%d", len(key), len(wire))
	}
	rec := recordBytes(key, ts, ttl, validated, wire)

	s.mu.Lock()
	defer s.mu.Unlock()
	off := s.tail
	if _, err := s.f.WriteAt(rec, off); err != nil {
		return err
	}
	s.tail += int64(len(rec))
	s.index[key] = indexEntry{
		ts: ts, ttl: ttl, validated: validated,
		wireOff: off + int64(recordHeaderLen+len(key)), wireLen: int32(len(wire)), //nolint:gosec // G115: wire length bounded by maxWireLen
	}
	return nil
}

// Get returns the record for key.  ok is false when the key is absent or
// the record can no longer be read (corrupted — treated as a miss).
func (s *Store) Get(key string) (ts int64, ttl int, validated bool, wire []byte, ok bool) {
	s.mu.Lock()
	e, found := s.index[key]
	s.mu.Unlock()
	if !found {
		return 0, 0, false, nil, false
	}
	wire = make([]byte, e.wireLen)
	if _, err := s.f.ReadAt(wire, e.wireOff); err != nil {
		return 0, 0, false, nil, false
	}
	return e.ts, e.ttl, e.validated, wire, true
}

// Delete removes key from the index.  The record stays in the file until
// the next Compact.
func (s *Store) Delete(key string) {
	s.mu.Lock()
	delete(s.index, key)
	s.mu.Unlock()
}

// Indexed reports whether the index holds a record for key with exactly the
// given timestamp — used by callers to avoid re-appending unchanged entries
// during a full-memory flush.
func (s *Store) Indexed(key string, ts int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.index[key]
	return ok && e.ts == ts
}

// Entries returns a snapshot of all indexed records (unordered).
func (s *Store) Entries() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Entry, 0, len(s.index))
	for k, e := range s.index {
		out = append(out, Entry{
			Key: k, Ts: e.ts, Ttl: e.ttl, Validated: e.validated,
			WireOff: e.wireOff, WireLen: e.wireLen,
		})
	}
	return out
}

// Compact rewrites the file keeping exactly the records for which keep
// returns true, atomically (temp + rename).  Keep is called with the map
// mutex held; it must not call back into the store.  Records are visited in
// ts-ascending (oldest-first) order for deterministic cap decisions.
func (s *Store) Compact(keep func(key string, ts int64, ttl int) bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tmp := s.path + ".tmp"
	tf, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o644) //nolint:gosec // G304: path from trusted config
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }() // no-op after a successful rename

	header := make([]byte, headerLen)
	copy(header, Magic)
	header[len(Magic)] = Version
	if _, err := tf.Write(header); err != nil {
		_ = tf.Close()
		return err
	}

	// Oldest-first traversal makes disk-cap drops deterministic.
	keys := make([]string, 0, len(s.index))
	for k := range s.index {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := s.index[keys[i]], s.index[keys[j]]
		if a.ts != b.ts {
			return a.ts < b.ts
		}
		return keys[i] < keys[j]
	})

	newIndex := make(map[string]indexEntry, len(s.index))
	tail := int64(headerLen)
	for _, k := range keys {
		e := s.index[k]
		if !keep(k, e.ts, e.ttl) {
			continue
		}
		wire := make([]byte, e.wireLen)
		if _, err := s.f.ReadAt(wire, e.wireOff); err != nil {
			continue // unreadable record — drop it
		}
		rec := recordBytes(k, e.ts, e.ttl, e.validated, wire)
		if _, err := tf.Write(rec); err != nil {
			_ = tf.Close()
			return err
		}
		newIndex[k] = indexEntry{
			ts: e.ts, ttl: e.ttl, validated: e.validated,
			wireOff: tail + int64(recordHeaderLen+len(k)), wireLen: e.wireLen,
		}
		tail += int64(len(rec))
	}
	if err := tf.Sync(); err != nil {
		_ = tf.Close()
		return err
	}
	if err := tf.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}

	nf, err := os.OpenFile(s.path, os.O_RDWR, 0o644) //nolint:gosec // G304: path from trusted config
	if err != nil {
		return err
	}
	_ = s.f.Close()
	s.f = nf
	s.index = newIndex
	s.tail = tail
	return nil
}

// Clear removes all records (index + file truncated back to the header).
func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writeHeader(); err != nil {
		return err
	}
	if err := s.f.Truncate(int64(headerLen)); err != nil {
		return err
	}
	s.tail = int64(headerLen)
	s.index = make(map[string]indexEntry)
	return nil
}

// Flush fsyncs the file — called periodically and on shutdown for
// durability (Put only reaches the page cache).
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Sync()
}

// Close flushes and closes the store.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.f.Sync()
	if cerr := s.f.Close(); err == nil {
		err = cerr
	}
	return err
}

// FileSize returns the current file size in bytes (including the header).
func (s *Store) FileSize() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tail
}

// EntryCount returns the number of indexed records.
func (s *Store) EntryCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.index)
}
