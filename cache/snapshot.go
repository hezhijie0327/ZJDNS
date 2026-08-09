package cache

import (
	"encoding/binary"
	"io"
	"zjdns/internal/snapfile"
)

// Snapshot entry format: [2B key_len][key][8B ts][4B ttl][1B validated][4B wire_len][wire]
const snapshotVersion = 1

// SaveSnapshot writes all cache entries to path atomically via snapfile.
func (c *Cache) SaveSnapshot(path string) error {
	return snapfile.Save(path, snapshotVersion, func(w io.Writer) error {
		var keyLenBuf [2]byte
		var tsBuf [8]byte
		var numBuf [4]byte
		var writeErr error
		c.entries.Range(func(key string, e *cacheEntry) bool {
			binary.BigEndian.PutUint16(keyLenBuf[:], uint16(len(key))) //nolint:gosec // G115: DNS qnames are bounded
			if _, err := w.Write(keyLenBuf[:]); err != nil {
				writeErr = err
				return false
			}
			if _, err := io.WriteString(w, key); err != nil {
				writeErr = err
				return false
			}
			binary.BigEndian.PutUint64(tsBuf[:], uint64(e.ts)) //nolint:gosec // G115: unix seconds fit uint64
			if _, err := w.Write(tsBuf[:]); err != nil {
				writeErr = err
				return false
			}
			binary.BigEndian.PutUint32(numBuf[:], uint32(e.ttl)) //nolint:gosec // G115: TTL bounded by config cap
			if _, err := w.Write(numBuf[:]); err != nil {
				writeErr = err
				return false
			}
			validated := byte(0)
			if e.validated {
				validated = 1
			}
			if _, err := w.Write([]byte{validated}); err != nil {
				writeErr = err
				return false
			}
			binary.BigEndian.PutUint32(numBuf[:], uint32(len(e.msgWire))) //nolint:gosec // G115: DNS wire bounded
			if _, err := w.Write(numBuf[:]); err != nil {
				writeErr = err
				return false
			}
			if _, err := w.Write(e.msgWire); err != nil {
				writeErr = err
			}
			return writeErr == nil
		})
		return writeErr
	})
}

// LoadSnapshot loads entries from a snapshot file.  A missing, foreign or
// truncated snapshot is silently ignored — the cache starts cold.
func (c *Cache) LoadSnapshot(path string) error {
	return snapfile.Load(path, snapshotVersion, func(r io.Reader) error {
		var keyLenBuf [2]byte
		if _, err := io.ReadFull(r, keyLenBuf[:]); err != nil {
			return err
		}
		key := make([]byte, int(binary.BigEndian.Uint16(keyLenBuf[:])))
		if _, err := io.ReadFull(r, key); err != nil {
			return err
		}
		var entryBuf [17]byte // ts(8) + ttl(4) + validated(1) + wire_len(4)
		if _, err := io.ReadFull(r, entryBuf[:]); err != nil {
			return err
		}
		ts := int64(binary.BigEndian.Uint64(entryBuf[0:8])) //nolint:gosec // G115: snapshot ts is a unix second
		ttl := int(binary.BigEndian.Uint32(entryBuf[8:12]))
		validated := entryBuf[12] != 0
		wire := make([]byte, int(binary.BigEndian.Uint32(entryBuf[13:17])))
		if _, err := io.ReadFull(r, wire); err != nil {
			return err
		}
		c.entries.Set(string(key), &cacheEntry{msgWire: wire, ts: ts, ttl: ttl, validated: validated})
		return nil
	})
}
