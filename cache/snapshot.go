package cache

import (
	"encoding/binary"
	"fmt"
	"io"
	"zjdns/internal/snapfile"

	"codeberg.org/miekg/dns"
)

// snapshotItem is one cache entry pinned for serialization — msgWire is
// immutable once stored, so a plain reference is safe outside the lock.
type snapshotItem struct {
	key       string
	ts        int64
	ttl       int
	validated bool
	wire      []byte
}

// Snapshot entry format: [2B key_len][key][8B ts][4B ttl][1B validated][4B wire_len][wire]
const snapshotVersion = 1

// Snapshot load guards: counts come from the file, so a corrupt or tampered
// snapshot must not drive an unbounded allocation (M3).
const (
	maxSnapshotKeyLen  = 1024 // buildCacheKey output: qname (<=255) + type/class/ECS/prefix/dnssec
	maxSnapshotWireLen = dns.MaxMsgSize
)

// SaveSnapshot writes all cache entries to path atomically via snapfile.
// Entries are collected under the LRU lock and serialized OUTSIDE it —
// holding the lock across per-entry disk writes would stall every cache
// Get/Set for the full save duration (H5).
func (c *Cache) SaveSnapshot(path string) error {
	items := make([]snapshotItem, 0, c.entries.Len())
	c.entries.Range(func(key string, e *cacheEntry) bool {
		items = append(items, snapshotItem{key: key, ts: e.ts, ttl: e.ttl, validated: e.validated, wire: e.msgWire})
		return true
	})
	return snapfile.Save(path, snapshotVersion, func(w io.Writer) error {
		var keyLenBuf [2]byte
		var tsBuf [8]byte
		var numBuf [4]byte
		for _, e := range items {
			binary.BigEndian.PutUint16(keyLenBuf[:], uint16(len(e.key))) //nolint:gosec // G115: DNS qnames are bounded
			if _, err := w.Write(keyLenBuf[:]); err != nil {
				return err
			}
			if _, err := io.WriteString(w, e.key); err != nil {
				return err
			}
			binary.BigEndian.PutUint64(tsBuf[:], uint64(e.ts)) //nolint:gosec // G115: unix seconds fit uint64
			if _, err := w.Write(tsBuf[:]); err != nil {
				return err
			}
			binary.BigEndian.PutUint32(numBuf[:], uint32(e.ttl)) //nolint:gosec // G115: TTL bounded by config cap
			if _, err := w.Write(numBuf[:]); err != nil {
				return err
			}
			validated := byte(0)
			if e.validated {
				validated = 1
			}
			if _, err := w.Write([]byte{validated}); err != nil {
				return err
			}
			binary.BigEndian.PutUint32(numBuf[:], uint32(len(e.wire))) //nolint:gosec // G115: DNS wire bounded
			if _, err := w.Write(numBuf[:]); err != nil {
				return err
			}
			if _, err := w.Write(e.wire); err != nil {
				return err
			}
		}
		return nil
	})
}

// LoadSnapshot loads entries from a snapshot file.  A missing or foreign
// file starts the cache cold (nil error); a corrupt or truncated file
// aborts with an error — entries read before the corruption remain loaded,
// and the caller logs accordingly (M3).
func (c *Cache) LoadSnapshot(path string) error {
	return snapfile.Load(path, snapshotVersion, func(r io.Reader) error {
		var keyLenBuf [2]byte
		if _, err := io.ReadFull(r, keyLenBuf[:]); err != nil {
			return err
		}
		keyLen := int(binary.BigEndian.Uint16(keyLenBuf[:]))
		if keyLen > maxSnapshotKeyLen {
			return fmt.Errorf("snapshot: corrupt key length %d", keyLen)
		}
		key := make([]byte, keyLen)
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
		wireLen := int(binary.BigEndian.Uint32(entryBuf[13:17]))
		if wireLen > maxSnapshotWireLen {
			return fmt.Errorf("snapshot: corrupt wire length %d", wireLen)
		}
		wire := make([]byte, wireLen)
		if _, err := io.ReadFull(r, wire); err != nil {
			return err
		}
		c.entries.Set(string(key), &cacheEntry{msgWire: wire, ts: ts, ttl: ttl, validated: validated})
		return nil
	})
}
