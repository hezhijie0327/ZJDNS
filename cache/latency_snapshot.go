package cache

import (
	"encoding/binary"
	"io"
	"zjdns/internal/log"
	"zjdns/internal/snapfile"
)

// Latency snapshot entry format: [2B key_len][key][4B latency][8B last_probe]
const latencySnapshotVersion = 1

// SaveLatencySnapshot writes the per-IP latency table to path atomically.
// Entries are collected under the LRU lock and serialized outside it (H5).
func (c *Cache) SaveLatencySnapshot(path string) error {
	items := make(map[string]latEntry, c.latencies.Len())
	c.latencies.Range(func(key string, e latEntry) bool {
		items[key] = e
		return true
	})
	return snapfile.Save(path, latencySnapshotVersion, func(w io.Writer) error {
		var keyLenBuf [2]byte
		var numBuf [4]byte
		var tsBuf [8]byte
		for key, e := range items {
			binary.BigEndian.PutUint16(keyLenBuf[:], uint16(len(key))) //nolint:gosec // G115: IP strings are bounded
			if _, err := w.Write(keyLenBuf[:]); err != nil {
				return err
			}
			if _, err := io.WriteString(w, key); err != nil {
				return err
			}
			binary.BigEndian.PutUint32(numBuf[:], uint32(e.latency)) //nolint:gosec // G115: latency bounded by probe config
			if _, err := w.Write(numBuf[:]); err != nil {
				return err
			}
			binary.BigEndian.PutUint64(tsBuf[:], uint64(e.lastProbe)) //nolint:gosec // G115: unix seconds fit uint64
			if _, err := w.Write(tsBuf[:]); err != nil {
				return err
			}
		}
		return nil
	})
}

// LoadLatencySnapshot loads the latency table from a snapshot file.
func (c *Cache) LoadLatencySnapshot(path string) error {
	return snapfile.Load(path, latencySnapshotVersion, func(r io.Reader) error {
		var keyLenBuf [2]byte
		if _, err := io.ReadFull(r, keyLenBuf[:]); err != nil {
			return err
		}
		key := make([]byte, int(binary.BigEndian.Uint16(keyLenBuf[:])))
		if _, err := io.ReadFull(r, key); err != nil {
			return err
		}
		var entryBuf [12]byte // latency(4) + last_probe(8)
		if _, err := io.ReadFull(r, entryBuf[:]); err != nil {
			return err
		}
		latency := int(binary.BigEndian.Uint32(entryBuf[0:4]))
		lastProbe := int64(binary.BigEndian.Uint64(entryBuf[4:12])) //nolint:gosec // G115: snapshot ts is a unix second
		c.latencies.Set(string(key), latEntry{latency: latency, lastProbe: lastProbe})
		if c.latencies.Len() > 0 {
			c.hasLatencyData.Store(true)
		}
		return nil
	})
}

// CleanupLatency physically removes entries past the stale window — the lazy
// read-time expiry only filters, it never frees the memory.  Called
// periodically by the server.
func (c *Cache) CleanupLatency() {
	cutoff := log.NowUnix() - defaultStaleMaxAge
	var stale []string
	c.latencies.Range(func(key string, e latEntry) bool {
		if e.lastProbe > 0 && e.lastProbe < cutoff {
			stale = append(stale, key)
		}
		return true
	})
	for _, key := range stale {
		c.latencies.Delete(key)
	}
}
