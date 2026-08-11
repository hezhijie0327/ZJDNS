package cache

import (
	"encoding/binary"
	"sort"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/spillfile"
)

// latencyWireLen is the spill-record wire size for a latEntry:
// [4B latency][8B last_probe].
const latencyWireLen = 12

// marshalLatency serialises a latEntry into the spill record wire format.
func marshalLatency(e latEntry) []byte {
	buf := make([]byte, latencyWireLen)
	binary.BigEndian.PutUint32(buf[0:4], uint32(e.latency))    //nolint:gosec // G115: latency bounded by probe config
	binary.BigEndian.PutUint64(buf[4:12], uint64(e.lastProbe)) //nolint:gosec // G115: unix seconds fit uint64
	return buf
}

// unmarshalLatency parses a latEntry from a spill record wire.  ok is false
// for corrupt or foreign-length wires (treated as a miss).
func unmarshalLatency(wire []byte) (latEntry, bool) {
	if len(wire) != latencyWireLen {
		return latEntry{}, false
	}
	return latEntry{
		latency:   int(binary.BigEndian.Uint32(wire[0:4])),
		lastProbe: int64(binary.BigEndian.Uint64(wire[4:12])), //nolint:gosec // G115: unix seconds fit int64
	}, true
}

// loadLatencySpill opens the latency spill store and warms memory with its
// freshest entries.  On failure (foreign/corrupt file) the disk tier is
// disabled — the latency table still works, just in memory.
func (s *Cache) loadLatencySpill(path string, diskCap, latencyMax int) {
	if path == "" {
		return
	}
	spill, err := spillfile.Open(path)
	if err != nil {
		log.Warnf("CACHE: latency spill store open failed (disk tier disabled): %v", err)
		return
	}
	s.spillLat = spill
	s.spillLatCap = diskCap

	entries := spill.Entries()
	sort.Slice(entries, func(i, j int) bool { return entries[i].Ts < entries[j].Ts })
	n := 0
	now := log.NowUnix()
	for _, e := range entries {
		if n >= latencyMax {
			break
		}
		// Spill ts == lastProbe — past the stale window the entry is dead.
		if e.Ts > 0 && e.Ts < now-config.DefaultStaleMaxAge {
			spill.Delete(e.Key)
			continue
		}
		_, _, _, wire, ok := spill.Get(e.Key)
		if !ok {
			continue
		}
		lat, ok := unmarshalLatency(wire)
		if !ok {
			spill.Delete(e.Key)
			continue
		}
		// Coldest first so the freshest entry ends up at the LRU front.
		s.latencies.Set(e.Key, lat)
		s.hasLatencyData.Store(true)
		n++
	}
	s.latencies.SetOnEvict(func(key string, e latEntry) {
		if e.lastProbe > 0 {
			_ = s.spillLat.Put(key, e.lastProbe, 0, false, marshalLatency(e))
		}
	})
	log.Infof("CACHE: latency spill store ready: %d records on disk, %d loaded to memory", spill.EntryCount(), n)
}

// getLatencyFromSpill reads a latency record by key and promotes it to
// memory.  A record past the stale window is dropped from the index.
func (s *Cache) getLatencyFromSpill(ip string) (latEntry, bool) {
	ts, _, _, wire, ok := s.spillLat.Get(ip)
	if !ok {
		return latEntry{}, false
	}
	if ts > 0 && ts < log.NowUnix()-config.DefaultStaleMaxAge {
		s.spillLat.Delete(ip)
		return latEntry{}, false
	}
	lat, ok := unmarshalLatency(wire)
	if !ok {
		s.spillLat.Delete(ip)
		return latEntry{}, false
	}
	s.latencies.Set(ip, lat)
	s.hasLatencyData.Store(true)
	return lat, true
}

// CleanupLatency physically removes entries past the stale window — the lazy
// read-time expiry only filters, it never frees the memory.  Called
// periodically by the server.
func (s *Cache) CleanupLatency() {
	cutoff := log.NowUnix() - defaultStaleMaxAge
	var stale []string
	s.latencies.Range(func(key string, e latEntry) bool {
		if e.lastProbe > 0 && e.lastProbe < cutoff {
			stale = append(stale, key)
		}
		return true
	})
	for _, key := range stale {
		s.latencies.Delete(key)
	}
}
