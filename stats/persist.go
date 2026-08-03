package stats

import (
	"encoding/binary"
	"errors"
	"io"
	"sync/atomic"
	"zjdns/internal/lrumap"
)

// Stats persistence: a single-entry lrumap (key "counters") holding the
// snapshot of all counters, written on the persist interval and at shutdown,
// restored at startup with an additive merge — a restart continues the totals
// instead of resetting them. Backups, version gating, and the zstd + atomic
// write substrate all come from the shared lrumap persistence mechanism.
// statsCodec implements lrumap.Codec for the counter snapshot.
type statsCodec struct{}

const (
	// statsPersistVersion gates the format; v1 was the fixed-layout snapshot,
	// v2 is the lrumap-framed entry — older files are backed up and rebuilt.
	statsPersistVersion = 2

	// countersKey is the single map key holding the counter snapshot.
	countersKey = "counters"

	// statsFixedCounters is the number of flat counters snapshot() writes
	// before the latency buckets and totalMS — keep in sync with
	// snapshot()'s field order.
	statsFixedCounters = 27
)

func (statsCodec) Version() uint16 { return statsPersistVersion }

func (statsCodec) EncodeKey(k string) []byte { return []byte(k) }

func (statsCodec) DecodeKey(b []byte) (string, error) { return string(b), nil }

// EncodeValue serializes the snapshot as one BigEndian int64 per counter
// field, in Collector field order.
func (statsCodec) EncodeValue(v []int64) []byte {
	buf := make([]byte, 8*len(v))
	for i, n := range v {
		binary.BigEndian.PutUint64(buf[8*i:], uint64(n)) //nolint:gosec // G115: counter snapshot — protocol-bounded int64
	}
	return buf
}

// DecodeValue parses the layout produced by EncodeValue. The field count is
// fixed by the collector layout; a mismatched length is rejected.
func (statsCodec) DecodeValue(b []byte) (snap []int64, include bool, err error) {
	if len(b)%8 != 0 || len(b) == 0 {
		return nil, false, errors.New("stats: snapshot length is not a multiple of 8")
	}
	out := make([]int64, len(b)/8)
	for i := range out {
		out[i] = int64(binary.BigEndian.Uint64(b[8*i:])) //nolint:gosec // G115: counter snapshot — protocol-bounded int64
	}
	return out, true, nil
}

// SetPersist attaches lrumap-backed persistence and eagerly restores any
// existing snapshot (additive merge into the current counters), returning the
// number of counter groups restored (1 when a file existed). A missing file
// is a cold start (0, nil); corrupt/unsupported files are errors — the caller
// logs and continues with empty stats.
func (c *Collector) SetPersist(path string) (int, error) {
	if path == "" {
		return 0, nil
	}
	m := lrumap.New[string, []int64](1)
	// Attach the store BEFORE loading: a version-mismatch or corrupt file
	// must not leave the collector without persistence — SavePersist keeps
	// working and writes the fresh format over the backed-up old file.
	c.persist = m
	n, err := m.EnablePersist(lrumap.PersistConfig[string, []int64]{
		Path:  path,
		Codec: statsCodec{},
	})
	if err != nil {
		return 0, err
	}
	if n > 0 {
		if snap, ok := m.Get(countersKey); ok {
			if err := c.merge(snap); err != nil {
				return 0, err
			}
		}
	}
	return n, nil
}

// SavePersist snapshots all counters to the persist file (zstd + atomic write
// via the lrumap persistence). A no-op when SetPersist was never called.
func (c *Collector) SavePersist() error {
	if c.persist == nil {
		return nil
	}
	c.persist.Set(countersKey, c.snapshot())
	return c.persist.Save()
}

// snapshot copies all counter fields into a flat slice in a fixed order —
// the on-disk layout must stay stable across versions.
func (c *Collector) snapshot() []int64 {
	s := []int64{
		c.startTime.Load(),
		c.total.Load(),
		c.totalMS.Load(),
		c.hit.Load(),
		c.miss.Load(),
		c.stale.Load(),
		c.zone.Load(),
		c.blocked.Load(),
		c.badcookie.Load(),
		c.errorCount.Load(),
		c.udp.Load(),
		c.tcp.Load(),
		c.tls.Load(),
		c.quic.Load(),
		c.https.Load(),
		c.http3.Load(),
		c.dtls.Load(),
		c.dnscrypt.Load(),
		c.dnscryptTCP.Load(),
		c.tlcp.Load(),
		c.httpTLCP.Load(),
		c.dtlcp.Load(),
		c.secure.Load(),
		c.insecure.Load(),
		c.bogus.Load(),
		c.poisoned.Load(),
		c.prefetch.Load(),
	}
	for i := range c.rCode {
		s = append(s, c.rCode[i].Load())
	}
	for i := range c.latCounts {
		s = append(s, c.latCounts[i].Load())
	}
	return append(s, c.latTotal.Load())
}

// merge adds a restored snapshot into the current counters (the collector is
// fresh at startup, so this is effectively a restore).
func (c *Collector) merge(snap []int64) error {
	if len(snap) < statsFixedCounters+24+latBuckets+1 {
		return io.ErrUnexpectedEOF
	}
	off := 0
	read := func() int64 {
		v := snap[off]
		off++
		return v
	}
	load := func(dst *atomic.Int64) {
		dst.Add(read())
	}

	if v := read(); v != 0 {
		// Keep the earlier start time so the uptime span stays continuous.
		if c.startTime.Load() == 0 || v < c.startTime.Load() {
			c.startTime.Store(v)
		}
	}
	for _, dst := range []*atomic.Int64{
		&c.total, &c.totalMS, &c.hit, &c.miss, &c.stale, &c.zone, &c.blocked,
		&c.badcookie, &c.errorCount, &c.udp, &c.tcp, &c.tls, &c.quic, &c.https,
		&c.http3, &c.dtls, &c.dnscrypt, &c.dnscryptTCP, &c.tlcp, &c.httpTLCP,
		&c.dtlcp, &c.secure, &c.insecure, &c.bogus, &c.poisoned, &c.prefetch,
	} {
		load(dst)
	}
	for i := range c.rCode {
		load(&c.rCode[i])
	}
	for i := range c.latCounts {
		load(&c.latCounts[i])
	}
	load(&c.latTotal)
	return nil
}
