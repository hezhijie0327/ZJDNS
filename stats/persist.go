package stats

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"
	"zjdns/internal/persist"
)

// Stats persist file: version-gated binary snapshot of all counters, written
// at shutdown and restored at startup (additive merge — a restart continues
// the totals instead of resetting them).
//
//	[2B version=1]
//	then one int64 (BigEndian) per counter field, in Collector field order.
const persistVersion = 1

// SavePersist snapshots all counters to path (zstd + atomic write via
// internal/persist). A missing/empty path is a no-op.
func (c *Collector) SavePersist(path string) error {
	if c == nil || path == "" {
		return nil
	}
	var buf bytes.Buffer
	buf.Grow(2 + 40*8)
	var ver [2]byte
	binary.BigEndian.PutUint16(ver[:], persistVersion)
	buf.Write(ver[:])
	writeI64(&buf, c.startTime.Load())
	writeI64(&buf, c.total.Load())
	writeI64(&buf, c.totalMS.Load())
	writeI64(&buf, c.hit.Load())
	writeI64(&buf, c.miss.Load())
	writeI64(&buf, c.stale.Load())
	writeI64(&buf, c.zone.Load())
	writeI64(&buf, c.blocked.Load())
	writeI64(&buf, c.badcookie.Load())
	writeI64(&buf, c.errorCount.Load())
	writeI64(&buf, c.udp.Load())
	writeI64(&buf, c.tcp.Load())
	writeI64(&buf, c.tls.Load())
	writeI64(&buf, c.quic.Load())
	writeI64(&buf, c.https.Load())
	writeI64(&buf, c.http3.Load())
	writeI64(&buf, c.dtls.Load())
	writeI64(&buf, c.dnscrypt.Load())
	writeI64(&buf, c.dnscryptTCP.Load())
	writeI64(&buf, c.tlcp.Load())
	writeI64(&buf, c.httpTLCP.Load())
	writeI64(&buf, c.dtlcp.Load())
	writeI64(&buf, c.secure.Load())
	writeI64(&buf, c.insecure.Load())
	writeI64(&buf, c.bogus.Load())
	writeI64(&buf, c.poisoned.Load())
	writeI64(&buf, c.prefetch.Load())
	for i := range c.rCode {
		writeI64(&buf, c.rCode[i].Load())
	}
	for i := range c.latCounts {
		writeI64(&buf, c.latCounts[i].Load())
	}
	writeI64(&buf, c.latTotal.Load())
	return persist.Save(path, buf.Bytes())
}

// LoadPersist restores counters from path, merging into the current values
// (the collector is fresh at startup, so this is effectively a restore).
// A missing file or empty path is a no-op; corrupt/unsupported files are
// surfaced as errors — the caller logs and continues with empty stats.
func (c *Collector) LoadPersist(path string) error {
	if c == nil || path == "" {
		return nil
	}
	raw, err := persist.Load(path)
	if err != nil {
		return err
	}
	if raw == nil {
		return nil //nolint:nilerr // cold start
	}
	if len(raw) < 2 {
		return io.ErrUnexpectedEOF
	}
	if version := binary.BigEndian.Uint16(raw[:2]); version != persistVersion {
		return fmt.Errorf("stats: unsupported persist version %d", version)
	}
	off := 2
	readI64 := func() (int64, error) {
		if off+8 > len(raw) {
			return 0, io.ErrUnexpectedEOF
		}
		v := int64(binary.BigEndian.Uint64(raw[off:])) //nolint:gosec // G115: counter snapshot — protocol-bounded int64
		off += 8
		return v, nil
	}

	// Restore — additive merge keeps any counters recorded before the load.
	load := func(dst *atomic.Int64) error {
		v, err := readI64()
		if err != nil {
			return err
		}
		dst.Add(v)
		return nil
	}

	if v, err := readI64(); err != nil {
		return err
	} else if v != 0 {
		// Keep the earlier start time so the uptime span stays continuous.
		if c.startTime.Load() == 0 || v < c.startTime.Load() {
			c.startTime.Store(v)
		}
	}
	rest := []*atomic.Int64{
		&c.total, &c.totalMS, &c.hit, &c.miss, &c.stale, &c.zone, &c.blocked,
		&c.badcookie, &c.errorCount, &c.udp, &c.tcp, &c.tls, &c.quic, &c.https,
		&c.http3, &c.dtls, &c.dnscrypt, &c.dnscryptTCP, &c.tlcp, &c.httpTLCP,
		&c.dtlcp, &c.secure, &c.insecure, &c.bogus, &c.poisoned, &c.prefetch,
	}
	for _, dst := range rest {
		if err := load(dst); err != nil {
			return err
		}
	}
	for i := range c.rCode {
		if err := load(&c.rCode[i]); err != nil {
			return err
		}
	}
	for i := range c.latCounts {
		if err := load(&c.latCounts[i]); err != nil {
			return err
		}
	}
	if err := load(&c.latTotal); err != nil {
		return err
	}
	return nil
}

// writeI64 appends v as BigEndian int64 (same layout as writeU64).
func writeI64(buf *bytes.Buffer, v int64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v)) //nolint:gosec // G115: bit-pattern copy of int64
	buf.Write(b[:])
}
