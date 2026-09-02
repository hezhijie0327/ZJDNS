package resolver

import (
	"cmp"
	"context"
	"encoding/binary"
	"slices"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/spillfile"
	"zjdns/internal/ttl"
)

// Delegation spill record wire layout:
// [2B zone_len][zone][2B parent_len][parent][8B ts][4B ttl]
// [4B ns_count][ns names...][4B addr_count][addrs...][4B ds_len][ds_wire]
const (
	maxSpillNames   = 64        // NS/address count per zone
	maxSpillNameLen = 1024      // zone/parent/NS name length
	maxSpillDSLen   = 64 * 1024 // packed DS wire
)

// packDelegationEntry serialises a delegationEntry into a spill record wire.
func packDelegationEntry(e *delegationEntry) []byte {
	out := make([]byte, 0, 128)
	var lenBuf [2]byte
	var numBuf [4]byte
	var tsBuf [8]byte
	writeStr := func(s string) {
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(s))) //nolint:gosec // G115: DNS names are bounded
		out = append(out, lenBuf[:]...)
		out = append(out, s...)
	}
	writeStrs := func(ss []string) {
		binary.BigEndian.PutUint32(numBuf[:], uint32(len(ss))) //nolint:gosec // G115: bounded by NS/addr counts
		out = append(out, numBuf[:]...)
		for _, s := range ss {
			writeStr(s)
		}
	}

	writeStr(e.zone)
	writeStr(e.parent)
	binary.BigEndian.PutUint64(tsBuf[:], uint64(e.ts)) //nolint:gosec // G115: unix seconds fit uint64
	out = append(out, tsBuf[:]...)
	binary.BigEndian.PutUint32(numBuf[:], uint32(e.ttl)) //nolint:gosec // G115: TTL bounded by config cap
	out = append(out, numBuf[:]...)
	writeStrs(e.nsNames)
	writeStrs(e.addrs)
	dsWire := packDS(e.ds)
	binary.BigEndian.PutUint32(numBuf[:], uint32(len(dsWire))) //nolint:gosec // G115: DS wire bounded
	out = append(out, numBuf[:]...)
	out = append(out, dsWire...)
	return out
}

// unpackDelegationEntry parses a delegationEntry from a spill record wire.
// ok is false for corrupt or foreign-length wires (treated as a miss).
func unpackDelegationEntry(wire []byte) (*delegationEntry, bool) {
	e := &delegationEntry{}
	r := wire
	take := func(n int) ([]byte, bool) {
		if len(r) < n {
			return nil, false
		}
		out := r[:n]
		r = r[n:]
		return out, true
	}
	readStr := func() (string, bool) {
		lb, ok := take(2)
		if !ok {
			return "", false
		}
		n := int(binary.BigEndian.Uint16(lb))
		if n > maxSpillNameLen {
			return "", false
		}
		b, ok := take(n)
		if !ok {
			return "", false
		}
		return string(b), true
	}
	readStrs := func() ([]string, bool) {
		nb, ok := take(4)
		if !ok {
			return nil, false
		}
		n := int(binary.BigEndian.Uint32(nb))
		if n > maxSpillNames {
			return nil, false
		}
		out := make([]string, 0, n)
		for range n {
			s, ok := readStr()
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}

	var ok bool
	if e.zone, ok = readStr(); !ok {
		return nil, false
	}
	if e.parent, ok = readStr(); !ok {
		return nil, false
	}
	tsb, ok := take(8)
	if !ok {
		return nil, false
	}
	e.ts = int64(binary.BigEndian.Uint64(tsb)) //nolint:gosec // G115: unix seconds fit int64
	ttlb, ok := take(4)
	if !ok {
		return nil, false
	}
	e.ttl = int(binary.BigEndian.Uint32(ttlb))
	if e.nsNames, ok = readStrs(); !ok {
		return nil, false
	}
	if e.addrs, ok = readStrs(); !ok {
		return nil, false
	}
	dslb, ok := take(4)
	if !ok {
		return nil, false
	}
	dsLen := int(binary.BigEndian.Uint32(dslb))
	if dsLen > maxSpillDSLen {
		return nil, false
	}
	dsWire, ok := take(dsLen)
	if !ok {
		return nil, false
	}
	e.ds = unpackDS(dsWire)
	return e, true
}

// loadDelegationSpill opens the delegation spill store and warms memory with
// its freshest entries (spill ts == store time — freshness is TTL-based).
// On failure (foreign/corrupt file) the disk tier is disabled.
func (r *Recursive) loadDelegationSpill(path string, diskCap, delegationMax int) {
	if path == "" {
		return
	}
	spill, err := spillfile.Open(path)
	if err != nil {
		log.Warnf("RESOLVER: delegation spill store open failed (disk tier disabled): %v", err)
		return
	}
	r.spill = spill
	r.spillCap = diskCap

	// Single-pass warm-up (see Store.Warm): spill ts == store time —
	// freshness is TTL-based, and corrupt wires are tombstoned so they
	// stop resurfacing on promotion.
	warmed, onDisk := spill.Warm(delegationMax, func(ts int64, entryTTL int) bool {
		return !ttl.IsExpired(ts, entryTTL)
	})
	n := 0
	for _, w := range warmed {
		de, ok := unpackDelegationEntry(w.Wire)
		if !ok {
			spill.Delete(w.Key)
			continue
		}
		// Coldest first so the freshest entry ends up at the LRU front.
		r.delegations.Set(w.Key, de)
		n++
	}
	// Spill-on-evict registered AFTER the warm-up load; the write runs on
	// the async writer (lock-free enqueue; a synchronous Put here froze
	// every concurrent delegation lookup behind the disk, 2026-09 R1).
	r.spillW = spillfile.NewAsyncWriter(spill)
	r.delegations.SetOnEvict(func(zone string, de *delegationEntry) {
		if de.ts > 0 && !ttl.IsExpired(de.ts, de.ttl) {
			r.spillW.Enqueue(zone, de.ts, de.ttl, false, packDelegationEntry(de))
		}
	})
	log.Infof("RESOLVER: delegation spill store ready: %d records on disk, %d loaded to memory", onDisk, n)
}

// getDelegationFromSpill reads a delegation record by zone and promotes it
// to memory.  An expired record is dropped from the index.
func (r *Recursive) getDelegationFromSpill(zone string) (*delegationEntry, bool) {
	ts, entryTTL, _, wire, ok := r.spill.Get(zone)
	if !ok {
		return nil, false
	}
	if ttl.IsExpired(ts, entryTTL) {
		r.spill.Delete(zone)
		return nil, false
	}
	de, ok := unpackDelegationEntry(wire)
	if !ok {
		r.spill.Delete(zone)
		return nil, false
	}
	r.delegations.Set(zone, de)
	return de, true
}

// flushDelegationSpill pushes the in-memory delegation cache to the spill
// store (shutdown hook).  The queued async writes are drained first (so the
// Indexed check sees them) and the remaining IO runs OUTSIDE the
// delegations lock — a synchronous Range+Put held the lock that every
// recursive walk needs for the whole flush (2026-09 R1).
func (r *Recursive) flushDelegationSpill() {
	if r.spill == nil {
		return
	}
	if r.spillW != nil {
		drainCtx, drainCancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
		r.spillW.Close(drainCtx)
		drainCancel()
	}
	type row struct {
		zone string
		de   *delegationEntry
	}
	var rows []row
	r.delegations.Range(func(zone string, de *delegationEntry) bool {
		rows = append(rows, row{zone, de})
		return true
	})
	for _, rw := range rows {
		if rw.de.ts > 0 && !ttl.IsExpired(rw.de.ts, rw.de.ttl) && !r.spill.Indexed(rw.zone, rw.de.ts) {
			if err := r.spill.Put(rw.zone, rw.de.ts, rw.de.ttl, false, packDelegationEntry(rw.de)); err != nil {
				// Persistence failures must be visible — a full disk
				// otherwise silently degrades the disk tier (R2).
				log.Warnf("RESOLVER: delegation spill flush %s: %v", rw.zone, err)
			}
		}
	}
	_ = r.spill.Flush() // _ = error: best-effort fsync, Close reports hard errors
}

// compactDelegationSpill rewrites the delegation spill store keeping only
// fresh records, newest first within the disk cap (cap <= 0 = unbounded).
// Runs when expired records dominate the index (> 50%) or the index exceeds
// the cap.
func (r *Recursive) compactDelegationSpill() {
	spill := r.spill
	if spill == nil {
		return
	}
	entries := spill.Entries()
	if len(entries) == 0 {
		return
	}
	now := log.NowUnix()
	expired := 0
	for _, e := range entries {
		if e.Ts+int64(e.Ttl) <= now {
			expired++
		}
	}
	if expired*2 <= len(entries) && (r.spillCap <= 0 || len(entries) <= r.spillCap) {
		return // nothing worth rewriting
	}

	slices.SortFunc(entries, func(a, b spillfile.Entry) int { return cmp.Compare(b.Ts, a.Ts) }) // newest first
	keepSize := len(entries)
	if r.spillCap > 0 {
		keepSize = min(r.spillCap, keepSize)
	}
	keep := make(map[string]bool, keepSize)
	for _, e := range entries {
		if e.Ts+int64(e.Ttl) <= now { // expired — drop
			continue
		}
		if r.spillCap > 0 && len(keep) >= r.spillCap {
			break
		}
		keep[e.Key] = true
	}
	if err := spill.Compact(func(key string, _ int64, _ int) bool { return keep[key] }); err != nil {
		log.Warnf("RESOLVER: delegation spill compact failed: %v", err)
	}
}

// CleanupDelegations physically removes expired entries — the lazy read-time
// TTL filter never frees the memory.  Called periodically by the server.
func (r *Recursive) CleanupDelegations() {
	now := log.NowUnix()
	var stale []string
	r.delegations.Range(func(zone string, e *delegationEntry) bool {
		if e.ts+int64(e.ttl) <= now {
			stale = append(stale, zone)
		}
		return true
	})
	for _, zone := range stale {
		r.delegations.Delete(zone)
	}
}
