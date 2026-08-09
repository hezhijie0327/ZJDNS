package resolver

import (
	"encoding/binary"
	"io"
	"zjdns/internal/log"
	"zjdns/internal/snapfile"
)

// Delegation snapshot entry format:
// [2B zone_len][zone][2B parent_len][parent][8B ts][4B ttl]
// [4B ns_count][ns names...][4B addr_count][addrs...][4B ds_len][ds_wire]
const delegationSnapshotVersion = 1

// SaveDelegationSnapshot writes the zone-cut delegation cache to path
// atomically.
func (r *Recursive) SaveDelegationSnapshot(path string) error {
	return snapfile.Save(path, delegationSnapshotVersion, func(w io.Writer) error {
		var lenBuf [2]byte
		var tsBuf [8]byte
		var numBuf [4]byte
		var writeErr error
		writeStr := func(s string) error {
			binary.BigEndian.PutUint16(lenBuf[:], uint16(len(s))) //nolint:gosec // G115: DNS names are bounded
			if _, err := w.Write(lenBuf[:]); err != nil {
				return err
			}
			_, err := io.WriteString(w, s)
			return err
		}
		writeStrings := func(ss []string) error {
			binary.BigEndian.PutUint32(numBuf[:], uint32(len(ss))) //nolint:gosec // G115: bounded by NS/addr counts
			if _, err := w.Write(numBuf[:]); err != nil {
				return err
			}
			for _, s := range ss {
				if err := writeStr(s); err != nil {
					return err
				}
			}
			return nil
		}

		r.delegations.Range(func(zone string, e *delegationEntry) bool {
			if err := writeStr(zone); err != nil {
				writeErr = err
				return false
			}
			if err := writeStr(e.parent); err != nil {
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
			if err := writeStrings(e.nsNames); err != nil {
				writeErr = err
				return false
			}
			if err := writeStrings(e.addrs); err != nil {
				writeErr = err
				return false
			}
			dsWire := packDS(e.ds)
			binary.BigEndian.PutUint32(numBuf[:], uint32(len(dsWire))) //nolint:gosec // G115: DS wire bounded
			if _, err := w.Write(numBuf[:]); err != nil {
				writeErr = err
				return false
			}
			if _, err := w.Write(dsWire); err != nil {
				writeErr = err
			}
			return writeErr == nil
		})
		return writeErr
	})
}

// LoadDelegationSnapshot loads the delegation cache from a snapshot file.
func (r *Recursive) LoadDelegationSnapshot(path string) error {
	return snapfile.Load(path, delegationSnapshotVersion, func(rd io.Reader) error {
		var lenBuf [2]byte
		readStr := func() (string, error) {
			if _, err := io.ReadFull(rd, lenBuf[:]); err != nil {
				return "", err
			}
			buf := make([]byte, int(binary.BigEndian.Uint16(lenBuf[:])))
			if _, err := io.ReadFull(rd, buf); err != nil {
				return "", err
			}
			return string(buf), nil
		}
		readStrings := func() ([]string, error) {
			var numBuf [4]byte
			if _, err := io.ReadFull(rd, numBuf[:]); err != nil {
				return nil, err
			}
			n := int(binary.BigEndian.Uint32(numBuf[:]))
			out := make([]string, 0, n)
			for range n {
				s, err := readStr()
				if err != nil {
					return nil, err
				}
				out = append(out, s)
			}
			return out, nil
		}

		zone, err := readStr()
		if err != nil {
			return err
		}
		parent, err := readStr()
		if err != nil {
			return err
		}
		var entryBuf [12]byte // ts(8) + ttl(4)
		if _, err := io.ReadFull(rd, entryBuf[:]); err != nil {
			return err
		}
		ts := int64(binary.BigEndian.Uint64(entryBuf[0:8])) //nolint:gosec // G115: snapshot ts is a unix second
		ttl := int(binary.BigEndian.Uint32(entryBuf[8:12]))
		nsNames, err := readStrings()
		if err != nil {
			return err
		}
		addrs, err := readStrings()
		if err != nil {
			return err
		}
		var numBuf [4]byte
		if _, err := io.ReadFull(rd, numBuf[:]); err != nil {
			return err
		}
		dsWire := make([]byte, int(binary.BigEndian.Uint32(numBuf[:])))
		if _, err := io.ReadFull(rd, dsWire); err != nil {
			return err
		}

		r.delegations.Set(zone, &delegationEntry{
			zone: zone, parent: parent, nsNames: nsNames, addrs: addrs,
			ds: unpackDS(dsWire), ts: ts, ttl: ttl,
		})
		return nil
	})
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
