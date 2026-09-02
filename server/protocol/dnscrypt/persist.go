package dnscrypt

import (
	"encoding/binary"
	"errors"
	"fmt"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"
	"zjdns/internal/log"

	"github.com/cloudflare/circl/sign/ed25519"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// StateStore persists the DNSCrypt identity + cert windows across restarts.
// Implemented by *FileStore (persist_file.go) — the database package was removed in the 2026-08 all-memory migration.  A nil store disables persistence.
type StateStore interface {
	LoadDNSCryptState() (identity, windows []byte, err error)
	SaveDNSCryptState(identity, windows []byte) error
}

// windowRecord is the decoded form of a single cert window.  Persisting the
// full window (rather than a seed) makes the cert exactly reproducible after
// a restart — the Ed25519 identity re-signs the same serial/timestamps, and
// the resolver sk/pk are stored verbatim.  The next rotation generates fresh
// random keys; windows are self-contained so no chain is needed.
type windowRecord struct {
	Serial     uint32
	NotBefore  uint32
	NotAfter   uint32
	ResolverSk []byte // 32 bytes
	ResolverPk []byte // 32 bytes
}

// stateLayoutVersion gates the persisted window blob layout.
const stateLayoutVersion = 1

// errCorruptState is returned when the persisted state fails to decode.
var errCorruptState = errors.New("dnscrypt: corrupted persisted state")

// ── Binary layout ─────────────────────────────────────────────────────────────
//
//	[1B layout version = 1]
//	[2B window_count]
//	per window: [4B serial][4B not_before][4B not_after][32B resolver_sk][32B resolver_pk]

// encodeWindows serializes window records to the binary layout above.
func encodeWindows(windows []windowRecord) []byte {
	buf := make([]byte, 0, 3+76*len(windows))
	buf = append(buf, stateLayoutVersion)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(windows))) //nolint:gosec // G115: window count capped at 2 by rotation
	for _, w := range windows {
		buf = binary.BigEndian.AppendUint32(buf, w.Serial)
		buf = binary.BigEndian.AppendUint32(buf, w.NotBefore)
		buf = binary.BigEndian.AppendUint32(buf, w.NotAfter)
		buf = append(buf, w.ResolverSk...)
		buf = append(buf, w.ResolverPk...)
	}
	return buf
}

// decodeWindows parses the layout produced by encodeWindows.
func decodeWindows(b []byte) ([]windowRecord, error) {
	if len(b) < 3 || b[0] != stateLayoutVersion {
		return nil, errCorruptState
	}
	wcount := int(binary.BigEndian.Uint16(b[1:3]))
	if len(b) != 3+76*wcount {
		return nil, errCorruptState
	}
	windows := make([]windowRecord, 0, wcount)
	for off := 3; off < len(b); off += 76 {
		windows = append(windows, windowRecord{
			Serial:     binary.BigEndian.Uint32(b[off:]),
			NotBefore:  binary.BigEndian.Uint32(b[off+4:]),
			NotAfter:   binary.BigEndian.Uint32(b[off+8:]),
			ResolverSk: b[off+12 : off+44],
			ResolverPk: b[off+44 : off+76],
		})
	}
	return windows, nil
}

// ── State helpers ─────────────────────────────────────────────────────────────

// encodeIdentity packs the Ed25519 signing key into the 96-byte layout
// [0:64]sk [64:96]pk.  Returns nil if the key is not Ed25519.
func encodeIdentity(sk ed25519.PrivateKey) []byte {
	pk, ok := sk.Public().(ed25519.PublicKey)
	if !ok {
		return nil
	}
	buf := make([]byte, 96)
	copy(buf[0:64], sk)
	copy(buf[64:96], pk)
	return buf
}

// windowsFromState filters persisted windows that are no longer valid
// (NotAfter has passed).
func windowsFromState(windows []windowRecord) []windowRecord {
	now := dnscryptcrypto.NowUnix32()
	out := windows[:0]
	for _, w := range windows {
		if w.NotAfter >= now {
			out = append(out, w)
		}
	}
	return out
}

// windowsToKeyEntries reconstructs keyEntry slices from persisted window records.
func windowsToKeyEntries(rc *ResolverConfig, windows []windowRecord) ([]keyEntry, error) {
	entries := make([]keyEntry, 0, len(windows))
	for _, w := range windows {
		rc.ResolverSk = dnscryptcrypto.HexEncodeKey(w.ResolverSk)
		rc.ResolverPk = dnscryptcrypto.HexEncodeKey(w.ResolverPk)
		pair, err := rc.NewCertPair(w.NotBefore, w.NotAfter)
		if err != nil {
			return nil, fmt.Errorf("recreating cert pair (not_before=%d): %w", w.NotBefore, err)
		}
		entries = append(entries, newKeyEntry(pair))
		log.Debugf("DNSCRYPT: restored window (not_before=%d, not_after=%d)", w.NotBefore, w.NotAfter)
	}
	return entries, nil
}

// stateWindows converts keyEntry windows to the persisted record form.
func stateWindows(keys []keyEntry) []windowRecord {
	windows := make([]windowRecord, 0, len(keys))
	for _, k := range keys {
		c := k.pair.Classical
		windows = append(windows, windowRecord{
			Serial:     c.Serial,
			NotBefore:  c.NotBefore,
			NotAfter:   c.NotAfter,
			ResolverSk: c.ResolverSk[:],
			ResolverPk: c.ResolverPk[:],
		})
	}
	return windows
}
