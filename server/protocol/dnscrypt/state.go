package dnscrypt

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"zjdns/config"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"
	"zjdns/internal/log"

	"github.com/cloudflare/circl/sign/ed25519"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// windowRecord is the decoded form of a single cert window.
type windowRecord struct {
	Serial     uint32
	NotBefore  uint32
	NotAfter   uint32
	ResolverSk []byte // 32 bytes
	ResolverPk []byte // 32 bytes
}

// dnscryptState is the single persisted entry: the Ed25519 identity plus all
// cert windows, stored via the shared lrumap persistence mechanism (backup on
// version mismatch, zstd + atomic write, unified load logs).
type dnscryptState struct {
	identity []byte // 96B: sk (64) + pk (32); nil = no identity yet
	windows  []windowRecord
}

// dnscryptCodec implements lrumap.Codec for the DNSCrypt state entry.
type dnscryptCodec struct{}

// dnscryptPersistVersion gates the lrumap-framed format; the old
// standalone layout (stateFileVersion 1) is backed up and rebuilt.
const dnscryptPersistVersion = 2

// errCorruptState is returned when the state file fails to decode.
var errCorruptState = errors.New("dnscrypt: corrupted state file")

func (dnscryptCodec) Version() uint16 { return dnscryptPersistVersion }

func (dnscryptCodec) EncodeKey(k string) []byte { return []byte(k) }

func (dnscryptCodec) DecodeKey(b []byte) (string, error) { return string(b), nil }

// EncodeValue serializes the state:
//
//	[2B inner layout version=1]
//	[4B identity_len][identity (96B: sk 64 + pk 32)]
//	[2B window_count]
//	per window: [4B serial][4B not_before][4B not_after][32B resolver_sk][32B resolver_pk]
func (dnscryptCodec) EncodeValue(s dnscryptState) []byte {
	var buf bytes.Buffer
	writeU16(&buf, 1)
	writeU32(&buf, uint32(len(s.identity))) //nolint:gosec // G115: identity is 96 bytes
	buf.Write(s.identity)
	writeU16(&buf, uint16(len(s.windows))) //nolint:gosec // G115: window count capped at 2 by rotation
	for _, w := range s.windows {
		writeU32(&buf, w.Serial)
		writeU32(&buf, w.NotBefore)
		writeU32(&buf, w.NotAfter)
		buf.Write(w.ResolverSk)
		buf.Write(w.ResolverPk)
	}
	return buf.Bytes()
}

// DecodeValue parses the layout produced by EncodeValue.
func (dnscryptCodec) DecodeValue(b []byte) (dnscryptState, bool, error) {
	if len(b) < 2+4 {
		return dnscryptState{}, false, errCorruptState
	}
	off := 0
	if binary.BigEndian.Uint16(b[off:]) != 1 {
		return dnscryptState{}, false, errCorruptState
	}
	off += 2

	// Identity: length-prefixed 96-byte sk+pk.
	ilen := int(binary.BigEndian.Uint32(b[off:])) //nolint:gosec // G115: bounded by file size below
	off += 4
	if off+ilen > len(b) || ilen != 96 {
		return dnscryptState{}, false, errCorruptState
	}
	identity := b[off : off+ilen]
	off += ilen

	// Windows.
	if off+2 > len(b) {
		return dnscryptState{}, false, errCorruptState
	}
	wcount := int(binary.BigEndian.Uint16(b[off:])) //nolint:gosec // G115: protocol-bounded uint16
	off += 2
	windows := make([]windowRecord, 0, wcount)
	for range wcount {
		if off+76 > len(b) {
			return dnscryptState{}, false, errCorruptState
		}
		windows = append(windows, windowRecord{
			Serial:     binary.BigEndian.Uint32(b[off:]),
			NotBefore:  binary.BigEndian.Uint32(b[off+4:]),
			NotAfter:   binary.BigEndian.Uint32(b[off+8:]),
			ResolverSk: b[off+12 : off+44],
			ResolverPk: b[off+44 : off+76],
		})
		off += 76
	}
	return dnscryptState{identity: identity, windows: windows}, true, nil
}

// ── State helpers ─────────────────────────────────────────────────────────────

// encodeIdentity packs the Ed25519 signing key into the 96-byte layout
// [0:64]sk [64:96]pk. Returns nil if the key is not Ed25519.
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

// windowsFromState filters persisted windows that are no longer served
// (past NotAfter + overlap).
func windowsFromState(windows []windowRecord) []windowRecord {
	cutoff := uint32(time.Now().Add(-config.DefaultDNSCryptKeyOverlap).Unix()) //nolint:gosec // G115: DNSCrypt window timestamps — protocol-bounded uint32
	out := windows[:0]
	for _, w := range windows {
		if w.NotAfter >= cutoff {
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
		pair, err := rc.NewCertPair(w.Serial, w.NotBefore, w.NotAfter)
		if err != nil {
			return nil, fmt.Errorf("recreating cert pair (serial=%d): %w", w.Serial, err)
		}
		entries = append(entries, keyEntry{
			pair:      pair,
			createdAt: time.Unix(int64(w.NotBefore), 0),
			cachedTXT: [2][]string{
				buildCertTXTForCert(pair.Classical),
				buildCertTXTForCert(pair.PQ),
			},
		})
		log.Debugf("DNSCRYPT: restored window serial=%d (not_before=%d, not_after=%d)", w.Serial, w.NotBefore, w.NotAfter)
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

// ── Primitive writers ────────────────────────────────────────────────────────

func writeU16(buf *bytes.Buffer, v uint16) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	buf.Write(b[:])
}

func writeU32(buf *bytes.Buffer, v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	buf.Write(b[:])
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// newRandomSeed generates a random 32-byte X25519 seed.
func newRandomSeed() ([32]byte, error) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return seed, fmt.Errorf("crypto/rand: %w", err)
	}
	return seed, nil
}

// generateNextPair creates the next cert pair using the deterministic seed chain.
// The seed is advanced in-place: after this call *seed contains the secret key
// of the new pair, which serves as the seed for the next generation.
func (rc *ResolverConfig) generateNextPair(seed *[32]byte, now uint32) (*dnscryptcrypto.CertPair, error) {
	sk, pk, err := dnscryptcrypto.X25519KeyPairFromSeed(*seed)
	if err != nil {
		return nil, fmt.Errorf("deriving resolver keys from seed: %w", err)
	}

	notAfter := now + uint32(config.DefaultDNSCryptCertificateTTL/time.Second)

	rc.ResolverSk = dnscryptcrypto.HexEncodeKey(sk[:])
	rc.ResolverPk = dnscryptcrypto.HexEncodeKey(pk[:])

	pair, err := rc.NewCertPair(now, now, notAfter)
	if err != nil {
		return nil, err
	}

	// Advance the seed chain: next seed = this window's secret key.
	*seed = sk
	return pair, nil
}
