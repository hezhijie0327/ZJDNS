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
	"zjdns/internal/persist"

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

// ── Persist file ──────────────────────────────────────────────────────────────

// Persist file layout — version gates format evolution; no magic (zstd
// framing + version + structure checks identify and validate the file).
//
//	[2B version=1]
//	[4B identity_len][identity (96B: sk 64 + pk 32)]
//	[2B window_count]
//	per window: [4B serial][4B not_before][4B not_after][32B resolver_sk][32B resolver_pk]
const stateFileVersion = 1

var (
	// errNoIdentity is returned when no signing key has been persisted yet
	// (first run). Callers check err != nil to decide whether to build a new
	// identity from config.
	errNoIdentity = errors.New("dnscrypt: no persisted identity")
	// errCorruptState is returned when the state file fails to decode.
	errCorruptState = errors.New("dnscrypt: corrupted state file")
)

// loadStateFile reads the DNSCrypt identity + windows persist file.
// A missing file returns errNoIdentity (first run); corrupt files are errors.
func loadStateFile(path string) (sk ed25519.PrivateKey, windows []windowRecord, err error) {
	if path == "" {
		return nil, nil, errNoIdentity
	}
	raw, err := persist.Load(path)
	if err != nil {
		_ = persist.Backup(path) // corrupt state — preserve the identity
		return nil, nil, err
	}
	if raw == nil {
		return nil, nil, errNoIdentity
	}
	sk, windows, err = decodeState(raw)
	if err != nil {
		// Corrupt or unsupported-version state — preserve it (the identity is
		// the least disposable data in the server) before a fresh write.
		_ = persist.Backup(path)
		return nil, nil, fmt.Errorf("dnscrypt: decode %s: %w", path, err)
	}
	return sk, windows, nil
}

// saveStateFile writes the identity + windows persist file (zstd + atomic
// write via internal/persist). Called on startup and key rotation — key
// rotation must survive a restart.
func saveStateFile(path string, sk ed25519.PrivateKey, keys []keyEntry) error {
	if path == "" {
		return nil
	}
	if err := persist.Save(path, encodeState(sk, keys)); err != nil {
		return err
	}
	return nil
}

// ── State encode/decode ───────────────────────────────────────────────────────

// encodeState serializes the identity + current key windows.
func encodeState(sk ed25519.PrivateKey, keys []keyEntry) []byte {
	var buf bytes.Buffer
	writeU16(&buf, stateFileVersion)

	identity := encodeIdentity(sk)
	writeU32(&buf, uint32(len(identity))) //nolint:gosec // G115: identity is 96 bytes
	buf.Write(identity)

	writeU16(&buf, uint16(len(keys))) //nolint:gosec // G115: window count capped at 2 by rotation
	for _, k := range keys {
		c := k.pair.Classical
		writeU32(&buf, c.Serial)
		writeU32(&buf, c.NotBefore)
		writeU32(&buf, c.NotAfter)
		buf.Write(c.ResolverSk[:])
		buf.Write(c.ResolverPk[:])
	}
	return buf.Bytes()
}

// decodeState parses the layout produced by encodeState.
func decodeState(raw []byte) (ed25519.PrivateKey, []windowRecord, error) {
	if len(raw) < 2+4 {
		return nil, nil, errCorruptState
	}
	off := 0
	if binary.BigEndian.Uint16(raw[off:]) != stateFileVersion {
		return nil, nil, errCorruptState
	}
	off += 2

	// Identity: length-prefixed 96-byte sk+pk.
	ilen := int(binary.BigEndian.Uint32(raw[off:])) //nolint:gosec // G115: bounded by file size below
	off += 4
	if off+ilen > len(raw) || ilen != 96 {
		return nil, nil, errCorruptState
	}
	sk := ed25519.PrivateKey(raw[off : off+64])
	off += ilen

	// Windows.
	if off+2 > len(raw) {
		return nil, nil, errCorruptState
	}
	wcount := int(binary.BigEndian.Uint16(raw[off:])) //nolint:gosec // G115: protocol-bounded uint16
	off += 2
	windows := make([]windowRecord, 0, wcount)
	for range wcount {
		if off+76 > len(raw) {
			return nil, nil, errCorruptState
		}
		windows = append(windows, windowRecord{
			Serial:     binary.BigEndian.Uint32(raw[off:]),
			NotBefore:  binary.BigEndian.Uint32(raw[off+4:]),
			NotAfter:   binary.BigEndian.Uint32(raw[off+8:]),
			ResolverSk: raw[off+12 : off+44],
			ResolverPk: raw[off+44 : off+76],
		})
		off += 76
	}
	return sk, windows, nil
}

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
