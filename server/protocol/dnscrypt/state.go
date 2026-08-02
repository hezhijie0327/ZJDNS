package dnscrypt

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"
	"zjdns/cache"
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

// StateSaver persists the DNSCrypt identity and cert windows. Implemented by
// the cache (SetDNSCrypt) — the DNSCrypt server owns the data, the saver owns
// the persist file. Nil saver disables persistence.
type StateSaver interface {
	SetDNSCrypt(identity []byte, windows []cache.Window)
}

// errNoIdentity is returned when no signing key has been persisted yet
// (first run). Callers check err != nil to decide whether to build a new
// identity from config.
var errNoIdentity = errors.New("dnscrypt: no persisted identity")

// ── State encode/decode ───────────────────────────────────────────────────────

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

// decodeIdentity unpacks the 96-byte identity layout. Returns errNoIdentity
// when state is absent (first run).
func decodeIdentity(dc *cache.DNSCrypt) (ed25519.PrivateKey, error) {
	if dc == nil || len(dc.Identity) != 96 {
		return nil, errNoIdentity
	}
	return ed25519.PrivateKey(dc.Identity[:64]), nil
}

// windowsFromState converts persisted windows into windowRecords, skipping
// entries that are no longer served (past NotAfter + overlap).
func windowsFromState(dc *cache.DNSCrypt) []windowRecord {
	if dc == nil {
		return nil
	}
	cutoff := uint32(time.Now().Add(-config.DefaultDNSCryptKeyOverlap).Unix()) //nolint:gosec // G115: DNSCrypt window timestamps — protocol-bounded uint32
	windows := make([]windowRecord, 0, len(dc.Windows))
	for _, w := range dc.Windows {
		if w.NotAfter < cutoff {
			continue // no longer served — skip
		}
		windows = append(windows, windowRecord{
			Serial:     w.Serial,
			NotBefore:  w.NotBefore,
			NotAfter:   w.NotAfter,
			ResolverSk: w.ResolverSK,
			ResolverPk: w.ResolverPK,
		})
	}
	return windows
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

// windowsFromKeys converts the in-memory key list back to persisted windows.
func windowsFromKeys(keys []keyEntry) []cache.Window {
	windows := make([]cache.Window, 0, len(keys))
	for _, k := range keys {
		c := k.pair.Classical
		windows = append(windows, cache.Window{
			Serial:     c.Serial,
			NotBefore:  c.NotBefore,
			NotAfter:   c.NotAfter,
			ResolverSK: c.ResolverSk[:],
			ResolverPK: c.ResolverPk[:],
		})
	}
	return windows
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
