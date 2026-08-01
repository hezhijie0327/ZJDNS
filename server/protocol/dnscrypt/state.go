package dnscrypt

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"zjdns/config"
	"zjdns/database"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"
	"zjdns/internal/log"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/dgraph-io/badger/v4"
)

// ── Key construction ─────────────────────────────────────────────────────────

// windowRecord is the decoded form of a single persisted cert window.
type windowRecord struct {
	Serial     uint32
	NotBefore  uint32
	NotAfter   uint32
	ResolverSk []byte // 32 bytes
	ResolverPk []byte // 32 bytes
}

// errNoIdentity is returned by loadIdentity when no signing key has been
// persisted yet (first run).  Callers check err != nil to decide whether to
// build a new identity from config.
var errNoIdentity = errors.New("dnscrypt: no persisted identity")

var (
	dnscryptIdentityKey = []byte(database.PrefixDNSCrypt + "identity")
	dnscryptWindowKey   = []byte(database.PrefixDNSCrypt + "window:")
)

func dnscryptWindowKeyBytes(serial uint32) []byte {
	key := make([]byte, len(dnscryptWindowKey)+4)
	copy(key, dnscryptWindowKey)
	binary.BigEndian.PutUint32(key[len(dnscryptWindowKey):], serial)
	return key
}

// ── Identity persistence ─────────────────────────────────────────────────────

// saveIdentity persists the Ed25519 signing key to the database.  Written on
// first run and whenever the config identity changes (auto-switch).
func saveIdentity(db *database.DB, sk ed25519.PrivateKey) error {
	pk, ok := sk.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("dnscrypt: signing key is not Ed25519")
	}
	val := database.EncodeDNSCryptIdentity([]byte(sk), []byte(pk))
	if val == nil {
		return errors.New("dnscrypt: identity key has wrong size")
	}
	return db.Update(func(txn *badger.Txn) error {
		return txn.Set(dnscryptIdentityKey, val)
	})
}

// loadIdentity reads the persisted Ed25519 signing key.
// Returns (nil, errNoIdentity) on first run when no key has been persisted yet.
func loadIdentity(db *database.DB) (ed25519.PrivateKey, error) {
	var sk ed25519.PrivateKey
	found := false
	err := db.View(func(txn *badger.Txn) error {
		item, getErr := txn.Get(dnscryptIdentityKey)
		if getErr != nil {
			if errors.Is(getErr, badger.ErrKeyNotFound) {
				return nil
			}
			return getErr
		}
		return item.Value(func(val []byte) error {
			s, pk := database.DecodeDNSCryptIdentity(val)
			if s == nil || pk == nil {
				return errors.New("dnscrypt: corrupted identity in database")
			}
			sk = ed25519.PrivateKey(s)
			found = true
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errNoIdentity
	}
	return sk, nil
}

// ── Window persistence ───────────────────────────────────────────────────────

// saveWindow persists a single cert window with TTL so BadgerDB auto-evicts it
// when expired.
func saveWindow(db *database.DB, w windowRecord) error {
	key := dnscryptWindowKeyBytes(w.Serial)
	val := database.EncodeDNSCryptWindow(w.Serial, w.NotBefore, w.NotAfter, w.ResolverSk, w.ResolverPk)
	if val == nil {
		return fmt.Errorf("dnscrypt: window serial=%d has wrong-sized keys", w.Serial)
	}

	return db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry(key, val)
		// Include key overlap so windows survive restarts during the
		// overlap period (the server serves them for NotAfter+overlap).
		e.ExpiresAt = uint64(w.NotAfter) + uint64(config.DefaultDNSCryptKeyOverlap/time.Second) //nolint:gosec // G115: fits in uint64
		return txn.SetEntry(e)
	})
}

// loadWindows scans all surviving cert windows from the database.  Expired
// windows are auto-evicted by BadgerDB, so only valid windows survive the scan.
func loadWindows(db *database.DB) ([]windowRecord, error) {
	var windows []windowRecord
	err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = dnscryptWindowKey
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			if item.IsDeletedOrExpired() {
				continue // compaction hasn't caught up yet — skip
			}
			if valErr := item.Value(func(val []byte) error {
				serial, notBefore, notAfter, resolverSk, resolverPk := database.DecodeDNSCryptWindow(val)
				if resolverSk == nil {
					return nil // corrupted entry — skip
				}
				windows = append(windows, windowRecord{
					Serial:     serial,
					NotBefore:  notBefore,
					NotAfter:   notAfter,
					ResolverSk: resolverSk,
					ResolverPk: resolverPk,
				})
				return nil
			}); valErr != nil {
				return valErr
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scanning dnscrypt windows: %w", err)
	}
	return windows, nil
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
