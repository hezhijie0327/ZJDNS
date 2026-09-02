package dnscrypt

import (
	"bytes"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"
	"zjdns/config"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"

	"github.com/cloudflare/circl/sign/ed25519"
)

// fakeStore implements StateStore in memory.
type fakeStore struct {
	identity, windows []byte
}

// testPub/testPriv is a generated test Ed25519 identity.
var testPub, testPriv = func() (pub, priv []byte) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return pub, priv
}()

func (f *fakeStore) LoadDNSCryptState() (identity, windows []byte, err error) {
	return f.identity, f.windows, nil
}

func (f *fakeStore) SaveDNSCryptState(identity, windows []byte) error {
	f.identity, f.windows = identity, windows
	return nil
}

func testCfg() *config.DNSCryptCertificate {
	return &config.DNSCryptCertificate{
		PublicKey:  dnscryptcrypto.HexEncodeKey(testPub),
		PrivateKey: dnscryptcrypto.HexEncodeKey(testPriv),
	}
}

// TestPersistRequiresKeys verifies that a missing identity key pair is a
// hard configuration error, not auto-generated.
func TestPersistRequiresKeys(t *testing.T) {
	if _, err := New(&config.DNSCryptCertificate{}, "0", "2.dnscrypt-cert.example.com", nil); err == nil {
		t.Fatal("New with empty keys: want error, got nil")
	}
}

// TestPersistRoundTrip verifies that a restart with the same StateStore
// resumes the exact same cert windows and identity.
func TestPersistRoundTrip(t *testing.T) {
	store := &fakeStore{}
	cfg := testCfg()

	srv1, err := New(cfg, "0", "2.dnscrypt-cert.example.com", store)
	if err != nil {
		t.Fatalf("New (first start): %v", err)
	}
	if store.identity == nil || store.windows == nil {
		t.Fatal("New did not persist initial state")
	}
	// Identity comes from config — the persisted identity must equal it.
	expectedPK, ok := srv1.signingSK.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("signing key is not Ed25519")
	}
	if !bytes.Equal(store.identity[64:96], expectedPK) {
		t.Error("persisted identity does not match the config key")
	}
	serial1 := srv1.current().Classical.Serial
	sk1 := srv1.current().Classical.ResolverSk

	// "Restart" with the same store.
	srv2, err := New(cfg, "0", "2.dnscrypt-cert.example.com", store)
	if err != nil {
		t.Fatalf("New (restart): %v", err)
	}
	if len(srv2.keys) != 1 {
		t.Fatalf("restart: want 1 restored window, got %d", len(srv2.keys))
	}
	curr2 := srv2.current()
	if curr2.Classical.Serial != serial1 {
		t.Errorf("restart: serial changed (%d → %d)", serial1, curr2.Classical.Serial)
	}
	if !bytes.Equal(curr2.Classical.ResolverSk[:], sk1[:]) {
		t.Error("restart: resolver secret key changed")
	}
	restoredPK, ok := srv2.signingSK.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(restoredPK, expectedPK) {
		t.Error("restart: identity changed")
	}
	// The full wire certs must be byte-identical — the classical AND PQ
	// certs (PQ keys derive from the same resolver sk).  This catches
	// derivation mistakes that leave the classical cert intact.
	classical1, _ := srv1.current().Classical.MarshalBinary()
	pq1, _ := srv1.current().PQ.MarshalBinary()
	classical2, _ := srv2.current().Classical.MarshalBinary()
	pq2, _ := srv2.current().PQ.MarshalBinary()
	if !bytes.Equal(classical1, classical2) {
		t.Error("restart: classical cert bytes differ")
	}
	if !bytes.Equal(pq1, pq2) {
		t.Error("restart: PQ cert bytes differ")
	}
}

// TestPersistRotation verifies renewal persists the new window set and the
// restored server serves both windows.
func TestPersistRotation(t *testing.T) {
	store := &fakeStore{}
	cfg := testCfg()

	srv, err := New(cfg, "0", "2.dnscrypt-cert.example.com", store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ageWindow(srv, 0, 8*time.Hour)
	srv.updateKeys()
	if len(srv.keys) != 2 {
		t.Fatalf("after renewal: want 2 windows, got %d", len(srv.keys))
	}

	srv2, err := New(cfg, "0", "2.dnscrypt-cert.example.com", store)
	if err != nil {
		t.Fatalf("New (restart): %v", err)
	}
	if len(srv2.keys) != 2 {
		t.Fatalf("restart after renewal: want 2 windows, got %d", len(srv2.keys))
	}
	// Newest window first — NotBefore must match the renewed order.
	if srv2.current().Classical.NotBefore != srv.current().Classical.NotBefore {
		t.Errorf("restart: current window NotBefore mismatch (%d ≠ %d)",
			srv2.current().Classical.NotBefore, srv.current().Classical.NotBefore)
	}
	if srv2.keys[1].pair.Classical.NotBefore != srv.keys[1].pair.Classical.NotBefore {
		t.Errorf("restart: previous window NotBefore mismatch (%d ≠ %d)",
			srv2.keys[1].pair.Classical.NotBefore, srv.keys[1].pair.Classical.NotBefore)
	}
}

// TestPersistConfigIdentityChange verifies that changing the config keys
// drops the persisted state and serves a fresh window under the new identity.
func TestPersistConfigIdentityChange(t *testing.T) {
	store := &fakeStore{}
	cfg := testCfg()

	srv1, err := New(cfg, "0", "2.dnscrypt-cert.example.com", store)
	if err != nil {
		t.Fatalf("New (first start): %v", err)
	}
	oldPK, _ := srv1.signingSK.Public().(ed25519.PublicKey)

	// New config with explicit keys that differ from the persisted identity.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 keypair: %v", err)
	}
	cfg2 := &config.DNSCryptCertificate{
		PublicKey:  dnscryptcrypto.HexEncodeKey(pub),
		PrivateKey: dnscryptcrypto.HexEncodeKey(priv),
	}

	srv2, err := New(cfg2, "0", "2.dnscrypt-cert.example.com", store)
	if err != nil {
		t.Fatalf("New (identity change): %v", err)
	}
	newPK, _ := srv2.signingSK.Public().(ed25519.PublicKey)
	if bytes.Equal(newPK, oldPK) {
		t.Error("config identity change did not switch the signing key")
	}
	// Fresh window: new identity means the persisted resolver keys can no
	// longer be served (certs are re-signed), so a new pair is minted.
	if len(srv2.keys) != 1 || bytes.Equal(srv2.current().Classical.ResolverSk[:], srv1.current().Classical.ResolverSk[:]) {
		t.Error("config identity change did not mint a fresh window")
	}
	// Persisted state now reflects the new identity.
	if !bytes.Equal(store.identity[64:96], newPK) {
		t.Error("persisted identity not updated to the new config key")
	}
}

// TestPersistFileStore verifies the file-backed state round-trip: a restart
// through the same state file resumes the same cert windows.
func TestPersistFileStore(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "state.bin"))

	cfg := testCfg()
	srv1, err := New(cfg, "0", "2.dnscrypt-cert.example.com", store)
	if err != nil {
		t.Fatalf("New (first start): %v", err)
	}
	serial1 := srv1.current().Classical.Serial

	srv2, err := New(cfg, "0", "2.dnscrypt-cert.example.com", store)
	if err != nil {
		t.Fatalf("New (restart): %v", err)
	}
	if srv2.current().Classical.Serial != serial1 {
		t.Errorf("file restart: serial changed (%d → %d)", serial1, srv2.current().Classical.Serial)
	}
}

// TestEncodeDecodeRoundTrip verifies the window blob layout round-trips.
func TestEncodeDecodeRoundTrip(t *testing.T) {
	windows := []windowRecord{
		{
			Serial: 1000, NotBefore: 1000, NotAfter: 1000 + uint32(config.DefaultDNSCryptCertificateTTL/time.Second),
			ResolverSk: bytes.Repeat([]byte{0x11}, 32), ResolverPk: bytes.Repeat([]byte{0x22}, 32),
		},
		{
			Serial: 2000, NotBefore: 2000, NotAfter: 2000 + uint32(config.DefaultDNSCryptCertificateTTL/time.Second),
			ResolverSk: bytes.Repeat([]byte{0x33}, 32), ResolverPk: bytes.Repeat([]byte{0x44}, 32),
		},
	}
	blob := encodeWindows(windows)
	decoded, err := decodeWindows(blob)
	if err != nil {
		t.Fatalf("decodeWindows: %v", err)
	}
	if len(decoded) != len(windows) {
		t.Fatalf("round-trip: want %d windows, got %d", len(windows), len(decoded))
	}
	for i, w := range decoded {
		want := windows[i]
		if w.Serial != want.Serial || w.NotBefore != want.NotBefore || w.NotAfter != want.NotAfter {
			t.Errorf("window %d: header mismatch (%+v ≠ %+v)", i, w, want)
		}
		if !bytes.Equal(w.ResolverSk, want.ResolverSk) || !bytes.Equal(w.ResolverPk, want.ResolverPk) {
			t.Errorf("window %d: key mismatch", i)
		}
	}
	// Corrupt inputs must error, not panic.
	for _, bad := range [][]byte{nil, {0x99}, {stateLayoutVersion, 0, 1}, {stateLayoutVersion, 0, 0, 0x01}} {
		if _, err := decodeWindows(bad); err == nil {
			t.Errorf("decodeWindows(%v): want error", bad)
		}
	}
}

// TestWindowsFromStateFiltersExpired verifies expired windows are dropped.
func TestWindowsFromStateFiltersExpired(t *testing.T) {
	now := dnscryptcrypto.NowUnix32()
	windows := []windowRecord{
		{Serial: 1, NotAfter: now - 1}, // expired
		{Serial: 2, NotAfter: now + uint32(config.DefaultDNSCryptCertificateTTL/time.Second)}, // live
	}
	filtered := windowsFromState(windows)
	if len(filtered) != 1 || filtered[0].Serial != 2 {
		t.Fatalf("windowsFromState: want [2], got %+v", filtered)
	}
}

// TestRestoredEntriesCarryCertTXT verifies the state-file restore path
// populates the precomputed handshake artifacts: windowsToKeyEntries used to
// build bare keyEntry{pair} values whose nil classicalTXT made every cert
// fetch after a restart serve a malformed (empty-chunk) TXT answer — every
// pinned client died until the window rotated out.
func TestRestoredEntriesCarryCertTXT(t *testing.T) {
	now := dnscryptcrypto.NowUnix32()
	sk, pk, err := dnscryptcrypto.GenerateRandomKeyPair()
	if err != nil {
		t.Fatalf("resolver key: %v", err)
	}
	signPk, signSk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("signing key: %v", err)
	}
	rc := &ResolverConfig{
		PrivateKey: dnscryptcrypto.HexEncodeKey(signSk),
		PublicKey:  dnscryptcrypto.HexEncodeKey(signPk),
	}
	w := windowRecord{
		Serial: 1, NotBefore: now - 1, NotAfter: now + 1024,
		ResolverSk: sk[:], ResolverPk: pk[:],
	}
	entries, err := windowsToKeyEntries(rc, []windowRecord{w})
	if err != nil {
		t.Fatalf("windowsToKeyEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	e := entries[0]
	if len(e.classicalTXT) == 0 || len(e.pqTXT) == 0 || e.pqWireSize == 0 {
		t.Fatalf("restored entry missing precomputed cert TXT: classical=%d pq=%d wire=%d", len(e.classicalTXT), len(e.pqTXT), e.pqWireSize)
	}
}
