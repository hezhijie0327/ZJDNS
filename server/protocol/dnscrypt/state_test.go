package dnscrypt

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
	"zjdns/config"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"
	"zjdns/internal/persist"

	"github.com/cloudflare/circl/sign/ed25519"
)

// testKeyEntry builds one keyEntry via the seed chain (state test helper).
func testKeyEntry(tb testing.TB, seed *[32]byte) keyEntry {
	tb.Helper()
	pub, priv, err := dnscryptcrypto.GenerateEd25519Keypair()
	if err != nil {
		tb.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	rc := ResolverConfig{
		ProviderName: "2.dnscrypt-cert.example.com",
		PublicKey:    dnscryptcrypto.HexEncodeKey(pub),
		PrivateKey:   dnscryptcrypto.HexEncodeKey(priv),
	}
	pair, err := rc.generateNextPair(seed, dnscryptcrypto.NowUnix32())
	if err != nil {
		tb.Fatalf("generateNextPair: %v", err)
	}
	return keyEntry{pair: pair, createdAt: time.Now()}
}

func TestStateFile_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dnscrypt.zst")

	seed, err := newRandomSeed()
	if err != nil {
		t.Fatal(err)
	}
	skBytes, _, err := dnscryptcrypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	sk := ed25519.PrivateKey(skBytes)
	keys := []keyEntry{testKeyEntry(t, &seed)}

	if err := saveStateFile(path, sk, keys); err != nil {
		t.Fatalf("saveStateFile: %v", err)
	}

	gotSK, windows, err := loadStateFile(path)
	if err != nil {
		t.Fatalf("loadStateFile: %v", err)
	}
	if len(gotSK) != 64 {
		t.Errorf("sk len = %d, want 64", len(gotSK))
	}
	if len(windows) != 1 {
		t.Fatalf("windows = %d, want 1", len(windows))
	}
	w := windows[0]
	if w.Serial != keys[0].pair.Classical.Serial || w.NotBefore != keys[0].pair.Classical.NotBefore ||
		w.NotAfter != keys[0].pair.Classical.NotAfter {
		t.Errorf("window mismatch: %+v", w)
	}
	if len(w.ResolverSk) != 32 || len(w.ResolverPk) != 32 {
		t.Errorf("resolver key sizes: sk=%d pk=%d", len(w.ResolverSk), len(w.ResolverPk))
	}
}

func TestStateFile_Missing_ReturnsErrNoIdentity(t *testing.T) {
	_, _, err := loadStateFile(filepath.Join(t.TempDir(), "nope.zst"))
	if !errors.Is(err, errNoIdentity) {
		t.Errorf("want errNoIdentity, got %v", err)
	}
}

func TestStateFile_EmptyPath_ReturnsErrNoIdentity(t *testing.T) {
	_, _, err := loadStateFile("")
	if !errors.Is(err, errNoIdentity) {
		t.Errorf("want errNoIdentity, got %v", err)
	}
}

func TestStateFile_Corrupt_ReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dnscrypt.zst")
	if err := os.WriteFile(path, []byte("corrupt state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadStateFile(path); err == nil {
		t.Fatal("load corrupt state: want error, got nil")
	}
}

func TestStateFile_UnsupportedVersion_ReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dnscrypt.zst")
	// Valid zstd payload with an unsupported version — must be rejected.
	payload := []byte{0, 99, 0, 0, 0, 96, 1, 2, 3} // version=99, identity_len=96
	payload = append(payload, make([]byte, 96)...)
	if err := persist.Save(path, payload); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadStateFile(path); err == nil {
		t.Fatal("unsupported version: want error, got nil")
	}
}

func TestStateFile_SaveEmptyPath_Noop(t *testing.T) {
	seed, err := newRandomSeed()
	if err != nil {
		t.Fatal(err)
	}
	sk, _, _ := dnscryptcrypto.GenerateEd25519Keypair()
	if err := saveStateFile("", sk, []keyEntry{testKeyEntry(t, &seed)}); err != nil {
		t.Fatalf("saveStateFile with empty path: %v", err)
	}
}

func TestResetKeys(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "dnscrypt.zst")
	pkBytes, skBytes, err := dnscryptcrypto.GenerateEd25519Keypair() //nolint:gocritic // (public, private) order
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.DNSCryptCertificate{
		PrivateKey: dnscryptcrypto.HexEncodeKey(skBytes),
		PublicKey:  dnscryptcrypto.HexEncodeKey(pkBytes),
	}
	s, err := New(stateFile, cfg, "12443", "2.dnscrypt-cert.example.com")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	oldResolverPk := s.current().Classical.ResolverPk
	oldSK := append([]byte(nil), s.signingSK...)

	if err := s.ResetKeys(); err != nil {
		t.Fatalf("ResetKeys: %v", err)
	}

	// New cert window with fresh resolver keys (a fresh seed chain makes a
	// different key pair — serial is now-based and can coincide within the
	// same second, the key material cannot); identity unchanged.
	if s.current().Classical.ResolverPk == oldResolverPk {
		t.Error("resolver key unchanged after reset")
	}
	if !bytes.Equal(s.signingSK, oldSK) {
		t.Error("signing identity changed after reset (must stay config-bound)")
	}

	// Persisted immediately: reloading the file yields the new window.
	gotSK, windows, err := loadStateFile(stateFile)
	if err != nil {
		t.Fatalf("loadStateFile: %v", err)
	}
	if len(windows) != 1 || windows[0].Serial != s.current().Classical.Serial {
		t.Errorf("persisted windows = %d (serial=%d), want 1 (serial=%d)",
			len(windows), windows[0].Serial, s.current().Classical.Serial)
	}
	if !bytes.Equal(gotSK, oldSK) {
		t.Error("persisted identity differs from config identity")
	}
}
