package dnscrypt

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
	"zjdns/config"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"
	"zjdns/internal/lrumap"
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

// testCertConfig returns a DNSCrypt certificate config with fresh keys.
func testCertConfig(t *testing.T) *config.DNSCryptCertificate {
	t.Helper()
	pkBytes, skBytes, err := dnscryptcrypto.GenerateEd25519Keypair() //nolint:gocritic // (public, private) order
	if err != nil {
		t.Fatal(err)
	}
	return &config.DNSCryptCertificate{
		PrivateKey: dnscryptcrypto.HexEncodeKey(skBytes),
		PublicKey:  dnscryptcrypto.HexEncodeKey(pkBytes),
	}
}

// testServer builds a DNSCrypt server on a temp state file.
func testServer(t *testing.T, stateFile string) *Server {
	t.Helper()
	s, err := New(stateFile, testCertConfig(t), "12443", "2.dnscrypt-cert.example.com")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestState_RoundTrip(t *testing.T) {
	// Codec-level round trip via the shared lrumap persistence.
	file := filepath.Join(t.TempDir(), "dnscrypt.zst")
	pk, sk, err := dnscryptcrypto.GenerateEd25519Keypair() //nolint:gocritic // (public, private) order
	if err != nil {
		t.Fatal(err)
	}
	identity := append(append([]byte{}, sk...), pk...)
	seed, err := newRandomSeed()
	if err != nil {
		t.Fatal(err)
	}
	entry := testKeyEntry(t, &seed)
	c := entry.pair.Classical

	m := lrumap.New[string, dnscryptState](1)
	if _, err := m.EnablePersist(lrumap.PersistConfig[string, dnscryptState]{
		Path:  file,
		Codec: dnscryptCodec{},
	}); err != nil {
		t.Fatalf("EnablePersist: %v", err)
	}
	m.Set("state", dnscryptState{
		identity: identity,
		windows: []windowRecord{{
			Serial:     c.Serial,
			NotBefore:  c.NotBefore,
			NotAfter:   c.NotAfter,
			ResolverSk: c.ResolverSk[:],
			ResolverPk: c.ResolverPk[:],
		}},
	})
	if err := m.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	m2 := lrumap.New[string, dnscryptState](1)
	n, err := m2.EnablePersist(lrumap.PersistConfig[string, dnscryptState]{
		Path:  file,
		Codec: dnscryptCodec{},
	})
	if err != nil {
		t.Fatalf("EnablePersist (2): %v", err)
	}
	if n != 1 {
		t.Errorf("EnablePersist returned %d, want 1", n)
	}
	st, ok := m2.Get("state")
	if !ok {
		t.Fatal("state not restored")
	}
	if !bytes.Equal(st.identity, identity) {
		t.Error("identity mismatch after round trip")
	}
	if len(st.windows) != 1 || st.windows[0].Serial != c.Serial {
		t.Errorf("windows = %d (serial=%d), want 1 (serial=%d)", len(st.windows), st.windows[0].Serial, c.Serial)
	}
}

func TestState_ServerRoundTrip(t *testing.T) {
	// Full server path: identity + windows survive Save → reload.
	stateFile := filepath.Join(t.TempDir(), "dnscrypt.zst")
	cfg := testCertConfig(t)
	s1, err := New(stateFile, cfg, "12443", "2.dnscrypt-cert.example.com")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s1.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	s2, err := New(stateFile, cfg, "12443", "2.dnscrypt-cert.example.com")
	if err != nil {
		t.Fatalf("New (2): %v", err)
	}
	if !bytes.Equal(s2.signingSK, s1.signingSK) {
		t.Error("signing identity not restored")
	}
	if s2.current().Classical.Serial != s1.current().Classical.Serial {
		t.Errorf("cert window not restored: serial %d != %d", s2.current().Classical.Serial, s1.current().Classical.Serial)
	}
}

func TestState_ConfigKeyChanged_DropsState(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "dnscrypt.zst")
	cfg1 := testCertConfig(t)
	s1, err := New(stateFile, cfg1, "12443", "2.dnscrypt-cert.example.com")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s1.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Different config key: the persisted state must be dropped, a fresh
	// identity generated from the new config.
	cfg2 := testCertConfig(t)
	s2, err := New(stateFile, cfg2, "12443", "2.dnscrypt-cert.example.com")
	if err != nil {
		t.Fatalf("New (2): %v", err)
	}
	if bytes.Equal(s2.signingSK, s1.signingSK) {
		t.Error("identity should have switched with the config key")
	}
}

func TestState_MissingFile_GeneratesIdentity(t *testing.T) {
	s := testServer(t, filepath.Join(t.TempDir(), "missing.zst"))
	if len(s.signingSK) != 64 {
		t.Errorf("signingSK len = %d, want 64 (generated from config)", len(s.signingSK))
	}
}

func TestState_EmptyPath_NoPersistence(t *testing.T) {
	s, err := New("", testCertConfig(t), "12443", "2.dnscrypt-cert.example.com")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Save(); err != nil {
		t.Fatalf("Save with empty path: %v", err)
	}
}

func TestState_Corrupt_BackedUpAndRebuilt(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "dnscrypt.zst")
	s1 := testServer(t, stateFile)
	if err := s1.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	data, err := os.ReadFile(stateFile) //nolint:gosec // G304: test fixture
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stateFile, data[:len(data)/2], 0o600); err != nil { //nolint:gosec // G703: test fixture
		t.Fatal(err)
	}

	// Corrupt state: server starts fresh (identity from config), old file
	// preserved as .bak.
	s2, err := New(stateFile, testCertConfig(t), "12443", "2.dnscrypt-cert.example.com")
	if err != nil {
		t.Fatalf("New on corrupt state: %v", err)
	}
	if len(s2.signingSK) != 64 {
		t.Error("server did not rebuild an identity after corrupt state")
	}
	if _, err := os.Stat(stateFile + ".bak"); err != nil {
		t.Errorf("corrupt state not backed up: %v", err)
	}
}

func TestResetKeys(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "dnscrypt.zst")
	cfg := testCertConfig(t)
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

	// Persisted immediately: a fresh server on the same file restores the
	// new window.
	s2, err := New(stateFile, cfg, "12443", "2.dnscrypt-cert.example.com")
	if err != nil {
		t.Fatalf("New (2): %v", err)
	}
	if s2.current().Classical.ResolverPk != s.current().Classical.ResolverPk {
		t.Error("reset window not persisted")
	}
}
