package dnscrypt

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.bin")
	s := NewFileStore(path)

	identity := bytes.Repeat([]byte{0xAB}, 96)
	windows := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	if err := s.SaveDNSCryptState(identity, windows); err != nil {
		t.Fatalf("Save: %v", err)
	}

	gotID, gotWin, err := s.LoadDNSCryptState()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(gotID, identity) {
		t.Error("identity mismatch after round-trip")
	}
	if !bytes.Equal(gotWin, windows) {
		t.Error("windows mismatch after round-trip")
	}
}

func TestLoadMissingFile(t *testing.T) {
	s := NewFileStore(filepath.Join(t.TempDir(), "nonexistent.bin"))
	id, win, err := s.LoadDNSCryptState()
	if err != nil {
		t.Fatalf("Load missing file: %v", err)
	}
	if id != nil || win != nil {
		t.Error("missing file should return nil, nil")
	}
}

func TestLoadCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.bin")
	s := NewFileStore(path)

	// Wrong version byte.
	if err := s.SaveDNSCryptState(bytes.Repeat([]byte{1}, 96), nil); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path) //nolint:gosec // G304: test temp file
	data[0] = 99
	if err := os.WriteFile(path, data, 0o600); err != nil { //nolint:gosec // G703: test temp file
		t.Fatal(err)
	}
	if _, _, err := s.LoadDNSCryptState(); err == nil {
		t.Error("corrupt version byte should error")
	}

	// Wrong identity length on save.
	if err := s.SaveDNSCryptState(make([]byte, 95), nil); err == nil {
		t.Error("short identity should error")
	}
}
