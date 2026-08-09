package snapfile

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func writeTestEntry(w io.Writer, key string, val uint32) error {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(key))) //nolint:gosec // G115: test keys are short
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := io.WriteString(w, key); err != nil {
		return err
	}
	var valBuf [4]byte
	binary.BigEndian.PutUint32(valBuf[:], val)
	_, err := w.Write(valBuf[:])
	return err
}

func readTestEntry(r io.Reader) (key string, val uint32, err error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", 0, err
	}
	keyBuf := make([]byte, int(binary.BigEndian.Uint16(lenBuf[:])))
	if _, err := io.ReadFull(r, keyBuf); err != nil {
		return "", 0, err
	}
	var valBuf [4]byte
	if _, err := io.ReadFull(r, valBuf[:]); err != nil {
		return "", 0, err
	}
	return string(keyBuf), binary.BigEndian.Uint32(valBuf[:]), nil
}

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.snap")

	entries := map[string]uint32{"a": 1, "b": 2, "c": 3}
	err := Save(path, 1, func(w io.Writer) error {
		for k, v := range entries {
			if err := writeTestEntry(w, k, v); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	got := map[string]uint32{}
	err = Load(path, 1, func(r io.Reader) error {
		k, v, err := readTestEntry(r)
		if err != nil {
			return err
		}
		got[k] = v
		return nil
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != len(entries) {
		t.Fatalf("loaded %d entries, want %d", len(got), len(entries))
	}
	for k, v := range entries {
		if got[k] != v {
			t.Errorf("entry %s = %d, want %d", k, got[k], v)
		}
	}
}

func TestMissingFile(t *testing.T) {
	err := Load(filepath.Join(t.TempDir(), "missing.snap"), 1, func(r io.Reader) error {
		t.Fatal("readEntry must not be called for a missing file")
		return nil
	})
	if err != nil {
		t.Fatalf("Load missing: %v", err)
	}
}

func TestWrongMagicAndVersion(t *testing.T) {
	dir := t.TempDir()

	garbage := filepath.Join(dir, "garbage.snap")
	if err := os.WriteFile(garbage, []byte("not a snapshot"), 0o600); err != nil { //nolint:gosec // G306: test file
		t.Fatal(err)
	}
	if err := Load(garbage, 1, func(r io.Reader) error {
		t.Fatal("readEntry must not be called for garbage")
		return nil
	}); err != nil {
		t.Fatalf("Load garbage: %v", err)
	}

	wrongVer := filepath.Join(dir, "wrongver.snap")
	entries := map[string]uint32{"x": 1}
	if err := Save(wrongVer, 1, func(w io.Writer) error {
		for k, v := range entries {
			return writeTestEntry(w, k, v)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := Load(wrongVer, 2, func(r io.Reader) error {
		t.Fatal("readEntry must not be called for wrong version")
		return nil
	}); err != nil {
		t.Fatalf("Load wrong version: %v", err)
	}
}
