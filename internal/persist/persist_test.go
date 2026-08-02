package persist

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSave_Load_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.zst")
	data := []byte("hello persist")
	if err := Save(path, data); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("got %q, want %q", got, data)
	}
}

func TestSave_Load_Binary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.zst")
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i * 31) //nolint:gosec // G115: test pattern, value intentionally wraps
	}
	if err := Save(path, data); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(data) {
		t.Fatalf("len = %d, want %d", len(got), len(data))
	}
	for i, b := range got {
		if b != data[i] {
			t.Fatalf("byte %d = %d, want %d", i, b, data[i])
		}
	}
}

func TestLoad_MissingFile_ReturnsNil(t *testing.T) {
	got, err := Load(filepath.Join(t.TempDir(), "nope.zst"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != nil {
		t.Errorf("got %v, want nil (cold start)", got)
	}
}

func TestLoad_Corrupt_ReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.zst")
	if err := os.WriteFile(path, []byte("not zstd at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load on corrupt file: want error, got nil")
	}
}

func TestSave_Overwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.zst")
	if err := Save(path, []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, []byte("v2")); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "v2" {
		t.Errorf("got %q, want v2", got)
	}
}

func TestSave_MissingDir_ReturnsError(t *testing.T) {
	err := Save(filepath.Join(t.TempDir(), "no", "such", "dir", "state.zst"), []byte("x"))
	if err == nil {
		t.Fatal("Save to missing dir: want error, got nil")
	}
}

func TestSave_EmptyData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.zst")
	if err := Save(path, nil); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}
