package lrumap

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// stringCodec is a minimal Codec for testing.
type stringCodec struct{ version uint16 }

// skipEvenCodec wraps stringCodec and drops even values on load.
type skipEvenCodec struct{ stringCodec }

// ── Weighted eviction ──────────────────────────────────────────────────────

func TestSetWeight_EvictsByWeight(t *testing.T) {
	m := New[string, []byte](100) // count capacity 100 — weight must override it
	m.SetWeight(30, func(v []byte) int64 { return int64(len(v)) })

	m.Set("a", []byte("1234567890")) // 10
	m.Set("b", []byte("1234567890")) // 10
	m.Set("c", []byte("1234567890")) // 10 → total 30, at budget
	if m.Len() != 3 {
		t.Fatalf("Len = %d, want 3 at budget", m.Len())
	}
	m.Set("d", []byte("1234567890")) // evicts a → total 30 again
	if m.Len() != 3 {
		t.Fatalf("Len = %d, want 3 after eviction", m.Len())
	}
	if _, ok := m.Get("a"); ok {
		t.Error("a should have been evicted (LRU by weight)")
	}
	for _, k := range []string{"b", "c", "d"} {
		if _, ok := m.Get(k); !ok {
			t.Errorf("key %q should be present", k)
		}
	}
	if w := m.TotalWeight(); w != 30 {
		t.Errorf("TotalWeight = %d, want 30", w)
	}
}

func TestSetWeight_SingleValueHeavierThanBudget(t *testing.T) {
	m := New[string, []byte](10)
	m.SetWeight(5, func(v []byte) int64 { return int64(len(v)) })

	m.Set("a", []byte("123"))          // 3
	m.Set("big", []byte("1234567890")) // 10 > 5 — evicts a, stores big anyway
	if m.Len() != 1 {
		t.Fatalf("Len = %d, want 1 (oversized value still stored)", m.Len())
	}
	if _, ok := m.Get("big"); !ok {
		t.Error("big should be present")
	}
	if w := m.TotalWeight(); w != 10 {
		t.Errorf("TotalWeight = %d, want 10", w)
	}
}

func TestSetWeight_UpdateAdjustsWeight(t *testing.T) {
	m := New[string, []byte](10)
	m.SetWeight(20, func(v []byte) int64 { return int64(len(v)) })

	m.Set("a", []byte("1234567890"))           // 10
	m.Set("a", []byte("12345678901234567890")) // update to 20
	if w := m.TotalWeight(); w != 20 {
		t.Errorf("TotalWeight = %d, want 20 after update", w)
	}
	m.Set("b", []byte("1")) // evicts a (20 > 20-1)
	if _, ok := m.Get("a"); ok {
		t.Error("a should have been evicted after weight grew")
	}
	if w := m.TotalWeight(); w != 1 {
		t.Errorf("TotalWeight = %d, want 1", w)
	}
}

func TestSetWeight_DeleteSubtractsWeight(t *testing.T) {
	m := New[string, []byte](10)
	m.SetWeight(100, func(v []byte) int64 { return int64(len(v)) })

	m.Set("a", []byte("12345"))
	m.Set("b", []byte("12345"))
	m.Delete("a")
	if w := m.TotalWeight(); w != 5 {
		t.Errorf("TotalWeight = %d, want 5 after delete", w)
	}
	m.Clear()
	if w := m.TotalWeight(); w != 0 {
		t.Errorf("TotalWeight = %d, want 0 after clear", w)
	}
}

// ── Persistence ────────────────────────────────────────────────────────────

func (c stringCodec) Version() uint16 { return c.version }

func (stringCodec) EncodeKey(k string) []byte {
	return []byte("k:" + k)
}

func (stringCodec) EncodeValue(v int) []byte {
	return []byte("v:" + strconv.Itoa(v))
}

func (stringCodec) DecodeKey(b []byte) (string, error) {
	s := string(b)
	if !strings.HasPrefix(s, "k:") {
		return "", errors.New("bad key")
	}
	return s[2:], nil
}

func (stringCodec) DecodeValue(b []byte) (v int, include bool, err error) {
	s := string(b)
	if !strings.HasPrefix(s, "v:") {
		return 0, false, errors.New("bad value")
	}
	n, err := strconv.Atoi(s[2:])
	if err != nil {
		return 0, false, err
	}
	return n, true, nil
}

func (skipEvenCodec) DecodeValue(b []byte) (v int, include bool, err error) {
	v, _, err = stringCodec{}.DecodeValue(b)
	return v, v%2 == 1, err
}

func TestPersist_RoundTrip(t *testing.T) {
	file := filepath.Join(t.TempDir(), "test.zst")
	m := New[string, int](10)
	m.Set("a", 1)
	m.Set("b", 2)
	if err := m.EnablePersist(PersistConfig[string, int]{Path: file, Codec: stringCodec{version: 1}}); err != nil {
		t.Fatalf("EnablePersist: %v", err)
	}
	// Save after load — file now exists with all entries.
	if err := m.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	m.Set("c", 3)
	if err := m.Save(); err != nil {
		t.Fatalf("Save (2): %v", err)
	}

	m2 := New[string, int](10)
	if err := m2.EnablePersist(PersistConfig[string, int]{Path: file, Codec: stringCodec{version: 1}}); err != nil {
		t.Fatalf("EnablePersist (2): %v", err)
	}
	for k, want := range map[string]int{"a": 1, "b": 2, "c": 3} {
		if v, ok := m2.Get(k); !ok || v != want {
			t.Errorf("Get(%q) = %d, %v; want %d, true", k, v, ok, want)
		}
	}
}

func TestPersist_LoadPreservesOrder(t *testing.T) {
	file := filepath.Join(t.TempDir(), "test.zst")
	m := New[string, int](5)
	for i := range 5 {
		m.Set(strconv.Itoa(i), i)
	}
	// Access "0" — it becomes most recent and is saved first.
	m.Get("0")
	if err := m.EnablePersist(PersistConfig[string, int]{Path: file, Codec: stringCodec{version: 1}}); err != nil {
		t.Fatalf("EnablePersist: %v", err)
	}
	if err := m.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	m2 := New[string, int](5)
	if err := m2.EnablePersist(PersistConfig[string, int]{Path: file, Codec: stringCodec{version: 1}}); err != nil {
		t.Fatalf("EnablePersist (2): %v", err)
	}
	// After reload, "0" must be the most recently used entry: inserting a new
	// key evicts "1" (the original LRU), not "0".
	m2.Set("new", 42)
	if _, ok := m2.Get("0"); !ok {
		t.Error("0 should still be present (hot entry preserved across restart)")
	}
	if _, ok := m2.Get("1"); ok {
		t.Error("1 should have been evicted (was LRU at save time)")
	}
}

func TestPersist_ColdStartMissingFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "missing.zst")
	m := New[string, int](10)
	if err := m.EnablePersist(PersistConfig[string, int]{Path: file, Codec: stringCodec{version: 1}}); err != nil {
		t.Fatalf("EnablePersist on missing file: %v", err)
	}
	if m.Len() != 0 {
		t.Errorf("Len = %d, want 0 (cold start)", m.Len())
	}
}

func TestPersist_VersionMismatch(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "test.zst")
	m := New[string, int](10)
	m.Set("a", 1)
	if err := m.EnablePersist(PersistConfig[string, int]{Path: file, Codec: stringCodec{version: 1}}); err != nil {
		t.Fatalf("EnablePersist: %v", err)
	}
	if err := m.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	orig, err := os.ReadFile(file) //nolint:gosec // G304: test fixture
	if err != nil {
		t.Fatal(err)
	}

	m2 := New[string, int](10)
	err = m2.EnablePersist(PersistConfig[string, int]{Path: file, Codec: stringCodec{version: 2}})
	if !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("EnablePersist with wrong version: got %v, want ErrVersionMismatch", err)
	}
	if m2.Len() != 0 {
		t.Errorf("Len = %d, want 0 (mismatched file skipped)", m2.Len())
	}
	// The old file must be backed up, not destroyed.
	backup, err := os.ReadFile(file + ".bak") //nolint:gosec // G304: test fixture
	if err != nil {
		t.Fatalf("old file not backed up: %v", err)
	}
	if !bytes.Equal(backup, orig) {
		t.Error("backup content differs from the original file")
	}
}

func TestPersist_CorruptFileBackedUp(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "test.zst")
	m := New[string, int](10)
	m.Set("a", 1)
	if err := m.EnablePersist(PersistConfig[string, int]{Path: file, Codec: stringCodec{version: 1}}); err != nil {
		t.Fatalf("EnablePersist: %v", err)
	}
	if err := m.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Corrupt the file (truncate the compressed payload).
	data, err := os.ReadFile(file) //nolint:gosec // G304: test fixture
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data[:len(data)/2], 0o600); err != nil { //nolint:gosec // G703: test fixture
		t.Fatal(err)
	}

	m2 := New[string, int](10)
	if err := m2.EnablePersist(PersistConfig[string, int]{Path: file, Codec: stringCodec{version: 1}}); err == nil {
		t.Fatal("EnablePersist on corrupt file should error")
	}
	if m2.Len() != 0 {
		t.Errorf("Len = %d, want 0 (corrupt file skipped)", m2.Len())
	}
	if _, err := os.Stat(file + ".bak"); err != nil {
		t.Errorf("corrupt file not backed up: %v", err)
	}
}

func TestPersist_DecodeSkipFilter(t *testing.T) {
	file := filepath.Join(t.TempDir(), "test.zst")
	m := New[string, int](10)
	m.Set("a", 2)
	m.Set("b", 3)
	if err := m.EnablePersist(PersistConfig[string, int]{Path: file, Codec: stringCodec{version: 1}}); err != nil {
		t.Fatalf("EnablePersist: %v", err)
	}
	if err := m.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	m2 := New[string, int](10)
	err := m2.EnablePersist(PersistConfig[string, int]{Path: file, Codec: skipEvenCodec{stringCodec{version: 1}}})
	if err != nil {
		t.Fatalf("EnablePersist with skip codec: %v", err)
	}
	if _, ok := m2.Get("a"); ok {
		t.Error("even value should have been skipped by DecodeValue")
	}
	if _, ok := m2.Get("b"); !ok {
		t.Error("odd value should have been loaded")
	}
}

func TestPersist_KeepFilterOnSave(t *testing.T) {
	file := filepath.Join(t.TempDir(), "test.zst")
	m := New[string, int](10)
	m.Set("keep", 1)
	m.Set("drop", 2)
	err := m.EnablePersist(PersistConfig[string, int]{
		Path:  file,
		Codec: stringCodec{version: 1},
		Keep:  func(k string, _ int) bool { return k == "keep" },
	})
	if err != nil {
		t.Fatalf("EnablePersist: %v", err)
	}
	if err := m.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	m2 := New[string, int](10)
	if err := m2.EnablePersist(PersistConfig[string, int]{Path: file, Codec: stringCodec{version: 1}}); err != nil {
		t.Fatalf("EnablePersist (2): %v", err)
	}
	if _, ok := m2.Get("keep"); !ok {
		t.Error("keep entry should be persisted")
	}
	if _, ok := m2.Get("drop"); ok {
		t.Error("drop entry should have been filtered out by Keep")
	}
}
