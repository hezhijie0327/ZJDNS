package stats

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPersist_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.zst")

	c := New()
	c.Record(&Request{Protocol: "udp", Result: "hit", ResponseTime: 5, Rcode: 0})
	c.Record(&Request{Protocol: "tls", Result: "miss", ResponseTime: 12, Rcode: 2})
	if n, err := c.SetPersist(path); err != nil {
		t.Fatalf("SetPersist: %v", err)
	} else if n != 0 {
		t.Errorf("SetPersist on fresh file returned %d, want 0", n)
	}
	if err := c.SavePersist(); err != nil {
		t.Fatalf("SavePersist: %v", err)
	}

	got := New()
	n, err := got.SetPersist(path)
	if err != nil {
		t.Fatalf("SetPersist (2): %v", err)
	}
	if n != 1 {
		t.Errorf("SetPersist returned %d, want 1 (snapshot restored)", n)
	}
	if got.total.Load() != 2 {
		t.Errorf("total = %d, want 2", got.total.Load())
	}
	if got.hit.Load() != 1 || got.miss.Load() != 1 {
		t.Errorf("hit/miss = %d/%d, want 1/1", got.hit.Load(), got.miss.Load())
	}
	if got.udp.Load() != 1 || got.tls.Load() != 1 {
		t.Errorf("udp/tls = %d/%d, want 1/1", got.udp.Load(), got.tls.Load())
	}
	if got.rCode[0].Load() != 1 || got.rCode[2].Load() != 1 {
		t.Errorf("rCode[0]/[2] = %d/%d, want 1/1", got.rCode[0].Load(), got.rCode[2].Load())
	}
	if got.latTotal.Load() != 2 {
		t.Errorf("latTotal = %d, want 2 (requests in histogram)", got.latTotal.Load())
	}
}

func TestPersist_Merge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.zst")

	c := New()
	c.Record(&Request{Protocol: "udp", Result: "hit", ResponseTime: 5, Rcode: 0})
	if _, err := c.SetPersist(path); err != nil {
		t.Fatal(err)
	}
	if err := c.SavePersist(); err != nil {
		t.Fatal(err)
	}

	got := New()
	got.Record(&Request{Protocol: "tcp", Result: "miss", ResponseTime: 7, Rcode: 3})
	if _, err := got.SetPersist(path); err != nil {
		t.Fatal(err)
	}
	if got.total.Load() != 2 {
		t.Errorf("total = %d, want 2 (merge)", got.total.Load())
	}
	if got.udp.Load() != 1 || got.tcp.Load() != 1 {
		t.Errorf("udp/tcp = %d/%d, want 1/1", got.udp.Load(), got.tcp.Load())
	}
}

func TestPersist_NoPersistConfigured_Noop(t *testing.T) {
	c := New()
	if err := c.SavePersist(); err != nil {
		t.Errorf("SavePersist without SetPersist: %v", err)
	}
	if _, err := c.SetPersist(""); err != nil {
		t.Errorf("SetPersist empty path: %v", err)
	}
}

func TestPersist_MissingFile_ColdStart(t *testing.T) {
	c := New()
	n, err := c.SetPersist(filepath.Join(t.TempDir(), "nope.zst"))
	if err != nil {
		t.Fatalf("SetPersist missing: %v", err)
	}
	if n != 0 {
		t.Errorf("SetPersist returned %d, want 0 (cold start)", n)
	}
	if c.total.Load() != 0 {
		t.Errorf("total = %d, want 0 (cold start)", c.total.Load())
	}
}

func TestPersist_VersionMismatch_BackedUp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.zst")

	c := New()
	c.Record(&Request{Protocol: "udp", Result: "hit", ResponseTime: 5, Rcode: 0})
	if _, err := c.SetPersist(path); err != nil {
		t.Fatal(err)
	}
	if err := c.SavePersist(); err != nil {
		t.Fatal(err)
	}
	orig, err := os.ReadFile(path) //nolint:gosec // G304: test fixture
	if err != nil {
		t.Fatal(err)
	}

	// Truncate the file — a corrupt snapshot must be backed up, not silently
	// overwritten by the next save.
	if err := os.WriteFile(path, orig[:len(orig)/2], 0o600); err != nil { //nolint:gosec // G703: test fixture
		t.Fatal(err)
	}
	if _, err := c.SetPersist(path); err == nil {
		t.Fatal("SetPersist on corrupt file should error")
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Errorf("corrupt file not backed up: %v", err)
	}
}
