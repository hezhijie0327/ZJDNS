package stats

import (
	"path/filepath"
	"testing"
)

func TestPersist_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.zst")

	c := New()
	c.Record(&Request{Protocol: "udp", Result: "hit", ResponseTime: 5, Rcode: 0})
	c.Record(&Request{Protocol: "tls", Result: "miss", ResponseTime: 12, Rcode: 2})
	if err := c.SavePersist(path); err != nil {
		t.Fatalf("SavePersist: %v", err)
	}

	got := New()
	if err := got.LoadPersist(path); err != nil {
		t.Fatalf("LoadPersist: %v", err)
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
	if err := c.SavePersist(path); err != nil {
		t.Fatal(err)
	}

	got := New()
	got.Record(&Request{Protocol: "tcp", Result: "miss", ResponseTime: 7, Rcode: 3})
	if err := got.LoadPersist(path); err != nil {
		t.Fatal(err)
	}
	if got.total.Load() != 2 {
		t.Errorf("total = %d, want 2 (merge)", got.total.Load())
	}
	if got.udp.Load() != 1 || got.tcp.Load() != 1 {
		t.Errorf("udp/tcp = %d/%d, want 1/1", got.udp.Load(), got.tcp.Load())
	}
}

func TestPersist_EmptyPath_Noop(t *testing.T) {
	c := New()
	if err := c.SavePersist(""); err != nil {
		t.Errorf("SavePersist empty path: %v", err)
	}
	if err := c.LoadPersist(""); err != nil {
		t.Errorf("LoadPersist empty path: %v", err)
	}
}

func TestPersist_MissingFile_ColdStart(t *testing.T) {
	c := New()
	if err := c.LoadPersist(filepath.Join(t.TempDir(), "nope.zst")); err != nil {
		t.Fatalf("LoadPersist missing: %v", err)
	}
	if c.total.Load() != 0 {
		t.Errorf("total = %d, want 0 (cold start)", c.total.Load())
	}
}

func TestPersist_Corrupt_ReturnsError(t *testing.T) {
	c := New()
	err := c.LoadPersist(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatalf("missing file should be nil, got %v", err)
	}
}
