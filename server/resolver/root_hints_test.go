package resolver

import (
	"os"
	"path/filepath"
	"testing"
)

const testNamedRoot = `
.                        3600000      NS    A.ROOT-SERVERS.NET.
.                        3600000      NS    B.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30
B.ROOT-SERVERS.NET.      3600000      A     170.247.170.2
B.ROOT-SERVERS.NET.      3600000      AAAA  2801:1b8:10::b
; comment line — should be skipped
`

func TestLoadRootHintsFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "named.root")
	if err := os.WriteFile(path, []byte(testNamedRoot), 0o600); err != nil {
		t.Fatal(err)
	}

	hints, err := loadRootHintsFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hints) != 2 {
		t.Fatalf("expected 2 root servers, got %d", len(hints))
	}

	aAddrs := hints["A.ROOT-SERVERS.NET."]
	bAddrs := hints["B.ROOT-SERVERS.NET."]
	if len(aAddrs) != 2 {
		t.Errorf("A.ROOT-SERVERS.NET: expected 2 addrs, got %d", len(aAddrs))
	}
	if len(bAddrs) != 2 {
		t.Errorf("B.ROOT-SERVERS.NET: expected 2 addrs, got %d", len(bAddrs))
	}
}

func TestLoadRootHintsFromFile_NotFound(t *testing.T) {
	_, err := loadRootHintsFromFile("/nonexistent/named.root")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadRootHintsFromFile_Invalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "named.root")
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadRootHintsFromFile(path)
	if err == nil {
		t.Error("expected error for file with no root servers")
	}
}

func TestLoadRootHintsFromFile_NoRootNS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "named.root")
	// Only A records, no NS records for "." — no root servers.
	if err := os.WriteFile(path, []byte("A.ROOT-SERVERS.NET. 3600000 A 198.41.0.4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadRootHintsFromFile(path)
	if err == nil {
		t.Error("expected error when no root NS records found")
	}
}
