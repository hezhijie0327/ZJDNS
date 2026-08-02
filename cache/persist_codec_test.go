package cache

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSave_Load_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.zst")
	f := &PersistFile{
		Version: 1,
		Entries: []PersistEntry{
			{Qname: "example.com.", ECSAddr: "1.2.3.0", ECSPrefix: 24, DNSsecOK: true, Qtype: 1, Qclass: 1, Value: []byte("wire-data"), ExpiresAt: 12345, Validated: true},
			{Qname: "test.org.", Qtype: 28, Qclass: 1, Value: []byte{0xde, 0xad, 0xbe, 0xef}, ExpiresAt: 0, Validated: false},
		},
	}
	if err := f.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Version != 1 {
		t.Errorf("Version = %d, want 1", got.Version)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("len(Entries) = %d, want 2", len(got.Entries))
	}
	for i, want := range f.Entries {
		gotE := got.Entries[i]
		if gotE.Qname != want.Qname || gotE.ECSAddr != want.ECSAddr || gotE.ECSPrefix != want.ECSPrefix ||
			gotE.DNSsecOK != want.DNSsecOK || gotE.Qtype != want.Qtype || gotE.Qclass != want.Qclass {
			t.Errorf("Entry %d key fields mismatch: got %+v want %+v", i, gotE, want)
		}
		if !bytes.Equal(gotE.Value, want.Value) {
			t.Errorf("Entry %d value mismatch: got %q want %q", i, gotE.Value, want.Value)
		}
		if gotE.ExpiresAt != want.ExpiresAt || gotE.Validated != want.Validated {
			t.Errorf("Entry %d mismatch: expires=%d validated=%v", i, gotE.ExpiresAt, gotE.Validated)
		}
	}
}

func TestSave_Load_EmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.zst")
	if err := (&PersistFile{Version: 1}).Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got.Entries) != 0 {
		t.Errorf("want empty file, got %+v", got)
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
	if err := os.WriteFile(path, []byte("this is not a persist file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load on corrupt file: want error, got nil")
	}
}

func TestSave_Overwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.zst")
	f1 := &PersistFile{Version: 1, Entries: []PersistEntry{{Qname: "a.com.", Qtype: 1, Value: []byte("v1")}}}
	if err := f1.Save(path); err != nil {
		t.Fatal(err)
	}
	f2 := &PersistFile{Version: 1, Entries: []PersistEntry{{Qname: "b.com.", Qtype: 1, Value: []byte("v2")}}}
	if err := f2.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 1 || got.Entries[0].Qname != "b.com." {
		t.Errorf("overwrite failed: %+v", got.Entries)
	}
}

func TestSave_MissingDir_ReturnsError(t *testing.T) {
	f := &PersistFile{Version: 1, Entries: []PersistEntry{{Qname: "k", Value: []byte("v")}}}
	err := f.Save(filepath.Join(t.TempDir(), "no", "such", "dir", "state.zst"))
	if err == nil {
		t.Fatal("Save to missing dir: want error, got nil")
	}
}

func TestRoundTrip_LargeValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.zst")
	big := make([]byte, 64<<10) // 64KB — beyond uint16 length, exercises u32 writer
	for i := range big {
		big[i] = byte(i)
	}
	f := &PersistFile{Version: 1, Entries: []PersistEntry{{Qname: "big.example.com.", Qtype: 1, Value: big}}}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries[0].Value) != len(big) {
		t.Fatalf("value len = %d, want %d", len(got.Entries[0].Value), len(big))
	}
	for i, b := range got.Entries[0].Value {
		if b != big[i] {
			t.Fatalf("byte %d = %d, want %d", i, b, big[i])
		}
	}
}

func TestLoad_Truncated_ReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.zst")
	f := &PersistFile{Version: 1, Entries: []PersistEntry{{Qname: "k1.example.", Qtype: 1, Value: []byte("v1")}}}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: test fixture path
	if err != nil {
		t.Fatal(err)
	}
	// Truncate halfway through the compressed payload.
	if err := os.WriteFile(path, data[:len(data)/2], 0o600); err != nil { //nolint:gosec // G703: test fixture path
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load on truncated file: want error, got nil")
	}
}

func TestRoundTrip_ECSAndNoECS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.zst")
	f := &PersistFile{Version: 1, Entries: []PersistEntry{
		{Qname: "ecs.com.", ECSAddr: "2001:db8::", ECSPrefix: 56, DNSsecOK: true, Qtype: 28, Qclass: 1, Value: []byte("v6"), ExpiresAt: 7, Validated: true},
		{Qname: "plain.com.", Qtype: 1, Qclass: 1, Value: []byte("v4")},
	}}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("len = %d, want 2", len(got.Entries))
	}
	if got.Entries[0].ECSAddr != "2001:db8::" || got.Entries[0].ECSPrefix != 56 || !got.Entries[0].DNSsecOK || !got.Entries[0].Validated {
		t.Errorf("ECS entry mismatch: %+v", got.Entries[0])
	}
	if got.Entries[1].ECSAddr != "" || got.Entries[1].ECSPrefix != 0 || got.Entries[1].DNSsecOK {
		t.Errorf("plain entry mismatch: %+v", got.Entries[1])
	}
}
