package spillfile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func tmpPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "spill.bin")
}

func TestPutGet(t *testing.T) {
	path := tmpPath(t)
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	for i := range 3 {
		key := fmt.Sprintf("example.com.\x00%d\x00%d\x00\x0016", i, i+1)
		wire := bytes.Repeat([]byte{byte(i)}, 100+i*50)
		if err := st.Put(key, 1700000000+int64(i), 300+i, i%2 == 0, wire); err != nil {
			t.Fatal(err)
		}
	}

	for i := range 3 {
		key := fmt.Sprintf("example.com.\x00%d\x00%d\x00\x0016", i, i+1)
		ts, ttl, validated, wire, ok := st.Get(key)
		if !ok {
			t.Fatalf("key %d missing", i)
		}
		if ts != 1700000000+int64(i) || ttl != 300+i || validated != (i%2 == 0) {
			t.Fatalf("key %d metadata mismatch: ts=%d ttl=%d validated=%t", i, ts, ttl, validated)
		}
		if !bytes.Equal(wire, bytes.Repeat([]byte{byte(i)}, 100+i*50)) {
			t.Fatalf("key %d wire mismatch", i)
		}
	}

	if got := st.EntryCount(); got != 3 {
		t.Fatalf("EntryCount = %d, want 3", got)
	}
	if _, _, _, _, ok := st.Get("missing"); ok {
		t.Fatal("missing key returned ok")
	}
}

func TestOpenRebuildsIndex(t *testing.T) {
	path := tmpPath(t)
	st, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put("a", 100, 10, true, []byte("wire-a")); err != nil {
		t.Fatal(err)
	}
	if err := st.Put("b", 200, 20, false, []byte("wire-b")); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st2.Close() }()
	if got := st2.EntryCount(); got != 2 {
		t.Fatalf("EntryCount = %d, want 2", got)
	}
	_, _, validated, wire, ok := st2.Get("a")
	if !ok || !validated || string(wire) != "wire-a" {
		t.Fatalf("key a wrong after reopen: ok=%t validated=%t wire=%q", ok, validated, wire)
	}
	if _, _, _, _, ok := st2.Get("b"); !ok {
		t.Fatal("key b missing after reopen")
	}
}

func TestOpenDedupNewestTs(t *testing.T) {
	path := tmpPath(t)
	st, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put("dup", 100, 10, false, []byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := st.Put("dup", 200, 20, true, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st2.Close() }()
	if got := st2.EntryCount(); got != 1 {
		t.Fatalf("EntryCount = %d, want 1 (dedup)", got)
	}
	ts, ttl, validated, wire, ok := st2.Get("dup")
	if !ok || ts != 200 || ttl != 20 || !validated || string(wire) != "new" {
		t.Fatalf("dedup picked wrong record: ts=%d ttl=%d validated=%t wire=%q ok=%t", ts, ttl, validated, wire, ok)
	}
}

func TestOpenTruncatedTail(t *testing.T) {
	path := tmpPath(t)
	st, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put("good", 100, 10, false, []byte("wire-good")); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// Append a partial record manually.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // G304: test temp file
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0x00, 0x03, 'x', 'y'}); err != nil { // key_len + half a key
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st2.Close() }()
	if got := st2.EntryCount(); got != 1 {
		t.Fatalf("EntryCount = %d, want 1 (truncated record dropped)", got)
	}
	if _, _, _, wire, ok := st2.Get("good"); !ok || string(wire) != "wire-good" {
		t.Fatalf("good record lost: ok=%t wire=%q", ok, wire)
	}
	// Appends must continue after the truncation point.
	if err := st2.Put("after", 300, 30, true, []byte("wire-after")); err != nil {
		t.Fatal(err)
	}
	if _, _, _, wire, ok := st2.Get("after"); !ok || string(wire) != "wire-after" {
		t.Fatal("append after truncation failed")
	}
}

func TestOpenForeignHeader(t *testing.T) {
	path := tmpPath(t)
	if err := os.WriteFile(path, []byte("ZJNS\x02garbage"), 0o644); err != nil { //nolint:gosec // G306: test fixture
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("foreign magic accepted")
	}
}

func TestCompact(t *testing.T) {
	path := tmpPath(t)
	st, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if err := st.Put(fmt.Sprintf("k%d", i), int64(1000+i), 300, true, fmt.Appendf(nil, "wire-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	// Keep only k1..k3 (oldest first traversal: k0, k1, k2...).
	if err := st.Compact(func(key string, _ int64, _ int) bool { //nolint:unparam // ts/ttl unused in test
		return key != "k0" && key != "k4"
	}); err != nil {
		t.Fatal(err)
	}
	if got := st.EntryCount(); got != 3 {
		t.Fatalf("EntryCount = %d, want 3", got)
	}
	for i := 1; i <= 3; i++ {
		if _, _, _, wire, ok := st.Get(fmt.Sprintf("k%d", i)); !ok || string(wire) != fmt.Sprintf("wire-%d", i) {
			t.Fatalf("k%d lost after compact: ok=%t wire=%q", i, ok, wire)
		}
	}
	if _, _, _, _, ok := st.Get("k0"); ok {
		t.Fatal("k0 survived compact")
	}
	// Reopen — the rewritten file must be self-consistent.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st2.Close() }()
	if got := st2.EntryCount(); got != 3 {
		t.Fatalf("EntryCount after reopen = %d, want 3", got)
	}
	if _, _, _, wire, ok := st2.Get("k2"); !ok || string(wire) != "wire-2" {
		t.Fatal("k2 lost after reopen")
	}
}

func TestCompactKeepOldestNDrops(t *testing.T) {
	// Server-side cap pattern: compute the drop set from Entries(), then
	// pass a keep predicate.
	path := tmpPath(t)
	st, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	for i := range 5 {
		if err := st.Put(fmt.Sprintf("k%d", i), int64(1000+i), 300, true, []byte("w")); err != nil {
			t.Fatal(err)
		}
	}
	entries := st.Entries()
	drop := map[string]bool{}
	for _, e := range entries {
		if e.Ts < 1003 { // drop the 3 oldest
			drop[e.Key] = true
		}
	}
	if err := st.Compact(func(key string, _ int64, _ int) bool { return !drop[key] }); err != nil {
		t.Fatal(err)
	}
	if got := st.EntryCount(); got != 2 {
		t.Fatalf("EntryCount = %d, want 2", got)
	}
	for i := 3; i <= 4; i++ {
		if _, _, _, _, ok := st.Get(fmt.Sprintf("k%d", i)); !ok {
			t.Fatalf("k%d missing", i)
		}
	}
}

func TestClear(t *testing.T) {
	path := tmpPath(t)
	st, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if err := st.Put("a", 100, 10, false, []byte("w")); err != nil {
		t.Fatal(err)
	}
	if err := st.Clear(); err != nil {
		t.Fatal(err)
	}
	if got := st.EntryCount(); got != 0 {
		t.Fatalf("EntryCount = %d, want 0", got)
	}
	if _, _, _, _, ok := st.Get("a"); ok {
		t.Fatal("cleared key still present")
	}
	if size := st.FileSize(); size != int64(headerLen) {
		t.Fatalf("FileSize = %d, want %d", size, headerLen)
	}
	if err := st.Put("b", 200, 20, true, []byte("w2")); err != nil {
		t.Fatal(err)
	}
	if _, _, _, wire, ok := st.Get("b"); !ok || string(wire) != "w2" {
		t.Fatal("Put after Clear failed")
	}
}

func TestCorruptMiddleRecord(t *testing.T) {
	path := tmpPath(t)
	st, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put("good", 100, 10, false, []byte("w1")); err != nil {
		t.Fatal(err)
	}
	if err := st.Put("evil", 200, 20, false, []byte("w2")); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// Corrupt the wire length of the second record (impossible size).
	f, err := os.OpenFile(path, os.O_RDWR, 0) //nolint:gosec // G304: test temp file
	if err != nil {
		t.Fatal(err)
	}
	evilStart := int64(headerLen + recordHeaderLen + len("good") + len("w1"))
	wireLenOff := evilStart + int64(2+len("evil")+8+4+1) // key_len + key + ts + ttl + flags
	var huge [4]byte
	binary.BigEndian.PutUint32(huge[:], maxWireLen+1)
	if _, err := f.WriteAt(huge[:], wireLenOff); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st2.Close() }()
	// The corrupt record cuts the file back — "good" survives, "evil" is gone.
	if got := st2.EntryCount(); got != 1 {
		t.Fatalf("EntryCount = %d, want 1", got)
	}
	if _, _, _, _, ok := st2.Get("good"); !ok {
		t.Fatal("good record lost")
	}
}

func TestConcurrentPutGet(t *testing.T) {
	st, err := Create(tmpPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := range 500 {
				key := fmt.Sprintf("g%d-k%d", g, i)
				if err := st.Put(key, int64(i), 60, true, []byte(key)); err != nil {
					t.Errorf("Put: %v", err)
					return
				}
				if _, _, _, wire, ok := st.Get(key); !ok || string(wire) != key {
					t.Errorf("Get(%s) inconsistent", key)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	if got := st.EntryCount(); got != 4000 {
		t.Fatalf("EntryCount = %d, want 4000", got)
	}
}

func TestOpenMissingCreates(t *testing.T) {
	path := tmpPath(t)
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}

func TestMergeAndSortedLookup(t *testing.T) {
	// 300 records span 3 blocks (128 + 128 + 44).  After a merge every key
	// lives in the sorted region and must be found via the sparse index.
	path := tmpPath(t)
	st, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	for i := range 300 {
		key := fmt.Sprintf("key-%03d.example.", i)
		if err := st.Put(key, int64(1000+i), 300, i%2 == 0, []byte(key)); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Compact(func(string, int64, int) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if got := st.EntryCount(); got != 300 {
		t.Fatalf("EntryCount after merge = %d, want 300", got)
	}
	for i := range 300 {
		key := fmt.Sprintf("key-%03d.example.", i)
		ts, ttl, validated, wire, ok := st.Get(key)
		if !ok || ts != int64(1000+i) || ttl != 300 || validated != (i%2 == 0) || string(wire) != key {
			t.Fatalf("key %q wrong after merge: ok=%t ts=%d ttl=%d validated=%t wire=%q", key, ok, ts, ttl, validated, wire)
		}
	}
	if _, _, _, _, ok := st.Get("missing.example."); ok {
		t.Fatal("missing key returned ok")
	}
	// Reopen — the merged file must be self-consistent.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st2.Close() }()
	if got := st2.EntryCount(); got != 300 {
		t.Fatalf("EntryCount after reopen = %d, want 300", got)
	}
	for i := 297; i < 300; i++ {
		key := fmt.Sprintf("key-%03d.example.", i)
		if _, _, _, wire, ok := st2.Get(key); !ok || string(wire) != key {
			t.Fatalf("key %q lost after reopen: ok=%t", key, ok)
		}
	}
}

func TestTailSupersedesSorted(t *testing.T) {
	path := tmpPath(t)
	st, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if err := st.Put("a.example.", 100, 10, false, []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if err := st.Compact(func(string, int64, int) bool { return true }); err != nil {
		t.Fatal(err)
	}
	// A fresh Put lands in the tail region and must supersede the sorted
	// record — without a merge in between.
	if err := st.Put("a.example.", 200, 20, true, []byte("v2")); err != nil {
		t.Fatal(err)
	}
	ts, ttl, validated, wire, ok := st.Get("a.example.")
	if !ok || ts != 200 || ttl != 20 || !validated || string(wire) != "v2" {
		t.Fatalf("tail did not supersede sorted: ok=%t ts=%d ttl=%d validated=%t wire=%q", ok, ts, ttl, validated, wire)
	}
	// After the next merge only the newest record survives.
	if err := st.Compact(func(string, int64, int) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if got := st.EntryCount(); got != 1 {
		t.Fatalf("EntryCount after second merge = %d, want 1", got)
	}
	if _, _, _, wire, ok := st.Get("a.example."); !ok || string(wire) != "v2" {
		t.Fatalf("merged record wrong: ok=%t wire=%q", ok, wire)
	}
}

func TestDeleteTombstone(t *testing.T) {
	path := tmpPath(t)
	st, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if err := st.Put("keep.example.", 100, 10, false, []byte("k")); err != nil {
		t.Fatal(err)
	}
	if err := st.Put("drop.example.", 100, 10, false, []byte("d")); err != nil {
		t.Fatal(err)
	}
	if err := st.Compact(func(string, int64, int) bool { return true }); err != nil {
		t.Fatal(err)
	}
	// Delete a sorted-region key — the tombstone must hide it without a merge.
	st.Delete("drop.example.")
	if _, _, _, _, ok := st.Get("drop.example."); ok {
		t.Fatal("deleted key served")
	}
	if _, _, _, _, ok := st.Get("keep.example."); !ok {
		t.Fatal("kept key lost")
	}
	if got := st.EntryCount(); got != 1 {
		t.Fatalf("EntryCount with tombstone = %d, want 1", got)
	}
	// The merge physically drops the tombstoned record.
	if err := st.Compact(func(string, int64, int) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if got := st.EntryCount(); got != 1 {
		t.Fatalf("EntryCount after merge = %d, want 1", got)
	}
	if _, _, _, _, ok := st.Get("drop.example."); ok {
		t.Fatal("deleted key resurrected by merge")
	}
}

func TestMergeDedupNewestTs(t *testing.T) {
	path := tmpPath(t)
	st, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if err := st.Put("dup.example.", 100, 10, false, []byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := st.Put("dup.example.", 200, 20, true, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := st.Compact(func(string, int64, int) bool { return true }); err != nil {
		t.Fatal(err)
	}
	ts, ttl, validated, wire, ok := st.Get("dup.example.")
	if !ok || ts != 200 || ttl != 20 || !validated || string(wire) != "new" {
		t.Fatalf("dedup picked wrong record: ok=%t ts=%d ttl=%d validated=%t wire=%q", ok, ts, ttl, validated, wire)
	}
	if got := st.EntryCount(); got != 1 {
		t.Fatalf("EntryCount = %d, want 1", got)
	}
}

func TestIndexedAcrossRegions(t *testing.T) {
	path := tmpPath(t)
	st, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if err := st.Put("sorted.example.", 100, 10, false, []byte("s")); err != nil {
		t.Fatal(err)
	}
	if err := st.Compact(func(string, int64, int) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if err := st.Put("tail.example.", 200, 20, false, []byte("t")); err != nil {
		t.Fatal(err)
	}
	// "sorted.example." lives in the sorted region, "tail.example." in the
	// tail map — Indexed must resolve both, plus ts mismatches.
	if !st.Indexed("sorted.example.", 100) {
		t.Fatal("sorted key not indexed")
	}
	if st.Indexed("sorted.example.", 101) {
		t.Fatal("wrong ts indexed")
	}
	if !st.Indexed("tail.example.", 200) {
		t.Fatal("tail key not indexed")
	}
	if st.Indexed("missing.example.", 100) {
		t.Fatal("missing key indexed")
	}
}

func TestBlockBoundaries(t *testing.T) {
	// 129 records = one full block of 128 + a partial block of 1.  Keys on
	// both sides of the boundary must be findable.
	path := tmpPath(t)
	st, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	for i := range 129 {
		key := fmt.Sprintf("b%03d.example.", i)
		if err := st.Put(key, int64(i), 10, false, []byte(key)); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Compact(func(string, int64, int) bool { return true }); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"b000.example.", "b127.example.", "b128.example.", "b126.example."} {
		if _, _, _, _, ok := st.Get(k); !ok {
			t.Fatalf("boundary key %q not found", k)
		}
	}
	if _, _, _, _, ok := st.Get("c000.example."); ok {
		t.Fatal("missing key found")
	}
}

func TestCorruptTailAfterMerge(t *testing.T) {
	// The sorted region must survive a corrupt tail: Open cuts the file back
	// to the last complete record without touching the sorted blocks.
	path := tmpPath(t)
	st, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 10 {
		key := fmt.Sprintf("k%d.example.", i)
		if err := st.Put(key, int64(1000+i), 300, false, []byte(key)); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Compact(func(string, int64, int) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // G304: test temp file
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0x00, 0x03, 'x', 'y'}); err != nil { // key_len + half a key
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st2.Close() }()
	if got := st2.EntryCount(); got != 10 {
		t.Fatalf("EntryCount = %d, want 10 (sorted region intact)", got)
	}
	if _, _, _, _, ok := st2.Get("k5.example."); !ok {
		t.Fatal("sorted key lost")
	}
	// Appends must continue after the truncation point.
	if err := st2.Put("new.example.", 500, 30, true, []byte("n")); err != nil {
		t.Fatal(err)
	}
	if _, _, _, wire, ok := st2.Get("new.example."); !ok || string(wire) != "n" {
		t.Fatal("append after truncation failed")
	}
}

// TestBlockBufTiers verifies the tiered block-buffer pools: buffers land in
// the smallest fitting tier and oversized blocks allocate fresh (never
// pooled).  Capacity class must survive the release round-trip.
func TestBlockBufTiers(t *testing.T) {
	tests := []struct {
		size    int
		wantCap int
	}{
		{100, blockBufSmall},
		{10 * 1024, blockBufMedium},
		{200 * 1024, blockBufLarge},
		{300 * 1024, 300 * 1024}, // beyond the largest tier — fresh alloc, no pool
	}
	for _, tt := range tests {
		buf := acquireBlockBuf(tt.size)
		if got := cap(buf); got != tt.wantCap {
			t.Errorf("acquire(%d): cap = %d, want %d", tt.size, got, tt.wantCap)
		}
		releaseBlockBuf(buf)
		buf2 := acquireBlockBuf(tt.size)
		if got := cap(buf2); got != tt.wantCap {
			t.Errorf("re-acquire(%d): cap = %d, want %d", tt.size, got, tt.wantCap)
		}
	}
}

func BenchmarkPut(b *testing.B) {
	st, err := Create(filepath.Join(b.TempDir(), "bench.bin"))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	wire := bytes.Repeat([]byte{0xAA}, 400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := st.Put("example.com.\x001\x001\x00\x0016", int64(i), 300, true, wire); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGetSorted(b *testing.B) {
	// Get through the sparse-index path: 1000 records merged into sorted
	// blocks, lookup by binary search + block parse (tail map miss).
	st, err := Create(filepath.Join(b.TempDir(), "bench.bin"))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	wire := bytes.Repeat([]byte{0xAA}, 400)
	for i := range 1000 {
		key := fmt.Sprintf("key-%04d.example.", i)
		if err := st.Put(key, int64(i), 300, true, wire); err != nil {
			b.Fatal(err)
		}
	}
	if err := st.Compact(func(string, int64, int) bool { return true }); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		key := fmt.Sprintf("key-%04d.example.", i%1000)
		if _, _, _, _, ok := st.Get(key); !ok {
			b.Fatal("miss")
		}
	}
}

func BenchmarkGet(b *testing.B) {
	st, err := Create(filepath.Join(b.TempDir(), "bench.bin"))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	wire := bytes.Repeat([]byte{0xAA}, 400)
	for i := range 1000 {
		if err := st.Put("example.com.\x001\x001\x00\x0016", int64(i), 300, true, wire); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, _, _, ok := st.Get("example.com.\x001\x001\x00\x0016"); !ok {
			b.Fatal("miss")
		}
	}
}

// BenchmarkOpen measures the startup scan: a 10K-record spill file reopened
// per iteration.  The scan walks every record header and skips the wire
// payloads — the restart cost on a large deployment spill file.
func BenchmarkOpen(b *testing.B) {
	path := filepath.Join(b.TempDir(), "bench.bin")
	st, err := Create(path)
	if err != nil {
		b.Fatal(err)
	}
	wire := bytes.Repeat([]byte{0xAA}, 400)
	for i := range 10000 {
		if err := st.Put(fmt.Sprintf("key-%05d.example.", i), int64(i), 300, true, wire); err != nil {
			b.Fatal(err)
		}
	}
	if err := st.Close(); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st, err := Open(path)
		if err != nil {
			b.Fatal(err)
		}
		if err := st.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

// TestGetDuringCompact: Get/Indexed previously dropped s.mu before their
// ReadAt while Compact (holding s.mu) closed and reassigned s.f — the race
// detector flags the unsynchronised s.f read, and the IO itself can hit the
// closed handle (2026-09 F1).  Run reads against a compacting store under
// the race detector.
func TestGetDuringCompact(t *testing.T) {
	st, err := Create(tmpPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	for i := range 200 {
		if err := st.Put(fmt.Sprintf("k%d", i), int64(i), 300, true, fmt.Appendf(nil, "w%d", i)); err != nil {
			t.Fatal(err)
		}
	}

	var readers sync.WaitGroup
	for g := range 4 {
		readers.Add(1)
		go func(g int) {
			defer readers.Done()
			for i := range 2000 {
				key := fmt.Sprintf("k%d", i%200)
				if _, _, _, _, ok := st.Get(key); !ok {
					t.Errorf("Get(%s) miss during Compact", key)
					return
				}
				st.Indexed(key, int64(i%200))
			}
		}(g)
	}
	compactDone := make(chan error, 1)
	go func() {
		var err error
		for i := range 8 {
			_ = i
			if e := st.Compact(func(key string, ts int64, ttl int) bool { return true }); e != nil {
				err = e
				break
			}
		}
		compactDone <- err
	}()
	readers.Wait()
	if err := <-compactDone; err != nil {
		t.Fatalf("Compact: %v", err)
	}
}
