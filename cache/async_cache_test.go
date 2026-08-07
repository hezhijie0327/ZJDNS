package cache

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"
	"zjdns/config"
	"zjdns/database"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

// asyncTestStore builds a FULLY wired SQLiteCache (async writers + pending
// read-through), unlike testStore which hand-constructs for sync semantics.
func asyncTestStore(t *testing.T) *SQLiteCache {
	t.Helper()
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	s := New(db)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestAsyncCache_PendingReadThrough verifies that a Set is immediately
// visible to Get (pending layer) BEFORE the batch commits to SQLite.
func TestAsyncCache_PendingReadThrough(t *testing.T) {
	s := asyncTestStore(t)

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}}
	s.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false, 0)

	// Visible immediately through the pending layer (no Flush needed).
	entry, found, expired := s.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found || expired {
		t.Fatalf("pending read-through: found=%v expired=%v, want true/false", found, expired)
	}
	if entry.ResponseWire == nil {
		t.Fatal("pending entry ResponseWire is nil")
	}
}

// TestAsyncCache_FlushCommitsBatch verifies that Flush persists all pending
// entries to SQLite in one place (the row becomes visible without the
// pending layer).
func TestAsyncCache_FlushCommitsBatch(t *testing.T) {
	s := asyncTestStore(t)

	const n = 300 // > DefaultAsyncCacheBatchSize, forces multiple batches
	for range n {
		rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}}
		s.Set("flush-test.example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false, 0)
	}
	s.Flush()

	var count int64
	if err := s.db.SQ.QueryRow(`SELECT COUNT(*) FROM entries WHERE qname='flush-test.example.com.'`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("entries count = %d, want 1 (upsert of the same key)", count)
	}
}

// TestAsyncCache_ReadThroughRemovedAfterCommit verifies the pending entry is
// removed once its batch commits (the SQLite row takes over).
func TestAsyncCache_ReadThroughRemovedAfterCommit(t *testing.T) {
	s := asyncTestStore(t)

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}}
	s.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false, 0)
	s.Flush()

	if got := s.pending.Len(); got != 0 {
		t.Errorf("pending entries after flush = %d, want 0", got)
	}
	// The SQLite row still serves the entry.
	entry, found, _ := s.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found || entry.ResponseWire == nil {
		t.Fatal("entry should be served from SQLite after flush")
	}
}

// TestAsyncCache_ReprocessSameKeyKeepsNewPending verifies that a re-Set of
// the same key while the first item is queued keeps the NEWER pending entry
// (pointer comparison in removePending).
func TestAsyncCache_ReprocessSameKeyKeepsNewPending(t *testing.T) {
	s := asyncTestStore(t)

	rr1 := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}}
	s.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr1}, nil, nil, false, 0)
	rr2 := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.2")}}
	s.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr2}, nil, nil, false, 0)

	s.Flush()

	entry, found, _ := s.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("entry missing after re-Set + flush")
	}
	_ = entry.Unpack()
	if got := entry.Answer[0].(*dns.A).A.String(); got != "192.0.2.2" {
		t.Errorf("answer = %s, want 192.0.2.2 (newer Set must win)", got)
	}
}

// TestAsyncCache_CloseDrains verifies Close persists queued entries: the
// file-backed DB is reopened after Close to observe the drained rows.
func TestAsyncCache_CloseDrains(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "close-drain.db")
	db, err := database.Open(dbPath, 0, database.Options{})
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	s := New(db)

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}}
	s.Set("close-drain.example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false, 0)
	_ = s.Close() // must flush before closing the DB

	reopened, err := database.Open(dbPath, 0, database.Options{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = reopened.Close() }()

	var count int64
	if err := reopened.SQ.QueryRow(`SELECT COUNT(*) FROM entries WHERE qname='close-drain.example.com.'`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("entries count = %d, want 1 (Close should drain)", count)
	}
}

// TestAsyncCache_EvictionAfterFlush verifies eviction triggers after the
// batched commit (onCommit hook), not on Set.
func TestAsyncCache_EvictionAfterFlush(t *testing.T) {
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	s := New(db)
	t.Cleanup(func() { _ = s.Close() })

	// MaxEntries defaults to 10000 — not practical to fill; instead verify the
	// hook wiring: evictIfNeeded runs after a flush without panicking and the
	// entry counter tracks the batch.
	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}}
	for range 200 {
		s.Set("evict.example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false, 0)
	}
	s.Flush()

	// 200 Sets of the same key = 1 row; counter must reflect that (EXISTS
	// check inside the batch transaction).
	if got := s.db.EntryCount(); got != 1 {
		t.Errorf("entry count = %d, want 1 (batched upserts must not drift)", got)
	}
	_ = config.DefaultCacheWriteTimeout // keep the import meaningful if unused elsewhere
	_ = time.Second
}
