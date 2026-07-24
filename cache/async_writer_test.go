package cache

import (
	"testing"
	"zjdns/database"
)

// testWriter creates an AsyncStatsWriter backed by an in-memory DB for testing.
func testWriter(t *testing.T, bufSize int) (*AsyncStatsWriter, *database.DB) {
	t.Helper()
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	w := NewAsyncStatsWriter(db, bufSize)
	t.Cleanup(func() {
		w.Close()
		_ = db.Close()
	})
	return w, db
}

func TestAsyncStatsWriter_RecordAndFlush(t *testing.T) {
	w, db := testWriter(t, 8)

	w.Record(&RequestRecord{
		Qname: "example.com.", Qtype: 1, Qclass: 1,
		Protocol: "udp", Result: "hit", Rcode: 0,
	})
	w.Record(&RequestRecord{
		Qname: "stale.example.com.", Qtype: 1, Qclass: 1,
		Protocol: "tcp", Result: "stale", Rcode: 0,
	})

	w.Flush()

	// query_stats should have both records.
	var hitCount, staleCount int64
	err := db.SQ.QueryRow(
		`SELECT COALESCE(SUM(CASE WHEN result='hit' THEN query_count ELSE 0 END), 0),
		        COALESCE(SUM(CASE WHEN result='stale' THEN query_count ELSE 0 END), 0)
		 FROM query_stats`,
	).Scan(&hitCount, &staleCount)
	if err != nil {
		t.Fatalf("query_stats: %v", err)
	}
	if hitCount != 1 {
		t.Errorf("hit count = %d, want 1", hitCount)
	}
	if staleCount != 1 {
		t.Errorf("stale count = %d, want 1", staleCount)
	}

	// query_log should have the stale record (non-hit).
	var logCount int64
	err = db.SQ.QueryRow(
		`SELECT COUNT(*) FROM query_log WHERE qname='stale.example.com.' AND result='stale'`,
	).Scan(&logCount)
	if err != nil {
		t.Fatalf("query_log: %v", err)
	}
	if logCount != 1 {
		t.Errorf("query_log stale count = %d, want 1", logCount)
	}

	// query_log should NOT have the hit record.
	err = db.SQ.QueryRow(
		`SELECT COUNT(*) FROM query_log WHERE qname='example.com.' AND result='hit'`,
	).Scan(&logCount)
	if err != nil {
		t.Fatalf("query_log: %v", err)
	}
	if logCount != 0 {
		t.Errorf("query_log hit count = %d, want 0 (hits skip query_log)", logCount)
	}
}

func TestAsyncStatsWriter_CloseDrains(t *testing.T) {
	w, db := testWriter(t, 8)

	w.Record(&RequestRecord{
		Qname: "close-test.example.com.", Qtype: 1, Qclass: 1,
		Protocol: "udp", Result: "error", Rcode: 2,
	})

	// Close should drain and flush before returning.
	w.Close()
	// Mark DB as not closed so we can still query (Close only closes the writer, not the DB).
	// But the writer's Close calls close(ch) which triggers drain. DB is still open.

	var logCount int64
	err := db.SQ.QueryRow(
		`SELECT COUNT(*) FROM query_log WHERE qname='close-test.example.com.'`,
	).Scan(&logCount)
	if err != nil {
		t.Fatalf("query_log: %v", err)
	}
	if logCount != 1 {
		t.Errorf("query_log count = %d, want 1 (Close should drain)", logCount)
	}
}

func TestAsyncStatsWriter_CloseIdempotent(t *testing.T) {
	w, _ := testWriter(t, 8)

	w.Close()
	// Second close must not panic.
	w.Close()
	// Third close must not panic either.
	w.Close()
}

func TestAsyncStatsWriter_NilSafety(t *testing.T) {
	var w *AsyncStatsWriter

	// None of these should panic.
	w.Record(&RequestRecord{Qname: "test.", Qtype: 1, Qclass: 1, Protocol: "udp", Result: "hit", Rcode: 0})
	w.Flush()
	w.Close()
}

// NOTE(L8): buffer-size-1 test may race with goroutine consumption. Run with -count=5.
func TestAsyncStatsWriter_ChannelFullDrops(t *testing.T) {
	w, db := testWriter(t, 1) // buffer of 1 — second record drops immediately

	// Fill the buffer.
	w.Record(&RequestRecord{
		Qname: "first.example.com.", Qtype: 1, Qclass: 1,
		Protocol: "udp", Result: "hit", Rcode: 0,
	})
	// This should drop (channel full).
	w.Record(&RequestRecord{
		Qname: "dropped.example.com.", Qtype: 1, Qclass: 1,
		Protocol: "udp", Result: "error", Rcode: 2,
	})

	w.Flush()

	// Only the first record should be present.
	var hitCount int64
	err := db.SQ.QueryRow(
		`SELECT COALESCE(SUM(query_count), 0) FROM query_stats WHERE result='hit'`,
	).Scan(&hitCount)
	if err != nil {
		t.Fatalf("query_stats: %v", err)
	}
	if hitCount != 1 {
		t.Errorf("hit count = %d, want 1 (second record should have dropped)", hitCount)
	}

	// The dropped error record should not be in query_log.
	var logCount int64
	err = db.SQ.QueryRow(
		`SELECT COUNT(*) FROM query_log WHERE qname='dropped.example.com.'`,
	).Scan(&logCount)
	if err != nil {
		t.Fatalf("query_log: %v", err)
	}
	if logCount != 0 {
		t.Errorf("dropped record should not appear in query_log, got %d", logCount)
	}
}

func TestAsyncStatsWriter_FlushGoroutineBatch(t *testing.T) {
	w, db := testWriter(t, 64)

	// Send a single record — the goroutine will pick it up into its internal batch
	// before we call Flush.  Flush Phase 2 signals the goroutine to flush its batch.
	w.Record(&RequestRecord{
		Qname: "batch.example.com.", Qtype: 1, Qclass: 1,
		Protocol: "quic", Result: "stale", Rcode: 0,
	})

	// Flush must write the record even if it's in the goroutine's batch, not the channel.
	w.Flush()

	var logCount int64
	err := db.SQ.QueryRow(
		`SELECT COUNT(*) FROM query_log WHERE qname='batch.example.com.'`,
	).Scan(&logCount)
	if err != nil {
		t.Fatalf("query_log: %v", err)
	}
	if logCount != 1 {
		t.Errorf("query_log count = %d, want 1 (Flush should sync goroutine batch)", logCount)
	}
}

func TestAsyncStatsWriter_FlushEmptyChannel(t *testing.T) {
	w, _ := testWriter(t, 8)

	// Flush on an idle writer (nothing in channel, nothing in goroutine batch)
	// must not block or panic.
	w.Flush()
	w.Flush() // twice
}

func TestAsyncStatsWriter_EmptyRecord(t *testing.T) {
	w, db := testWriter(t, 8)

	// Record with minimal fields (like the error path in handler.go).
	w.Record(&RequestRecord{
		Result: "error", Protocol: "udp", Rcode: 2,
	})

	w.Flush()

	var logCount int64
	err := db.SQ.QueryRow(
		`SELECT COUNT(*) FROM query_log WHERE result='error'`,
	).Scan(&logCount)
	if err != nil {
		t.Fatalf("query_log: %v", err)
	}
	if logCount != 1 {
		t.Errorf("query_log count = %d, want 1", logCount)
	}
}
