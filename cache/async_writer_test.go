package cache

import (
	"testing"
	"zjdns/database"
)

func testWriter(t *testing.T, bufSize int) (*AsyncStatsWriter, *database.DB) {
	t.Helper()
	db, err := database.Open("", 0, 0, 0, 0)
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
	w, _ := testWriter(t, 8)

	w.Record(&RequestRecord{
		Qname: "example.com.", Qtype: 1, Qclass: 1,
		Protocol: "udp", Result: "hit", Rcode: 0,
	})
	w.Record(&RequestRecord{
		Qname: "stale.example.com.", Qtype: 1, Qclass: 1,
		Protocol: "tcp", Result: "stale", Rcode: 0,
	})

	w.Flush()
	// Records should be flushed without error.
}

func TestAsyncStatsWriter_CloseDrains(t *testing.T) {
	w, _ := testWriter(t, 8)

	w.Record(&RequestRecord{
		Qname: "close-test.example.com.", Qtype: 1, Qclass: 1,
		Protocol: "udp", Result: "error", Rcode: 2,
	})

	w.Close()
	// Close should drain and flush without error.
}

func TestAsyncStatsWriter_CloseIdempotent(t *testing.T) {
	w, _ := testWriter(t, 8)

	w.Close()
	w.Close()
	w.Close()
	// Should not panic.
}

func TestAsyncStatsWriter_NilSafety(t *testing.T) {
	var w *AsyncStatsWriter

	w.Record(&RequestRecord{Qname: "test.", Qtype: 1, Qclass: 1, Protocol: "udp", Result: "hit", Rcode: 0})
	w.Flush()
	w.Close()
	// Should not panic.
}

func TestAsyncStatsWriter_ChannelFullDrops(t *testing.T) {
	db, err := database.Open("", 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}

	w := &AsyncStatsWriter{
		ch:       make(chan RequestRecord, 1),
		flushSig: make(chan chan struct{}),
		db:       db,
		done:     make(chan struct{}),
	}

	w.ch <- RequestRecord{
		Qname: "first.example.com.", Qtype: 1, Qclass: 1,
		Protocol: "udp", Result: "hit", Rcode: 0,
	}

	go w.run()
	t.Cleanup(func() { w.Close(); _ = db.Close() })

	w.Record(&RequestRecord{
		Qname: "dropped.example.com.", Qtype: 1, Qclass: 1,
		Protocol: "udp", Result: "error", Rcode: 2,
	})

	w.Flush()
	// The first record should be written, the second should be dropped.
}

func TestAsyncStatsWriter_FlushGoroutineBatch(t *testing.T) {
	w, _ := testWriter(t, 64)

	w.Record(&RequestRecord{
		Qname: "batch.example.com.", Qtype: 1, Qclass: 1,
		Protocol: "quic", Result: "stale", Rcode: 0,
	})

	w.Flush()
	// Flush should work even if the record was in the goroutine batch.
}

func TestAsyncStatsWriter_FlushEmptyChannel(t *testing.T) {
	w, _ := testWriter(t, 8)

	w.Flush()
	w.Flush()
	// Should not block or panic.
}

func TestAsyncStatsWriter_EmptyRecord(t *testing.T) {
	w, _ := testWriter(t, 8)

	w.Record(&RequestRecord{
		Result: "error", Protocol: "udp", Rcode: 2,
	})

	w.Flush()
	// Record with minimal fields should not panic.
}
