package server

import (
	"testing"
	"time"
)

// TestTCPWriteMuRefcountAndSweep verifies the H1 fix contract: an entry's
// refcount returns to 0 after a request completes, the sweep deletes stale
// idle entries, and an in-flight entry survives a sweep pass.
func TestTCPWriteMuRefcountAndSweep(t *testing.T) {
	s := &Server{}
	addr := "192.0.2.1:54321"

	// Simulate the request-path critical section: lookup-or-create + in-flight
	// ref under the shard lock (as in handleDNSRequest).
	shard := s.tcpWriteShardFor(addr)
	shard.mu.Lock()
	entry, ok := shard.entries[addr]
	if !ok {
		entry = &tcpWriteEntry{}
		if shard.entries == nil {
			shard.entries = make(map[string]*tcpWriteEntry)
		}
		shard.entries[addr] = entry
	}
	entry.refs.Add(1)
	shard.mu.Unlock()

	// Entry exists with one in-flight ref — sweep must not delete it even
	// though lastAccess (0) is far below the cutoff.
	s.sweepTCPWriteMu(time.Now().UnixNano())
	if _, ok := shard.entries[addr]; !ok {
		t.Fatal("sweep deleted an entry with in-flight refs")
	}

	// Request completes: refs drops to 0.
	entry.refs.Add(-1)
	if got := entry.refs.Load(); got != 0 {
		t.Fatalf("refs after completed request = %d, want 0", got)
	}

	// Idle entry (lastAccess 0 < cutoff) is now sweepable.
	s.sweepTCPWriteMu(time.Now().UnixNano())
	if _, ok := shard.entries[addr]; ok {
		t.Fatal("sweep did not delete an idle stale entry with refs == 0")
	}

	// A freshly created entry inside the same critical section is never
	// deleted by a concurrent sweep: the ref add happens under the same lock
	// the sweep needs for its check+delete. With a recent lastAccess and a
	// cutoff one hour in the past the entry must survive.
	shard.mu.Lock()
	entry, ok = shard.entries[addr]
	if !ok {
		entry = &tcpWriteEntry{}
		if shard.entries == nil {
			shard.entries = make(map[string]*tcpWriteEntry)
		}
		shard.entries[addr] = entry
	}
	entry.refs.Add(1)
	entry.lastAccess.Store(time.Now().UnixNano())
	shard.mu.Unlock()
	entry.refs.Add(-1)
	s.sweepTCPWriteMu(time.Now().UnixNano() - int64(time.Hour))
	if _, ok := shard.entries[addr]; !ok {
		t.Fatal("freshly-idle entry with recent lastAccess was deleted")
	}
	shard.mu.Lock()
	delete(shard.entries, addr)
	shard.mu.Unlock()
}
