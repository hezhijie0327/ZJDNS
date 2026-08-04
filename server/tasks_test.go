package server

import (
	"sync"
	"testing"
	"time"
)

// TestTCPWriteMuRefcountAndSweep verifies the H1 fix contract: an entry's
// refcount returns to 0 after a request completes, the sweep deletes stale
// idle entries, and an in-flight entry survives a sweep pass.
func TestTCPWriteMuRefcountAndSweep(t *testing.T) {
	s := &Server{tcpWriteMu: sync.Map{}}
	addr := "192.0.2.1:54321"

	// Simulate the request-path critical section: LoadOrStore + in-flight ref
	// under tcpMu (as in handleDNSRequest).
	s.tcpMu.Lock()
	entryI, _ := s.tcpWriteMu.LoadOrStore(addr, &tcpWriteEntry{})
	entry := entryI.(*tcpWriteEntry)
	entry.refs.Add(1)
	s.tcpMu.Unlock()

	// Entry exists with one in-flight ref — sweep must not delete it even
	// though lastAccess (0) is far below the cutoff.
	s.sweepTCPWriteMu(time.Now().UnixNano())
	if _, ok := s.tcpWriteMu.Load(addr); !ok {
		t.Fatal("sweep deleted an entry with in-flight refs")
	}

	// Request completes: refs drops to 0.
	entry.refs.Add(-1)
	if got := entry.refs.Load(); got != 0 {
		t.Fatalf("refs after completed request = %d, want 0", got)
	}

	// Idle entry (lastAccess 0 < cutoff) is now sweepable.
	s.sweepTCPWriteMu(time.Now().UnixNano())
	if _, ok := s.tcpWriteMu.Load(addr); ok {
		t.Fatal("sweep did not delete an idle stale entry with refs == 0")
	}

	// A freshly LoadOrStored entry inside the same critical section is never
	// deleted by a concurrent sweep: the ref add happens under the same lock
	// the sweep needs for its check+delete. With a recent lastAccess and a
	// cutoff one hour in the past the entry must survive.
	s.tcpMu.Lock()
	entryI, _ = s.tcpWriteMu.LoadOrStore(addr, &tcpWriteEntry{})
	entry = entryI.(*tcpWriteEntry)
	entry.refs.Add(1)
	entry.lastAccess.Store(time.Now().UnixNano())
	s.tcpMu.Unlock()
	entry.refs.Add(-1)
	s.sweepTCPWriteMu(time.Now().UnixNano() - int64(time.Hour))
	if _, ok := s.tcpWriteMu.Load(addr); !ok {
		t.Fatal("freshly-idle entry with recent lastAccess was deleted")
	}
	s.tcpWriteMu.Delete(addr)
}
