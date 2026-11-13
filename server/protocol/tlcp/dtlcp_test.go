package tlcp

import (
	"testing"
	"zjdns/config"
)

// TestDTLCPListenerAdmissionGate pins the Round 6 audit P10 fix: the
// dedicated-port DTLCP accept loop admits new clients via try-acquire — a
// full gate drops the datagram (never blocks the read loop, mirroring the
// shared-port rt.admit() semantics), and a released slot is immediately
// reusable.  The pre-fix path called the blocking errgroup.Go directly, so
// a spoofed-source flood froze the whole port for a handshake-timeout
// window per wave.
func TestDTLCPListenerAdmissionGate(t *testing.T) {
	l := newDTLCPListener(nil, nil)

	// Every slot below the cap acquires without blocking.
	for i := range config.DefaultServerGoroutineLimit {
		if !l.tryAdmit() {
			t.Fatalf("slot %d: tryAdmit must succeed below capacity", i)
		}
	}

	// A full gate drops (returns false) instead of blocking: a blocking
	// acquire here would hang the test, which is exactly the regression
	// this pins (the accept loop must never stall on admission).
	if l.tryAdmit() {
		t.Fatal("tryAdmit must fail at capacity — new clients are dropped, not queued")
	}

	// Releasing one slot makes room for exactly one more client.
	l.release()
	if !l.tryAdmit() {
		t.Fatal("tryAdmit must succeed after a release")
	}
	if l.tryAdmit() {
		t.Fatal("tryAdmit must fail again at capacity")
	}
}
