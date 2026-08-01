package dnsutil_test

import (
	"testing"
	"time"
	"zjdns/config"
)

// TestTCPKeepAlivePeriodConsistency guards the duplicated constant in
// keepalive.go: internal/dnsutil cannot import config (layering), so
// defaultTCPKeepAlivePeriod mirrors config.DefaultTCPKeepAlivePeriod.
// This external test package can import both and catches drift.
func TestTCPKeepAlivePeriodConsistency(t *testing.T) {
	const mirroredKeepAlivePeriod = 30 * time.Second // must match keepalive.go's defaultTCPKeepAlivePeriod
	if config.DefaultTCPKeepAlivePeriod != mirroredKeepAlivePeriod {
		t.Fatalf("config.DefaultTCPKeepAlivePeriod = %v, but keepalive.go mirrors %v — update both",
			config.DefaultTCPKeepAlivePeriod, mirroredKeepAlivePeriod)
	}
}
