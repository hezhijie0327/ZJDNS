package edns

import (
	"testing"

	"codeberg.org/miekg/dns"
)

func TestQueryTCPKeepalive(t *testing.T) {
	if QueryTCPKeepalive(nil) {
		t.Error("nil request must not report keepalive")
	}
	if QueryTCPKeepalive(new(dns.Msg)) {
		t.Error("option-free request must not report keepalive")
	}
	req := new(dns.Msg)
	req.Pseudo = append(req.Pseudo, &dns.TCPKEEPALIVE{})
	if !QueryTCPKeepalive(req) {
		t.Error("request carrying TCPKEEPALIVE must report keepalive")
	}
}

func TestTCPKeepaliveTimeout(t *testing.T) {
	tests := []struct {
		protocol string
		want     uint16
	}{
		{"tcp", 1200}, // DefaultTCPIdleTimeout 120s in 100ms units
		{"tls", 600},  // DoT per-message idle 60s
		{"tlcp", 600}, // TLCP DoT per-message idle 60s
		{"udp", 0},    // §3.3.1: TCP-only
		{"https", 0},  // HTTP layer manages idle
		{"quic", 0},   // QUIC transport keepalive
		{"dtlcp", 0},  // datagram
		{"", 0},
	}
	for _, tc := range tests {
		if got := TCPKeepaliveTimeout(tc.protocol); got != tc.want {
			t.Errorf("protocol %q: got %d, want %d", tc.protocol, got, tc.want)
		}
	}
}
