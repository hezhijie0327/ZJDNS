package config

import (
	"net"
	"testing"
)

func TestECSOption_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		ecs   *ECSOption
		valid bool
	}{
		{"nil", nil, true},
		{"valid IPv4 /24", &ECSOption{Family: 1, SourcePrefix: 24, Address: net.ParseIP("1.2.3.0").To4()}, true},
		{"valid IPv6 /56", &ECSOption{Family: 2, SourcePrefix: 56, Address: net.ParseIP("2001:db8::")}, true},
		{"valid /0", &ECSOption{Family: 1, SourcePrefix: 0, Address: nil}, true},
		{"family 0 /0", &ECSOption{Family: 0, SourcePrefix: 0, Address: nil}, true},
		{"invalid family 3", &ECSOption{Family: 3, SourcePrefix: 24}, false},
		{"IPv4 prefix >32", &ECSOption{Family: 1, SourcePrefix: 33}, false},
		{"IPv6 prefix >128", &ECSOption{Family: 2, SourcePrefix: 129}, false},
		{"family 0 with prefix", &ECSOption{Family: 0, SourcePrefix: 8}, false},
		{"address too short", &ECSOption{Family: 1, SourcePrefix: 24, Address: []byte{1, 2}}, false},
	}
	for _, tt := range tests {
		if got := tt.ecs.IsValid(); got != tt.valid {
			t.Errorf("%s: IsValid() = %v, want %v", tt.name, got, tt.valid)
		}
	}
}
