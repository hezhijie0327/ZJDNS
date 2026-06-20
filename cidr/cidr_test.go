package cidr

import (
	"net"
	"testing"

	"zjdns/config"
)

func TestMatchIP(t *testing.T) {
	filter, err := New([]config.CIDRConfig{
		{Rules: []string{"192.168.0.0/16", "10.0.0.0/8"}, Tag: "internal"},
		{Rules: []string{"2001:db8::/32"}, Tag: "ipv6"},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name     string
		ip       string
		matchTag string
		want     bool
		exists   bool
	}{
		{"internal match /16", "192.168.1.1", "internal", true, true},
		{"internal match /8", "10.255.255.255", "internal", true, true},
		{"internal no match", "172.16.0.1", "internal", false, true},
		{"ipv6 match", "2001:db8::1", "ipv6", true, true},
		{"ipv6 no match", "2001:4860::1", "ipv6", false, true},
		{"negate match", "192.168.1.1", "!internal", false, true},
		{"negate no match", "172.16.0.1", "!internal", true, true},
		{"empty tag defaults to pass", "8.8.8.8", "", true, true},
		{"unknown tag", "8.8.8.8", "nonexistent", false, false},
		{"nil filter", "8.8.8.8", "any", true, true}, // nil filter check in subtest
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil && tt.matchTag != "" {
				t.Fatalf("invalid test IP: %s", tt.ip)
			}

			var fm *Filter
			if tt.matchTag == "any" && tt.name == "nil filter" {
				// test nil filter
				fm = nil
				matched, exists := fm.MatchIP(ip, tt.matchTag)
				if !matched || !exists {
					t.Errorf("nil filter: matched=%v exists=%v", matched, exists)
				}
				return
			}

			fm = filter
			matched, exists := fm.MatchIP(ip, tt.matchTag)
			if matched != tt.want {
				t.Errorf("matched = %v, want %v", matched, tt.want)
			}
			if exists != tt.exists {
				t.Errorf("exists = %v, want %v", exists, tt.exists)
			}
		})
	}
}

func TestMatchIP_IPv4MappedIPv6(t *testing.T) {
	filter, _ := New([]config.CIDRConfig{
		{Rules: []string{"192.168.0.0/16"}, Tag: "test"},
	})

	// IPv4-mapped IPv6 should be treated as IPv4
	ip := net.ParseIP("::ffff:192.168.1.1")
	matched, exists := filter.MatchIP(ip, "test")
	if matched != true || exists != true {
		t.Errorf("IPv4-mapped IPv6: matched=%v exists=%v, want true,true", matched, exists)
	}
}

func TestMatchIP_CacheHit(t *testing.T) {
	filter, _ := New([]config.CIDRConfig{
		{Rules: []string{"10.0.0.0/8"}, Tag: "ten"},
	})

	ip := net.ParseIP("10.0.0.1")
	// First call populates cache
	filter.MatchIP(ip, "ten")
	// Second call hits cache
	matched, exists := filter.MatchIP(ip, "ten")
	if !matched || !exists {
		t.Errorf("cache hit: matched=%v exists=%v", matched, exists)
	}
}

func TestNew_Errors(t *testing.T) {
	tests := []struct {
		name    string
		configs []config.CIDRConfig
		wantErr bool
	}{
		{"empty tag", []config.CIDRConfig{{Rules: []string{"10.0.0.0/8"}}}, true},
		{"duplicate tag", []config.CIDRConfig{
			{Rules: []string{"10.0.0.0/8"}, Tag: "dup"},
			{Rules: []string{"192.168.0.0/16"}, Tag: "dup"},
		}, true},
		{"no valid entries", []config.CIDRConfig{
			{Rules: []string{}, Tag: "empty", File: ""},
		}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.configs)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}
