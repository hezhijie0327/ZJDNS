package edns

import (
	"net"
	"testing"
	"zjdns/config"
)

func TestECSConfig_ValueForQType(t *testing.T) {
	cfg := config.ECSConfig{
		IPv4:       "1.2.3.0/24",
		IPv6:       "2001:db8::/32",
		PreferIPv4: true,
	}

	tests := []struct {
		name  string
		qtype uint16
		want  string
	}{
		{"A prefers IPv4", 1, "1.2.3.0/24"},
		{"AAAA prefers IPv6", 28, "2001:db8::/32"},
		{"other prefers IPv4", 255, "1.2.3.0/24"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cfg.ValueForQType(tt.qtype)
			if got != tt.want {
				t.Errorf("ValueForQType(%d) = %q, want %q", tt.qtype, got, tt.want)
			}
		})
	}

	// Test PreferIPv4=false
	cfg.PreferIPv4 = false
	got := cfg.ValueForQType(255)
	if got != "2001:db8::/32" {
		t.Errorf("PreferIPv4=false: got %q, want %q", got, "2001:db8::/32")
	}
}

func TestECSConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.ECSConfig
		wantErr bool
	}{
		{"empty config", config.ECSConfig{}, true},
		{"IPv4 only valid", config.ECSConfig{IPv4: "1.2.3.0/24"}, false},
		{"IPv6 only valid", config.ECSConfig{IPv6: "2001:db8::/32"}, false},
		{"both valid", config.ECSConfig{IPv4: "1.2.3.0/24", IPv6: "2001:db8::/32"}, false},
		{"invalid value", config.ECSConfig{IPv4: "not-an-ip"}, true},
		{"auto value valid", config.ECSConfig{IPv4: "auto", IPv6: "auto"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestECSConfig_IsEmpty(t *testing.T) {
	empty := config.ECSConfig{}
	if !empty.IsEmpty() {
		t.Error("empty config should be empty")
	}
	v4 := config.ECSConfig{IPv4: "1.2.3.0/24"}
	if v4.IsEmpty() {
		t.Error("config with IPv4 should not be empty")
	}
}

func TestECSConfig_HasAuto(t *testing.T) {
	static := config.ECSConfig{IPv4: "1.2.3.0/24"}
	if static.HasAuto() {
		t.Error("static config should not have auto")
	}
	auto := config.ECSConfig{IPv4: "auto"}
	if !auto.HasAuto() {
		t.Error("auto config should have auto")
	}
}

func TestECSOption(t *testing.T) {
	opt := &ECSOption{
		Family:       1,
		SourcePrefix: 24,
		ScopePrefix:  0,
		Address:      net.ParseIP("1.2.3.0"),
	}
	if opt.Family != 1 {
		t.Errorf("Family = %d, want 1", opt.Family)
	}
	if opt.SourcePrefix != 24 {
		t.Errorf("SourcePrefix = %d, want 24", opt.SourcePrefix)
	}
}
