package edns

import (
	"net"
	"testing"
)

func TestECSConfig_ValueForQType(t *testing.T) {
	cfg := ECSConfig{
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
		cfg     ECSConfig
		wantErr bool
	}{
		{"empty config", ECSConfig{}, true},
		{"IPv4 only valid", ECSConfig{IPv4: "1.2.3.0/24"}, false},
		{"IPv6 only valid", ECSConfig{IPv6: "2001:db8::/32"}, false},
		{"both valid", ECSConfig{IPv4: "1.2.3.0/24", IPv6: "2001:db8::/32"}, false},
		{"invalid value", ECSConfig{IPv4: "not-an-ip"}, true},
		{"auto value valid", ECSConfig{IPv4: "auto", IPv6: "auto"}, false},
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
	empty := ECSConfig{}
	if !empty.IsEmpty() {
		t.Error("empty config should be empty")
	}
	v4 := ECSConfig{IPv4: "1.2.3.0/24"}
	if v4.IsEmpty() {
		t.Error("config with IPv4 should not be empty")
	}
}

func TestECSConfig_HasAuto(t *testing.T) {
	static := ECSConfig{IPv4: "1.2.3.0/24"}
	if static.HasAuto() {
		t.Error("static config should not have auto")
	}
	auto := ECSConfig{IPv4: "auto"}
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

func TestCookieGenerator_Basic(t *testing.T) {
	cg := NewCookieGenerator()
	if cg == nil {
		t.Fatal("NewCookieGenerator returned nil")
	}

	clientIP := net.ParseIP("192.168.1.1")
	clientCookie := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	// Generate server cookie
	serverCookie := cg.GenerateServerCookie(clientIP, clientCookie)
	if len(serverCookie) != DefaultCookieServerLen {
		t.Errorf("server cookie len = %d, want %d", len(serverCookie), DefaultCookieServerLen)
	}

	// Validate server cookie
	if !cg.IsServerCookieValid(clientIP, clientCookie, serverCookie) {
		t.Error("IsServerCookieValid should succeed with fresh cookie")
	}

	// Invalid client cookie
	if cg.IsServerCookieValid(clientIP, []byte{0, 0, 0, 0}, serverCookie) {
		t.Error("IsServerCookieValid should fail with short client cookie")
	}
}

func TestCookieGenerator_Rotation(t *testing.T) {
	cg := NewCookieGenerator()
	clientIP := net.ParseIP("10.0.0.1")
	clientCookie := []byte{8, 7, 6, 5, 4, 3, 2, 1}

	oldCookie := cg.GenerateServerCookie(clientIP, clientCookie)
	cg.RotateSecret()
	newCookie := cg.GenerateServerCookie(clientIP, clientCookie)

	// New cookie should be different
	if string(oldCookie) == string(newCookie) {
		t.Error("cookies should differ after rotation")
	}

	// Old cookie should still validate (previous secret retained)
	if !cg.IsServerCookieValid(clientIP, clientCookie, oldCookie) {
		t.Error("old cookie should still validate after rotation")
	}

	// New cookie should validate
	if !cg.IsServerCookieValid(clientIP, clientCookie, newCookie) {
		t.Error("new cookie should validate after rotation")
	}
}

func TestCookieGenerator_Nil(t *testing.T) {
	var cg *CookieGenerator
	if cg.GenerateServerCookie(nil, nil) != nil {
		t.Error("nil CookieGenerator should return nil")
	}
	if cg.IsServerCookieValid(nil, nil, nil) {
		t.Error("nil CookieGenerator should return false")
	}
	cg.RotateSecret() // should not panic
}

func TestCookieGenerator_ClientCookie(t *testing.T) {
	cg := NewCookieGenerator()
	clientIP := net.ParseIP("172.16.0.1")
	cookie := cg.GenerateClientCookie(clientIP)
	if len(cookie) != DefaultCookieClientLen {
		t.Errorf("client cookie len = %d, want %d", len(cookie), DefaultCookieClientLen)
	}
}

func TestBuildCookieResponse(t *testing.T) {
	client := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	server := []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}

	result := BuildCookieResponse(client, server)
	if result == "" {
		t.Error("BuildCookieResponse should not return empty")
	}

	resultInvalid := BuildCookieResponse([]byte{0, 0}, server)
	if resultInvalid != "" {
		t.Error("BuildCookieResponse should return empty for invalid client cookie")
	}
}
