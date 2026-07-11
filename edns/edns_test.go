package edns

import (
	"net"
	"testing"
	"zjdns/config"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
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

func TestCookieGenerator_RFC9018_Basic(t *testing.T) {
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

	// Check RFC 9018 wire format: version byte must be 1
	if serverCookie[0] != 1 {
		t.Errorf("cookie version = %d, want 1", serverCookie[0])
	}
	// Reserved bytes must be zero
	if serverCookie[1] != 0 || serverCookie[2] != 0 || serverCookie[3] != 0 {
		t.Errorf("reserved bytes not zero: %v", serverCookie[1:4])
	}

	// Validate fresh server cookie
	status := cg.IsServerCookieValid(clientIP, clientCookie, serverCookie)
	if status != CookieValid {
		t.Errorf("IsServerCookieValid = %d, want CookieValid (0)", status)
	}

	// Short client cookie → Invalid
	if cg.IsServerCookieValid(clientIP, []byte{0, 0, 0, 0}, serverCookie) != CookieInvalid {
		t.Error("IsServerCookieValid should return CookieInvalid with short client cookie")
	}

	// Wrong server cookie length → Invalid
	if cg.IsServerCookieValid(clientIP, clientCookie, []byte{0}) != CookieInvalid {
		t.Error("IsServerCookieValid should return CookieInvalid with short server cookie")
	}

	// Wrong version → Invalid
	badVer := make([]byte, DefaultCookieServerLen)
	copy(badVer, serverCookie)
	badVer[0] = 2
	if cg.IsServerCookieValid(clientIP, clientCookie, badVer) != CookieInvalid {
		t.Error("IsServerCookieValid should return CookieInvalid for version != 1")
	}

	// Tampered hash → Invalid
	tampered := make([]byte, DefaultCookieServerLen)
	copy(tampered, serverCookie)
	tampered[15] ^= 0xff
	if cg.IsServerCookieValid(clientIP, clientCookie, tampered) != CookieInvalid {
		t.Error("IsServerCookieValid should return CookieInvalid for tampered cookie")
	}

	// IPv6 client
	ip6 := net.ParseIP("2001:db8::1")
	serverCookie6 := cg.GenerateServerCookie(ip6, clientCookie)
	if status := cg.IsServerCookieValid(ip6, clientCookie, serverCookie6); status != CookieValid {
		t.Errorf("IPv6: IsServerCookieValid = %d, want CookieValid (0)", status)
	}
}

func TestCookieGenerator_RFC9018_Rotation(t *testing.T) {
	cg := NewCookieGenerator()
	clientIP := net.ParseIP("10.0.0.1")
	clientCookie := []byte{8, 7, 6, 5, 4, 3, 2, 1}

	oldCookie := cg.GenerateServerCookie(clientIP, clientCookie)
	cg.RotateSecret()
	newCookie := cg.GenerateServerCookie(clientIP, clientCookie)

	// Cookies should differ (different secret produces different SipHash)
	// Note: timestamps may be identical since timeNow is deterministic in tests

	// Old cookie should still validate (previous secret retained) but flag renew
	statusOld := cg.IsServerCookieValid(clientIP, clientCookie, oldCookie)
	if statusOld != CookieValidRenew {
		t.Errorf("old cookie status = %d, want CookieValidRenew (%d)", statusOld, CookieValidRenew)
	}

	// New cookie should validate with current secret
	statusNew := cg.IsServerCookieValid(clientIP, clientCookie, newCookie)
	if statusNew != CookieValid {
		t.Errorf("new cookie status = %d, want CookieValid (%d)", statusNew, CookieValid)
	}

	// Second rotation: even older secret still validates
	cg.RotateSecret()
	statusOld = cg.IsServerCookieValid(clientIP, clientCookie, oldCookie)
	if statusOld != CookieValidRenew {
		t.Errorf("after 2nd rotation old cookie status = %d, want CookieValidRenew (%d)", statusOld, CookieValidRenew)
	}
}

func TestCookieGenerator_RFC9018_Nil(t *testing.T) {
	var cg *CookieGenerator
	if cg.GenerateServerCookie(nil, nil) != nil {
		t.Error("nil CookieGenerator should return nil")
	}
	if cg.IsServerCookieValid(nil, nil, nil) != CookieInvalid {
		t.Error("nil CookieGenerator should return CookieInvalid")
	}
	cg.RotateSecret() // should not panic
}

func TestCookieGenerator_RFC9018_TimeExpired(t *testing.T) {
	cg := NewCookieGenerator()
	clientIP := net.ParseIP("192.168.1.1")
	clientCookie := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	// Save original clock
	origNow := timeNow
	defer func() { timeNow = origNow }()

	now := origNow()
	cookie := cg.GenerateServerCookie(clientIP, clientCookie)

	// Advance clock past expiry (> 1 hour)
	timeNow = func() uint32 { return now + 3601 }
	status := cg.IsServerCookieValid(clientIP, clientCookie, cookie)
	if status != CookieExpired {
		t.Errorf("expired cookie status = %d, want CookieExpired", status)
	}
}

func TestCookieGenerator_RFC9018_TimeRenew(t *testing.T) {
	cg := NewCookieGenerator()
	clientIP := net.ParseIP("192.168.1.1")
	clientCookie := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	origNow := timeNow
	defer func() { timeNow = origNow }()

	now := origNow()
	cookie := cg.GenerateServerCookie(clientIP, clientCookie)

	// Advance clock past renew threshold (> 30 min but < 1 hour)
	timeNow = func() uint32 { return now + 1801 }
	status := cg.IsServerCookieValid(clientIP, clientCookie, cookie)
	if status != CookieValidRenew {
		t.Errorf("renew cookie status = %d, want CookieValidRenew", status)
	}
}

func TestCookieGenerator_RFC9018_TimeFuture(t *testing.T) {
	cg := NewCookieGenerator()
	clientIP := net.ParseIP("192.168.1.1")
	clientCookie := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	origNow := timeNow
	defer func() { timeNow = origNow }()

	// Advance clock 1 hour, generate cookie with future timestamp
	now := origNow()
	timeNow = func() uint32 { return now + 3600 }
	cookie := cg.GenerateServerCookie(clientIP, clientCookie)

	// Restore clock → cookie timestamp is 1 hour in the future (>5 min limit)
	timeNow = origNow
	status := cg.IsServerCookieValid(clientIP, clientCookie, cookie)
	if status != CookieFuture {
		t.Errorf("future cookie status = %d, want CookieFuture (%d)", status, CookieFuture)
	}
}

func TestApplyToMessage_Keepalive(t *testing.T) {
	h, _ := NewHandler(config.ECSConfig{})
	msg := new(dns.Msg)
	dnsutil.SetQuestion(msg, "example.com.", dns.TypeA)

	// tcpKeepaliveTimeout=0 → no keepalive option in response
	h.ApplyToMessage(msg, nil, false, "", nil, false, true, 0)
	for _, o := range msg.Pseudo {
		if _, ok := o.(*dns.TCPKEEPALIVE); ok {
			t.Error("unexpected keepalive option with timeout=0")
		}
	}

	// tcpKeepaliveTimeout=1200 → keepalive option present in response
	msg2 := new(dns.Msg)
	dnsutil.SetQuestion(msg2, "example.com.", dns.TypeA)
	h.ApplyToMessage(msg2, nil, false, "", nil, false, true, 1200)
	var found bool
	for _, o := range msg2.Pseudo {
		if ka, ok := o.(*dns.TCPKEEPALIVE); ok {
			found = true
			if ka.Timeout != 1200 {
				t.Errorf("expected timeout=1200, got %d", ka.Timeout)
			}
		}
	}
	if !found {
		t.Error("expected keepalive option with timeout=1200")
	}

	// tcpKeepaliveTimeout=1200 but isRequest=true → no keepalive (client-side)
	msg3 := new(dns.Msg)
	dnsutil.SetQuestion(msg3, "example.com.", dns.TypeA)
	h.ApplyToMessage(msg3, nil, false, "", nil, true, true, 1200)
	for _, o := range msg3.Pseudo {
		if _, ok := o.(*dns.TCPKEEPALIVE); ok {
			t.Error("keepalive should not be included in requests")
		}
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
