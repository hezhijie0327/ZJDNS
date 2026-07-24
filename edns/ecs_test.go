package edns

import (
	"net"
	"net/netip"
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

// TestParseFromDNS_ClientSubnetRoundTrip verifies that an ECS subnet sent by
// a client is correctly parsed from the incoming DNS message and re-applied
// to the response via ApplyToMessage.  This ensures the client's own subnet
// is echoed back rather than replaced by the server's default ECS.
func TestParseFromDNS_ClientSubnetRoundTrip(t *testing.T) {
	h, err := NewHandler(config.ECSConfig{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	tests := []struct {
		name    string
		family  uint16
		netmask uint8
		address string
	}{
		{"IPv4 /32", 1, 32, "101.132.169.0"},
		{"IPv4 /24", 1, 24, "10.0.0.0"},
		{"IPv4 /0", 1, 0, "0.0.0.0"},
		{"IPv6 /64", 2, 64, "2001:db8::"},
		{"IPv6 /128", 2, 128, "2001:db8::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build an incoming request message carrying the client's ECS.
			req := new(dns.Msg)
			dnsutil.SetQuestion(req, "example.com.", dns.TypeA)
			req.Pseudo = append(req.Pseudo, &dns.SUBNET{
				Family:  tt.family,
				Netmask: tt.netmask,
				Scope:   0,
				Address: netip.MustParseAddr(tt.address),
			})

			// Parse the ECS from the incoming request.
			parsed := h.ParseFromDNS(req)
			if parsed == nil {
				t.Fatal("ParseFromDNS returned nil for client ECS")
			}
			if parsed.Family != tt.family {
				t.Errorf("Family = %d, want %d", parsed.Family, tt.family)
			}
			if parsed.SourcePrefix != tt.netmask {
				t.Errorf("SourcePrefix = %d, want %d", parsed.SourcePrefix, tt.netmask)
			}
			if !parsed.Address.Equal(net.ParseIP(tt.address)) {
				t.Errorf("Address = %s, want %s", parsed.Address, tt.address)
			}

			// Apply the parsed ECS to a response message.
			resp := new(dns.Msg)
			dnsutil.SetReply(resp, req)
			h.ApplyToMessage(resp, parsed, false, "", nil, false, true, 0)

			// Verify the response contains the client's SUBNET.
			var found bool
			for _, rr := range resp.Pseudo {
				subnet, ok := rr.(*dns.SUBNET)
				if !ok {
					continue
				}
				found = true
				if subnet.Family != tt.family {
					t.Errorf("response Family = %d, want %d", subnet.Family, tt.family)
				}
				if subnet.Netmask != tt.netmask {
					t.Errorf("response Netmask = %d, want %d", subnet.Netmask, tt.netmask)
				}
				if subnet.Scope != DefaultECSScope {
					t.Errorf("response Scope = %d, want %d", subnet.Scope, DefaultECSScope)
				}
				wantAddr := netip.MustParseAddr(tt.address)
				if subnet.Address != wantAddr {
					t.Errorf("response Address = %s, want %s", subnet.Address, wantAddr)
				}
			}
			if !found {
				t.Error("response missing SUBNET pseudo record")
			}
		})
	}
}

// TestParseFromDNS_NoECS ensures a request without an ECS option returns nil.
func TestParseFromDNS_NoECS(t *testing.T) {
	h, err := NewHandler(config.ECSConfig{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := new(dns.Msg)
	dnsutil.SetQuestion(req, "example.com.", dns.TypeA)
	// No Pseudo record — no ECS.

	parsed := h.ParseFromDNS(req)
	if parsed != nil {
		t.Errorf("expected nil for request without ECS, got %+v", parsed)
	}
}

// TestParseFromDNS_OnlyCookie ensures ParseFromDNS returns nil when the
// request has a COOKIE but no SUBNET (it must not return the cookie as ECS).
func TestParseFromDNS_OnlyCookie(t *testing.T) {
	h, err := NewHandler(config.ECSConfig{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := new(dns.Msg)
	dnsutil.SetQuestion(req, "example.com.", dns.TypeA)
	req.Pseudo = append(req.Pseudo, &dns.COOKIE{Cookie: "0102030405060708090a0b0c0d0e0f10"})

	parsed := h.ParseFromDNS(req)
	if parsed != nil {
		t.Errorf("expected nil when only cookie is present, got %+v", parsed)
	}
}
