package config

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"codeberg.org/miekg/dns"
)

func TestLoadConfig_DefaultPortsApplied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"server": {"protocol": {"udp": "53", "tls": "853"}, "certificate": {"domain": "test.example.com"}}, "upstream": [{"address": "8.8.8.8:53", "protocol": "udp"}]}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Server.Protocol.TLS != "853" {
		t.Errorf("TLS port = %q, want 853", cfg.Server.Protocol.TLS)
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.json")
	if err == nil {
		t.Error("expected error for nonexistent config file")
	}
}

func TestLoadConfig_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadConfig_MissingServer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	// An empty config file starts from the defaults: omitted fields keep
	// their default behavior (ports, DNSSEC enforcement, ECS). Explicitly
	// empty protocol values in JSON still disable that listener.
	if cfg.Server.Protocol.UDP != DefaultUDPPort {
		t.Errorf("empty config should keep default UDP port, got %q", cfg.Server.Protocol.UDP)
	}
	if !cfg.Server.Features.DNSSECEnforce {
		t.Error("empty config should keep default dnssec_enforce=true")
	}
}

func TestUpstreamServer_IsRecursive(t *testing.T) {
	s := &UpstreamServer{Protocol: ProtoRecursive}
	if !s.IsRecursive() {
		t.Error("protocol=recursive should report as recursive")
	}

	s2 := &UpstreamServer{Address: "8.8.8.8:53"}
	if s2.IsRecursive() {
		t.Error("normal upstream should not report as recursive")
	}
}

func TestECSOption_Normalize(t *testing.T) {
	tests := []struct {
		name   string
		opt    *ECSOption
		wantIP string
	}{
		{
			name:   "nil option",
			opt:    nil,
			wantIP: "",
		},
		{
			name:   "nil address",
			opt:    &ECSOption{Family: 1, SourcePrefix: 24, Address: nil},
			wantIP: "",
		},
		{
			name:   "zero prefix",
			opt:    &ECSOption{Family: 1, SourcePrefix: 0, Address: net.ParseIP("1.2.3.4")},
			wantIP: "1.2.3.4",
		},
		{
			name:   "IPv4 /24 masks to network",
			opt:    &ECSOption{Family: 1, SourcePrefix: 24, Address: net.ParseIP("101.132.169.46")},
			wantIP: "101.132.169.0",
		},
		{
			name:   "IPv4 /24 already network",
			opt:    &ECSOption{Family: 1, SourcePrefix: 24, Address: net.ParseIP("101.132.169.0")},
			wantIP: "101.132.169.0",
		},
		{
			name:   "IPv6 /64 masks to network",
			opt:    &ECSOption{Family: 2, SourcePrefix: 64, Address: net.ParseIP("2408:4002:100b:6900:d57c:9d51:9858:25a4")},
			wantIP: "2408:4002:100b:6900::",
		},
		{
			name:   "IPv4 /32 keeps host",
			opt:    &ECSOption{Family: 1, SourcePrefix: 32, Address: net.ParseIP("192.168.1.100")},
			wantIP: "192.168.1.100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.opt.Normalize()
			if tt.opt == nil {
				if tt.wantIP != "" {
					t.Error("expected non-nil option")
				}
				return
			}
			if tt.wantIP == "" {
				if tt.opt.Address != nil {
					t.Errorf("Address = %v, want nil", tt.opt.Address)
				}
				return
			}
			if tt.opt.Address.String() != tt.wantIP {
				t.Errorf("Address = %v, want %v", tt.opt.Address, tt.wantIP)
			}
		})
	}
}

func TestUpstreamServer_DefenseFlagsParsed(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantPG  bool
		wantSG  bool
		wantHG  bool
		wantSpG bool
	}{
		{"all on", `[{"protocol":"recursive","poisonguard":true,"spoofguard":true,"splitguard":true,"hopguard":true}]`, true, true, true, true},
		{"all off", `[{"address":"8.8.8.8:53","protocol":"udp"}]`, false, false, false, false},
		{"only poisonguard", `[{"protocol":"recursive","poisonguard":true}]`, true, false, false, false},
		{"only spoofguard", `[{"address":"8.8.8.8:53","spoofguard":true}]`, false, true, false, false},
		{"only splitguard", `[{"address":"1.2.4.8:53","protocol":"tcp","splitguard":true}]`, false, false, false, true},
		{"only hopguard", `[{"address":"8.8.8.8:53","hopguard":true}]`, false, false, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			path := filepath.Join(tmpDir, "config.json")
			cfg := `{"server":{"protocol":{"udp":"53535"},"certificate":{"domain":"test.example.com"}},"upstream":` + tt.json + `}`
			if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := LoadConfig(path)
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			if len(c.Upstream) != 1 {
				t.Fatalf("expected 1 upstream, got %d", len(c.Upstream))
			}
			u := c.Upstream[0]
			if u.Poisonguard != tt.wantPG {
				t.Errorf("Poisonguard = %v, want %v", u.Poisonguard, tt.wantPG)
			}
			if u.Spoofguard != tt.wantSG {
				t.Errorf("Spoofguard = %v, want %v", u.Spoofguard, tt.wantSG)
			}
			if u.Splitguard != tt.wantSpG {
				t.Errorf("Splitguard = %v, want %v", u.Splitguard, tt.wantSpG)
			}
			if u.HopGuard != tt.wantHG {
				t.Errorf("HopGuard = %v, want %v", u.HopGuard, tt.wantHG)
			}
		})
	}
}

func TestValidateUpstreamServers_InvalidProtocol(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.json")
	cfg := `{"server":{"protocol":{"udp":"53535"},"certificate":{"domain":"test.example.com"}},"upstream":[{"address":"8.8.8.8:53","protocol":"invalid_proto"}]}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(path)
	if err == nil {
		t.Error("expected error for invalid protocol")
	}
}

func TestValidateUpstreamServers_EmptyAddress(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.json")
	cfg := `{"server":{"protocol":{"udp":"53535"},"certificate":{"domain":"test.example.com"}},"upstream":[{"protocol":"udp"}]}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(path)
	if err == nil {
		t.Error("expected error for empty upstream address")
	}
}

func TestDDRRecords_AllProtocolsEnabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	// Enable every encrypted protocol; HTTPS + HTTP3 share port 443,
	// TLS + QUIC share port 853, TLCP + DTLCP share port 9853.
	cfg := `{
		"server": {
			"protocol": {
				"tls": "853",
				"quic": "853",
				"https": {"port": "443", "endpoint": "/dns-query"},
				"http3": {"port": "443", "endpoint": "/dns-query"},
				"dtls": "8853",
				"tlcp": "9853",
				"http_tlcp": {"port": "9443", "endpoint": "/dns-query"},
				"dtlcp": "9853"
			},
			"certificate": {"domain": "dns.example.com"},
			"features": {"ddr": {"ipv4": "127.0.0.1", "ipv6": "::1"}}
		}
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	// Find the _dns.resolver.arpa zone rule.
	var svcbRecords []ZoneRecord
	for _, zr := range c.Zone {
		if zr.Name == "_dns.resolver.arpa" {
			svcbRecords = zr.Answer
			break
		}
	}
	if len(svcbRecords) == 0 {
		t.Fatal("no SVCB records for _dns.resolver.arpa")
	}

	// Expected: 5 records aggregated by port.
	// Port 443: HTTPS(h2) + HTTP3(h3) → alpn=h2,h3 + dohpath
	// Port 9443: HTTP_TLCP(h2) → alpn=h2 + dohpath
	// Port 853: TLS(dot) + QUIC(doq) → alpn=doq,dot
	// Port 8853: DTLS(dot) → alpn=dot
	// Port 9853: TLCP(dot) + DTLCP(dot) → alpn=dot
	want := []string{
		`1 dns.example.com alpn=h2,h3 port=443 dohpath="/dns-query{?dns}" ipv4hint=127.0.0.1 ipv6hint=::1`,
		`2 dns.example.com alpn=h2 port=9443 dohpath="/dns-query{?dns}" ipv4hint=127.0.0.1 ipv6hint=::1`,
		`3 dns.example.com alpn=doq,dot port=853 ipv4hint=127.0.0.1 ipv6hint=::1`,
		`4 dns.example.com alpn=dot port=8853 ipv4hint=127.0.0.1 ipv6hint=::1`,
		`5 dns.example.com alpn=dot port=9853 ipv4hint=127.0.0.1 ipv6hint=::1`,
	}
	if len(svcbRecords) != len(want) {
		t.Fatalf("got %d SVCB records, want %d:\n%v", len(svcbRecords), len(want), svcbRecords)
	}
	for i, w := range want {
		if svcbRecords[i].Type != dns.TypeSVCB {
			t.Errorf("record %d: Type = %d, want SVCB(%d)", i, svcbRecords[i].Type, dns.TypeSVCB)
		}
		if svcbRecords[i].Content != w {
			t.Errorf("record %d:\n  got  %s\n  want %s", i, svcbRecords[i].Content, w)
		}
	}

	// Verify the domain zone rule also exists.
	foundDomain := false
	for _, zr := range c.Zone {
		if zr.Name == "dns.example.com" {
			foundDomain = true
			break
		}
	}
	if !foundDomain {
		t.Error("missing A/AAAA zone rule for dns.example.com")
	}
}

func TestDDRRecords_HTTPSOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := `{
		"server": {
			"protocol": {
				"udp": "", "tcp": "", "tls": "", "quic": "", "http3": {"port": ""},
				"dtls": "", "dnscrypt": "", "tlcp": "", "http_tlcp": {"port": ""}, "dtlcp": "",
				"https": {"port": "443", "endpoint": "/dns-query"}
			},
			"certificate": {"domain": "dns.example.com"},
			"features": {"ddr": {"ipv4": "1.2.3.4", "ipv6": ""}}
		}
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	var svcbRecords []ZoneRecord
	for _, zr := range c.Zone {
		if zr.Name == "_dns.resolver.arpa" {
			svcbRecords = zr.Answer
			break
		}
	}
	if len(svcbRecords) != 1 {
		t.Fatalf("got %d SVCB records, want 1", len(svcbRecords))
	}
	want := `1 dns.example.com alpn=h2 port=443 dohpath="/dns-query{?dns}" ipv4hint=1.2.3.4`
	if svcbRecords[0].Content != want {
		t.Errorf("got  %s\nwant %s", svcbRecords[0].Content, want)
	}
}

func TestDDRRecords_DifferentPorts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	// TLS on 853, QUIC on 784 (different); DTLS separate on 8853 → 3 records.
	cfg := `{
		"server": {
			"protocol": {
				"udp": "", "tcp": "", "https": {"port": ""}, "http3": {"port": ""},
				"dnscrypt": "", "tlcp": "", "http_tlcp": {"port": ""}, "dtlcp": "",
				"tls": "853",
				"quic": "784",
				"dtls": "8853"
			},
			"certificate": {"domain": "dns.example.com"},
			"features": {"ddr": {"ipv4": "10.0.0.1", "ipv6": ""}}
		}
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	var svcbRecords []ZoneRecord
	for _, zr := range c.Zone {
		if zr.Name == "_dns.resolver.arpa" {
			svcbRecords = zr.Answer
			break
		}
	}
	if len(svcbRecords) != 3 {
		t.Fatalf("got %d SVCB records, want 3", len(svcbRecords))
	}
	// Sorted: stream group by port → 784 < 853 < 8853
	// Port 784: QUIC(doq) only
	want0 := `1 dns.example.com alpn=doq port=784 ipv4hint=10.0.0.1`
	if svcbRecords[0].Content != want0 {
		t.Errorf("record 0:\n  got  %s\n  want %s", svcbRecords[0].Content, want0)
	}
	// Port 853: TLS(dot) only
	want1 := `2 dns.example.com alpn=dot port=853 ipv4hint=10.0.0.1`
	if svcbRecords[1].Content != want1 {
		t.Errorf("record 1:\n  got  %s\n  want %s", svcbRecords[1].Content, want1)
	}
	// Port 8853: DTLS(dot) only
	want2 := `3 dns.example.com alpn=dot port=8853 ipv4hint=10.0.0.1`
	if svcbRecords[2].Content != want2 {
		t.Errorf("record 2:\n  got  %s\n  want %s", svcbRecords[2].Content, want2)
	}
}

func TestDDRRecords_TLSAndDTLS_SamePort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	// TLS (TCP) and DTLS (UDP) on the same port — same ALPN (dot),
	// different transports, no port conflict.  Should merge into one record.
	cfg := `{
		"server": {
			"protocol": {
				"udp": "", "tcp": "", "https": {"port": ""}, "http3": {"port": ""},
				"quic": "", "dnscrypt": "", "tlcp": "", "http_tlcp": {"port": ""}, "dtlcp": "",
				"tls": "853",
				"dtls": "853"
			},
			"certificate": {"domain": "dns.example.com"},
			"features": {"ddr": {"ipv4": "10.0.0.1", "ipv6": ""}}
		}
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	var svcbRecords []ZoneRecord
	for _, zr := range c.Zone {
		if zr.Name == "_dns.resolver.arpa" {
			svcbRecords = zr.Answer
			break
		}
	}
	if len(svcbRecords) != 1 {
		t.Fatalf("got %d SVCB records, want 1 (merged)", len(svcbRecords))
	}
	want := `1 dns.example.com alpn=dot port=853 ipv4hint=10.0.0.1`
	if svcbRecords[0].Content != want {
		t.Errorf("got  %s\nwant %s", svcbRecords[0].Content, want)
	}
}

func TestDDRRecords_NoSecureProtocols(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	// DDR configured but no secure protocols enabled → should be skipped.
	cfg := `{
		"server": {
			"protocol": {
				"udp": "53", "tcp": "", "tls": "", "quic": "",
				"https": {"port": ""}, "http3": {"port": ""}, "dtls": "",
				"dnscrypt": "", "tlcp": "", "http_tlcp": {"port": ""}, "dtlcp": ""
			},
			"certificate": {"domain": "dns.example.com"},
			"features": {"ddr": {"ipv4": "127.0.0.1"}}
		}
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	for _, zr := range c.Zone {
		if zr.Name == "_dns.resolver.arpa" {
			t.Error("DDR should be disabled when no secure protocols are enabled")
		}
	}
}

func TestDDRRecords_Disabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	// DDR enabled but no certificate domain → should be skipped.
	cfg := `{
		"server": {
			"protocol": {
				"udp": "", "tcp": "", "tls": "", "quic": "",
				"https": {"port": ""}, "http3": {"port": ""}, "dtls": "",
				"dnscrypt": "", "tlcp": "", "http_tlcp": {"port": ""}, "dtlcp": ""
			},
			"certificate": {"domain": ""},
			"features": {"ddr": {"ipv4": "127.0.0.1"}}
		}
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	for _, zr := range c.Zone {
		if zr.Name == "_dns.resolver.arpa" {
			t.Error("DDR should be disabled when certificate.domain is missing")
		}
	}
}

func TestValidateConfig_MissingCertDomain(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.json")
	cfg := `{"server":{"protocol":{"tls":"853"},"certificate":{"domain":""}},"upstream":[{"address":"8.8.8.8:53"}]}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(path)
	if err == nil {
		t.Error("expected error for TLS without cert domain")
	}
}
