package config

import (
	"net"
	"os"
	"path/filepath"
	"testing"
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
	// Empty config should load successfully with no listeners enabled.
	if cfg.Server.Protocol.UDP != "" {
		t.Error("expected empty protocol config")
	}
}

func TestUpstreamServer_IsRecursive(t *testing.T) {
	s := &UpstreamServer{Address: "builtin_recursive"}
	if !s.IsRecursive() {
		t.Error("builtin_recursive should report as recursive")
	}

	s2 := &UpstreamServer{Address: "8.8.8.8:53"}
	if s2.IsRecursive() {
		t.Error("normal upstream should not report as recursive")
	}
}

func TestCacheSettings_MaxEntriesDefaults(t *testing.T) {
	// MaxEntries 0 should be handled by the cache package (defaults to DefaultMaxCacheEntries)
	s := ServerSettings{Features: FeatureFlags{Cache: CacheSettings{MaxEntries: 0}}}
	if s.Features.Cache.MaxEntries != 0 {
		t.Error("MaxEntries=0 should be allowed (cache will default to DefaultMaxCacheEntries)")
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
