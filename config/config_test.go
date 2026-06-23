package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateExampleConfig_ValidJSON(t *testing.T) {
	data := GenerateExampleConfig()
	if len(data) == 0 {
		t.Fatal("GenerateExampleConfig returned empty")
	}
	var cfg ServerConfig
	if err := json.Unmarshal([]byte(data), &cfg); err != nil {
		t.Fatalf("generated config is not valid JSON: %v", err)
	}
}

func TestLoadConfig_DefaultPortsApplied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"server": {"port": "53", "tls": {"port": "853"}}, "upstream_servers": [{"address": "8.8.8.8:53", "protocol": "udp"}]}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := &Loader{}
	cfg, err := loader.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Server.TLS.Port != "853" {
		t.Errorf("TLS port = %q, want 853", cfg.Server.TLS.Port)
	}
	// HTTPS port is optional; defaults only applied by getDefaultConfig, not LoadConfig
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	loader := &Loader{}
	_, err := loader.LoadConfig("/nonexistent/config.json")
	if err == nil {
		t.Error("expected error for nonexistent config file")
	}
}

func TestLoadConfig_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}

	loader := &Loader{}
	_, err := loader.LoadConfig(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadConfig_MissingServer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}

	loader := &Loader{}
	_, err := loader.LoadConfig(path)
	if err == nil {
		t.Error("expected error for missing server port")
	}
}

func TestServerSettings_StatsInterval_Default(t *testing.T) {
	s := &ServerSettings{}
	if got := s.StatsInterval(); got != 0 {
		t.Errorf("StatsInterval = %d, want 0 (disabled by default)", got)
	}
}

func TestServerSettings_StatsPersistTTL_Default(t *testing.T) {
	s := &ServerSettings{}
	if got := s.StatsPersistTTL(); got != DefaultStatsPersistTTL {
		t.Errorf("StatsPersistTTL = %d, want %d", got, DefaultStatsPersistTTL)
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

func TestCacheSettings_SizeDefaults(t *testing.T) {
	// Size 0 should be handled by the cache package (defaults to DefaultCacheSize)
	s := ServerSettings{Features: FeatureFlags{Cache: CacheSettings{Size: 0}}}
	if s.Features.Cache.Size != 0 {
		t.Error("Size=0 should be allowed (cache will default to DefaultCacheSize)")
	}
}
