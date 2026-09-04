package cli

import (
	"os"
	"path/filepath"
	"testing"
	"zjdns/config"
)

// TestGenerateExampleConfigRoundTrip verifies the --generate-config output
// passes the full LoadConfig validation pipeline — the example must always be
// loadable, not just marshalled.
func TestGenerateExampleConfigRoundTrip(t *testing.T) {
	out, err := generateExampleConfig()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.example.json")
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatalf("generated config fails LoadConfig: %v", err)
	}
	if len(cfg.Upstream) == 0 || len(cfg.Zone) == 0 || len(cfg.RuleSet) == 0 {
		t.Fatalf("generated config missing sections: upstream=%d zone=%d ruleset=%d",
			len(cfg.Upstream), len(cfg.Zone), len(cfg.RuleSet))
	}
}
