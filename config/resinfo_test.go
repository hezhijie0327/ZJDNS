package config

import (
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
)

// testDDRConfig returns a config that passes shouldEnableDDR: certificate
// domain + IP hint + an encrypted protocol listener.
func testDDRConfig(infoURL string) *ServerConfig {
	cfg := &ServerConfig{
		Server: ServerSettings{
			Certificate: CertificateSettings{Domain: "dns.example.com"},
			Protocol:    ProtocolSettings{TLS: "853"},
			Features:    FeatureFlags{DDR: DDRSettings{IPv4: "127.0.0.1", InfoURL: infoURL}},
		},
	}
	return cfg
}

// TestAddResolverInfoRecords verifies RFC 9606 RESINFO zone-rule injection:
// with DDR enabled, resolver.arpa gets a RESINFO record with the advertised
// keys, and the optional infourl key appears only when configured.
func TestAddResolverInfoRecords(t *testing.T) {
	cfg := testDDRConfig("https://dns.example.com/help")
	addResolverInfoRecords(cfg)

	found := false
	for _, rule := range cfg.Zone {
		if rule.Name != "resolver.arpa" {
			continue
		}
		if len(rule.Answer) != 1 {
			t.Fatalf("resolver.arpa rule has %d answers, want 1", len(rule.Answer))
		}
		rec := rule.Answer[0]
		if rec.Type != dns.TypeRESINFO {
			t.Errorf("answer type = %d, want RESINFO(261)", rec.Type)
		}
		if rec.Class != dns.ClassINET {
			t.Errorf("answer class = %d, want IN", rec.Class)
		}
		if !strings.Contains(rec.Content, "qnamemin") {
			t.Errorf("content missing qnamemin: %q", rec.Content)
		}
		if !strings.Contains(rec.Content, "exterr=") {
			t.Errorf("content missing exterr: %q", rec.Content)
		}
		if !strings.Contains(rec.Content, `infourl=https://dns.example.com/help`) {
			t.Errorf("content missing infourl: %q", rec.Content)
		}
		found = true
	}
	if !found {
		t.Fatal("resolver.arpa RESINFO rule not injected")
	}
}

// TestAddResolverInfoRecords_NoInfoURL verifies infourl is omitted when unset.
func TestAddResolverInfoRecords_NoInfoURL(t *testing.T) {
	cfg := testDDRConfig("")
	addResolverInfoRecords(cfg)

	for _, rule := range cfg.Zone {
		if rule.Name == "resolver.arpa" {
			if strings.Contains(rule.Answer[0].Content, "infourl=") {
				t.Errorf("infourl must be omitted when unset: %q", rule.Answer[0].Content)
			}
			return
		}
	}
	t.Fatal("resolver.arpa RESINFO rule not injected")
}

// TestAddResolverInfoRecords_DDRDisabled verifies RESINFO is not injected
// when DDR is disabled (no certificate domain / no encrypted listener).
func TestAddResolverInfoRecords_DDRDisabled(t *testing.T) {
	cfg := &ServerConfig{
		Server: ServerSettings{
			Features: FeatureFlags{DDR: DDRSettings{InfoURL: "https://dns.example.com/help"}},
		},
	}
	addResolverInfoRecords(cfg)
	for _, rule := range cfg.Zone {
		if rule.Name == "resolver.arpa" {
			t.Fatal("RESINFO must not be injected when DDR is disabled")
		}
	}
}
