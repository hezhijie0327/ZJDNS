package config

import (
	"strings"
	"testing"
)

// TestValidateTLSCertificateConfig_NoCertWithTLSFamily pins the Round 6 D2
// fix: any enabled TLS-family protocol without certificate.tls fails
// validation up front — previously validation passed and the listener was
// silently not created (server/protocols.go gates every TLS-family listener
// on Certificate.TLS.IsEnabled()).
func TestValidateTLSCertificateConfig_NoCertWithTLSFamily(t *testing.T) {
	for name, set := range map[string]func(*ProtocolSettings){
		"tls":   func(p *ProtocolSettings) { p.TLS = "853" },
		"quic":  func(p *ProtocolSettings) { p.QUIC = "853" },
		"https": func(p *ProtocolSettings) { p.HTTPS.Port = "443" },
		"http3": func(p *ProtocolSettings) { p.HTTP3.Port = "443" },
		"dtls":  func(p *ProtocolSettings) { p.DTLS = "853" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &ServerConfig{}
			set(&cfg.Server.Protocol)
			err := validateTLSCertificateConfig(cfg)
			if err == nil {
				t.Fatalf("%s listener without certificate.tls passed validation — the listener would silently never be created", name)
			}
			if !strings.Contains(err.Error(), "certificate.tls") {
				t.Fatalf("error = %v, want a certificate.tls requirement", err)
			}
		})
	}
}

// TestValidateTLSCertificateConfig_DTLSOnlyBadCertPath pins the DTLS gap: a
// DTLS-only deployment's cert/key files must run the same checks as every
// other TLS-family protocol (DTLS was missing from tlsEnabled, deferring file
// errors to listener init).
func TestValidateTLSCertificateConfig_DTLSOnlyBadCertPath(t *testing.T) {
	cfg := &ServerConfig{}
	cfg.Server.Protocol.DTLS = "853"
	cfg.Server.Certificate.TLS = TLSCertificate{CertFile: "/nonexistent/cert.pem", KeyFile: "/nonexistent/key.pem"}
	err := validateTLSCertificateConfig(cfg)
	if err == nil {
		t.Fatal("DTLS-only config with missing cert files passed validation")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("error = %v, want the cert-file-not-found path", err)
	}
}
