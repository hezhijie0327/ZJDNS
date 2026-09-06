package tls

import (
	"crypto/x509"
	"testing"
)

func TestSelfSignedCertWildcardSAN(t *testing.T) {
	cert, err := generateSelfSignedCert("dns.example.org")
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	want := map[string]bool{"dns.example.org": false, "*.dns.example.org": false, "alice.dns.example.org": false}
	for _, name := range leaf.DNSNames {
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
	if !want["dns.example.org"] || !want["*.dns.example.org"] {
		t.Errorf("SANs = %v, want both dns.example.org and *.dns.example.org", leaf.DNSNames)
	}
	// The wildcard must actually validate the client-name form.
	if err := leaf.VerifyHostname("alice.dns.example.org"); err != nil {
		t.Errorf("alice.dns.example.org does not match cert: %v", err)
	}
}
