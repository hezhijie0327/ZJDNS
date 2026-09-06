package tlcp

import (
	"testing"

	"github.com/emmansun/gmsm/smx509"
)

func TestSelfSignedSMCertWildcardSAN(t *testing.T) {
	signCert, _, _, _, err := generateSelfSignedSMCerts("dns.example.org")
	if err != nil {
		t.Fatalf("generateSelfSignedSMCerts: %v", err)
	}
	leaf, err := smx509.ParseCertificate(signCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	found := map[string]bool{"dns.example.org": false, "*.dns.example.org": false}
	for _, name := range leaf.DNSNames {
		if _, ok := found[name]; ok {
			found[name] = true
		}
	}
	if !found["dns.example.org"] || !found["*.dns.example.org"] {
		t.Errorf("SANs = %v, want both dns.example.org and *.dns.example.org", leaf.DNSNames)
	}
	if err := leaf.VerifyHostname("alice.dns.example.org"); err != nil {
		t.Errorf("alice.dns.example.org does not match cert: %v", err)
	}
}
