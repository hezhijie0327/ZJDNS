package tlcp

import (
	"net"
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

// TestSelfSignedSMCertIPSAN pins the Round 6 audit P8 fix: an IP-literal
// domain must populate the iPAddress SAN (SM2 clients match IPs there), not
// DNSNames — the pre-fix template stuffed the IP into DNSNames, so TLCP/
// DTLCP certificate verification failed on IP deployments while the TLS
// twin path worked.
func TestSelfSignedSMCertIPSAN(t *testing.T) {
	signCert, _, _, _, err := generateSelfSignedSMCerts("192.0.2.1")
	if err != nil {
		t.Fatalf("generateSelfSignedSMCerts: %v", err)
	}
	leaf, err := smx509.ParseCertificate(signCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("IPAddresses = %v, want [192.0.2.1]", leaf.IPAddresses)
	}
	if len(leaf.DNSNames) != 0 {
		t.Errorf("DNSNames = %v, want empty for an IP-literal domain", leaf.DNSNames)
	}
	if err := leaf.VerifyHostname("192.0.2.1"); err != nil {
		t.Errorf("192.0.2.1 does not match cert: %v", err)
	}
}
