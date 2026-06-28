package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"zjdns/config"
	dnscrypt "zjdns/server/dnscrypt"
)

// GenerateDNSCryptKeys generates a DNSCrypt v2 Ed25519 key pair and returns a
// JSON config snippet with server-side and client-side settings.
func GenerateDNSCryptKeys(providerName string, certTTLHours int, esVersion string) string {
	if providerName == "" {
		providerName = config.DefaultDNSCryptProviderName
	} else {
		providerName = config.NormalizeDNSCryptProviderName(providerName)
	}
	certTTL := time.Duration(certTTLHours) * time.Second
	if certTTL <= 0 {
		certTTL = config.DefaultDNSCryptCertTTL
		certTTLHours = int(config.DefaultDNSCryptCertTTL.Seconds())
	}

	esVersionStr := strings.ToLower(strings.TrimSpace(esVersion))
	cryptoCon := dnscrypt.XSalsa20Poly1305
	switch esVersionStr {
	case "xchacha20", "xchacha20poly1305":
		cryptoCon = dnscrypt.XChacha20Poly1305
	}

	// Generate Ed25519 provider key pair (long-term signing key).
	providerPK, providerSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Sprintf(`{"error": "failed to generate Ed25519 key: %v"}`, err)
	}

	_, err = dnscrypt.GenerateCertificate(providerSK, cryptoCon, certTTL)
	if err != nil {
		return fmt.Sprintf(`{"error": "failed to generate certificate: %v"}`, err)
	}

	skHex := hex.EncodeToString(providerSK)
	pkHex := hex.EncodeToString(providerPK)
	addr := "127.0.0.1:" + config.DefaultDNSCryptPort

	data, _ := json.MarshalIndent(map[string]any{
		"server": config.DNSCryptSettings{
			Port:         config.DefaultDNSCryptPort,
			ProviderName: providerName,
			PrivateKey:   skHex,
			CertTTL:      certTTLHours,
			ESVersion:    esVersionStr,
		},
		"client": config.UpstreamServer{
			Address:           addr,
			Protocol:          config.ProtoDNSCrypt,
			ServerName:        providerName,
			DNSCryptPublicKey: pkHex,
		},
	}, "", "  ")
	return string(data)
}
