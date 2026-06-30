package cli

import (
	"strings"
	"time"

	"zjdns/config"
	serverdnscrypt "zjdns/server/dnscrypt"
)

// GenerateDNSCryptKeys generates a new DNSCrypt resolver key set and returns
// the canonical JSON config snippet (server + upstream entry).
//
// certTTL and esVersion are optional; 0 means use defaults (24h / XSalsa20Poly1305).
func GenerateDNSCryptKeys(providerName string, certTTL, esVersion int) string {
	ttl := config.DefaultDNSCryptCertValidity
	if certTTL > 0 {
		ttl = time.Duration(certTTL) * time.Second
	}

	keys, err := serverdnscrypt.GenerateKeys(providerName, esVersion, ttl)
	if err != nil {
		return "Error: " + err.Error()
	}

	fullProviderName := providerName
	if !strings.HasPrefix(fullProviderName, "2.dnscrypt-cert.") {
		fullProviderName = "2.dnscrypt-cert." + fullProviderName
	}

	return serverdnscrypt.BuildKeysJSON(
		config.DefaultDNSCryptPort,
		providerName,
		fullProviderName,
		keys.PrivateKey,
		keys.PublicKey,
		keys.ResolverSk,
		keys.ResolverPk,
		int(ttl/time.Second),
		esVersion,
	)
}
