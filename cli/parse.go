package cli

import (
	"flag"
	"fmt"
	"os"
)

// ParseFlags parses command-line arguments and handles special commands
// (-version, -generate-config, -generate-dnscrypt-keys, -dns-stamp).
// Returns the config file path (empty for default config) and whether the
// caller should exit (true after running a special command).
func ParseFlags(osArgs []string, versionStr string) (configFile string, exitAfter bool) {
	var (
		configFileFlag    string
		generateConfig    bool
		generateDNSCrypt  bool
		dnscryptProvider  string
		dnscryptCertTTL   int
		dnscryptESVersion string
		stampStr          string
		showVersion       bool
	)

	fs := flag.NewFlagSet(osArgs[0], flag.ContinueOnError)
	fs.StringVar(&configFileFlag, "config", "", "Configuration file path (JSON format)")
	fs.BoolVar(&generateConfig, "generate-config", false, "Generate example configuration file")
	fs.BoolVar(&generateDNSCrypt, "generate-dnscrypt-keys", false, "Generate DNSCrypt v2 key pair and config snippet")
	fs.StringVar(&dnscryptProvider, "provider-name", "", "Provider name for DNSCrypt key generation")
	fs.IntVar(&dnscryptCertTTL, "cert-ttl", 0, "Certificate TTL in seconds (default: 31536000)")
	fs.StringVar(&dnscryptESVersion, "es-version", "", "Crypto construction: xsalsa20 (default), xchacha20, xwing-pq")
	fs.StringVar(&stampStr, "dns-stamp", "", "Decode a DNS stamp (sdns://) and output config snippet")
	fs.BoolVar(&showVersion, "version", false, "Show version information and exit")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "ZJDNS Server - High Performance DNS Server\n\n")
		fmt.Fprintf(os.Stderr, "Version: %s\n\n", versionStr)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s -config <config file>     # Start with config file\n", fs.Name())
		fmt.Fprintf(os.Stderr, "  %s -generate-config          # Generate example config\n", fs.Name())
		fmt.Fprintf(os.Stderr, "  %s -generate-dnscrypt-keys   # Generate DNSCrypt v2 key pair\n", fs.Name())
		fmt.Fprintf(os.Stderr, "  %s -version                  # Show version information\n", fs.Name())
		fmt.Fprintf(os.Stderr, "  %s                            # Start with default config\n\n", fs.Name())
		fmt.Fprintf(os.Stderr, "DNSCrypt options (with -generate-dnscrypt-keys):\n")
		fmt.Fprintf(os.Stderr, "  -provider-name <name>         Provider name (default: 2.dnscrypt-cert.ZJDNS)\n")
		fmt.Fprintf(os.Stderr, "  -cert-ttl <seconds>           Certificate TTL in seconds (default: 31536000)\n")
		fmt.Fprintf(os.Stderr, "  -es-version <version>         xsalsa20 | xchacha20 | xwing-pq\n")
	}

	_ = fs.Parse(osArgs[1:])

	if showVersion {
		fmt.Printf("ZJDNS Server\n")
		fmt.Printf("Version: %s\n", versionStr)
		return "", true
	}

	if generateConfig {
		fmt.Println(GenerateExampleConfig())
		return "", true
	}

	if generateDNSCrypt {
		fmt.Println(GenerateDNSCryptKeys(dnscryptProvider, dnscryptCertTTL, dnscryptESVersion))
		return "", true
	}

	if stampStr != "" {
		fmt.Println(ParseStamp(stampStr))
		return "", true
	}

	return configFileFlag, false
}
