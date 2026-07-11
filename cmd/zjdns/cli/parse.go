package cli

import (
	"flag"
	"fmt"
	"os"
)

// ParseFlags parses command-line arguments and handles special commands.
// Returns the config file path (empty for default config) and whether the
// caller should exit (true after running a special command).
func ParseFlags(osArgs []string, versionStr string) (configFile string, exitAfter bool) {
	// ── Flags ────────────────────────────────────────────────────────────
	var (
		// Server
		configFileFlag string
		showVersion    bool

		// Generate config
		generateConfig    bool
		dnscrypt          bool
		dnscryptProvider  string
		dnscryptAddr      string
		dnscryptESVersion string
		dnscryptCertTTL   string

		// SQL
		runSQL bool

		// DNS stamp
		runDNSStamp    bool
		dnsStampDecode bool
		dnsStampEncode bool

		// DNS stamp encode
		stampProto     string
		stampAddr      string
		stampProvider  string
		stampPublicKey string
		stampPath      string
		stampProps     uint64
	)

	fs := flag.NewFlagSet(osArgs[0], flag.ContinueOnError)

	// Server
	fs.StringVar(&configFileFlag, "config", "", "Configuration file path (JSON format)")
	fs.BoolVar(&showVersion, "version", false, "Show version information and exit")

	// Generate config
	fs.BoolVar(&generateConfig, "generate-config", false, "Generate example configuration")
	fs.BoolVar(&dnscrypt, "dnscrypt", false, "Generate DNSCrypt configuration (with --generate-config)")
	fs.StringVar(&dnscryptProvider, "provider", "", "Provider name for DNSCrypt config")
	fs.StringVar(&dnscryptAddr, "addr", "127.0.0.1:8443", "Server address for DNSCrypt stamp")
	fs.StringVar(&dnscryptESVersion, "es-version", "xwingpq", "Encryption algorithm (xwingpq or xchacha20poly1305)")
	fs.StringVar(&dnscryptCertTTL, "cert-ttl", "", "Certificate validity duration (e.g. 720h, 30d; default 8760h/365d)")

	// SQL
	fs.BoolVar(&runSQL, "sql", false, "Run SQL query against database")

	// DNS stamp
	fs.BoolVar(&runDNSStamp, "dnsstamp", false, "Decode or encode an sdns:// DNS stamp")
	fs.BoolVar(&dnsStampDecode, "decode", false, "Decode mode for --dnsstamp")
	fs.BoolVar(&dnsStampEncode, "encode", false, "Encode mode for --dnsstamp")

	// DNS stamp encode
	fs.StringVar(&stampProto, "proto", "", "Stamp protocol: plain, dnscrypt, doh, dot, doq, odoh-target, dnscrypt-relay, odoh-relay")
	fs.StringVar(&stampAddr, "stamp-addr", "", "Server address for stamp encode (host:port)")
	fs.StringVar(&stampProvider, "provider-name", "", "Provider name (DNSCrypt) or TLS SNI (DoT/DoQ/DoH)")
	fs.StringVar(&stampPublicKey, "public-key", "", "DNSCrypt Ed25519 public key (hex, 64 chars)")
	fs.StringVar(&stampPath, "path", "/dns-query", "HTTP path for DoH/ODoH stamps")
	fs.Uint64Var(&stampProps, "props", 0, "Informal properties bitmask (1=DNSSEC, 2=NoLog, 4=NoFilter)")

	// ── Usage ────────────────────────────────────────────────────────────
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "ZJDNS Server - High Performance DNS Server\n\n")
		fmt.Fprintf(os.Stderr, "Version: %s\n\n", versionStr)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s --config <file>              # Start with config file\n", fs.Name())
		fmt.Fprintf(os.Stderr, "  %s                              # Start with default config\n", fs.Name())
		fmt.Fprintf(os.Stderr, "  %s --version                    # Show version information\n", fs.Name())
		fmt.Fprintf(os.Stderr, "  %s --generate-config            # Generate example config\n", fs.Name())
		fmt.Fprintf(os.Stderr, "  %s --generate-config --dnscrypt --provider <name> [--addr <addr>] [--es-version <ver>] [--cert-ttl <ttl>]\n", fs.Name())
		fmt.Fprintf(os.Stderr, "  %s --sql <db> <query>           # Run SQL query against database\n", fs.Name())
		fmt.Fprintf(os.Stderr, "  %s --dnsstamp --decode <stamp>  # Decode an sdns:// stamp to upstream JSON\n", fs.Name())
		fmt.Fprintf(os.Stderr, "  %s --dnsstamp --encode --proto <type> --stamp-addr <addr> [--provider-name <name>] [--public-key <hex>] [--path <path>] [--props <n>]\n", fs.Name())
		fmt.Fprintf(os.Stderr, "\n")
	}

	// ── Help ─────────────────────────────────────────────────────────────
	for _, arg := range osArgs[1:] {
		if arg == "-h" || arg == "--help" {
			fs.Usage()
			return "", true
		}
	}

	// ── Parse ────────────────────────────────────────────────────────────
	if err := fs.Parse(osArgs[1:]); err != nil {
		return "", true
	}

	// ── Dispatch ─────────────────────────────────────────────────────────
	// --version
	if showVersion {
		fmt.Printf("ZJDNS Server\n")
		fmt.Printf("Version: %s\n", versionStr)
		return "", true
	}

	// --generate-config
	if generateConfig {
		if dnscrypt {
			output, err := generateDNSCryptConfig(dnscryptProvider, dnscryptAddr, dnscryptESVersion, dnscryptCertTTL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "generate-config: %v\n", err)
			} else {
				fmt.Println(output)
			}
		} else {
			fmt.Println(generateExampleConfig())
		}
		return "", true
	}

	// --dnsstamp
	if runDNSStamp {
		switch {
		case dnsStampDecode:
			args := fs.Args()
			if len(args) < 1 {
				fmt.Fprintf(os.Stderr, "Usage: %s --dnsstamp --decode <sdns://...>\n", fs.Name())
				return "", true
			}
			if err := RunDNSStampDecode(args[0]); err != nil {
				fmt.Fprintf(os.Stderr, "dnsstamp decode: %v\n", err)
			}
		case dnsStampEncode:
			if err := RunDNSStampEncode(stampProto, stampAddr, stampProvider, stampPublicKey, stampPath, stampProps); err != nil {
				fmt.Fprintf(os.Stderr, "dnsstamp encode: %v\n", err)
			}
		default:
			fmt.Fprintf(os.Stderr, "Usage: %s --dnsstamp --decode <stamp> | --dnsstamp --encode [options]\n", fs.Name())
		}
		return "", true
	}

	// --sql
	if runSQL {
		args := fs.Args()
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: %s --sql <db> <query>\n", fs.Name())
			return "", true
		}
		if err := RunSQL(args[0], args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "sql: %v\n", err)
		}
		return "", true
	}

	// Default: start server
	return configFileFlag, false
}
