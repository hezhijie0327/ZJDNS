package cli

import (
	"flag"
	"fmt"
	"os"
	"zjdns/config"
	serverdnscrypt "zjdns/server/dnscrypt"
)

// ParseFlags parses command-line arguments and handles special commands
// Returns the config file path (empty for default config) and whether the
// caller should exit (true after running a special command).
func ParseFlags(osArgs []string, versionStr string) (configFile string, exitAfter bool) {
	var (
		configFileFlag      string
		generateConfig      bool
		showVersion         bool
		analyzeDB           bool
		generateDNSCryptCfg bool
		dnscryptProvider    string
		dnscryptAddr        string
		dnscryptESVersion   string
	)

	fs := flag.NewFlagSet(osArgs[0], flag.ContinueOnError)
	fs.StringVar(&configFileFlag, "config", "", "Configuration file path (JSON format)")
	fs.BoolVar(&generateConfig, "generate-config", false, "Generate example configuration file")
	fs.BoolVar(&showVersion, "version", false, "Show version information and exit")
	fs.BoolVar(&analyzeDB, "analyze", false, "Run SQL query against cache database")
	fs.BoolVar(&generateDNSCryptCfg, "generate-dnscrypt-config", false, "Generate DNSCrypt server configuration")
	fs.StringVar(&dnscryptProvider, "provider", "", "Provider name for DNSCrypt config generation")
	fs.StringVar(&dnscryptAddr, "addr", "127.0.0.1:8443", "Server address for DNSCrypt stamp")
	fs.StringVar(&dnscryptESVersion, "es-version", "xsalsa20poly1305", "Encryption algorithm (xsalsa20poly1305 or xchacha20poly1305)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "ZJDNS Server - High Performance DNS Server\n\n")
		fmt.Fprintf(os.Stderr, "Version: %s\n\n", versionStr)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s -config <file>            # Start with config file\n", fs.Name())
		fmt.Fprintf(os.Stderr, "  %s -generate-config          # Generate example config\n", fs.Name())
		fmt.Fprintf(os.Stderr, "  %s -version                  # Show version information\n", fs.Name())
		fmt.Fprintf(os.Stderr, "  %s -analyze <db> <query>     # Run SQL query on cache database\n", fs.Name())
		fmt.Fprintf(os.Stderr, "  %s -generate-dnscrypt-config -provider <name> [-addr <host:port>] [-es-version <ver>]\n", fs.Name())
		fmt.Fprintf(os.Stderr, "  %s                            # Start with default config\n\n", fs.Name())
	}

	for _, arg := range osArgs[1:] {
		if arg == "-h" || arg == "--help" {
			fs.Usage()
			return "", true
		}
	}

	if err := fs.Parse(osArgs[1:]); err != nil {
		return "", true
	}

	if showVersion {
		fmt.Printf("ZJDNS Server\n")
		fmt.Printf("Version: %s\n", versionStr)
		return "", true
	}

	if generateConfig {
		fmt.Println(config.GenerateExampleConfig())
		return "", true
	}

	if generateDNSCryptCfg {
		output, err := serverdnscrypt.GenerateDNSCryptConfig(dnscryptProvider, dnscryptAddr, dnscryptESVersion)
		if err != nil {
			fmt.Fprintf(os.Stderr, "generate-dnscrypt-config: %v\n", err)
		} else {
			fmt.Println(output)
		}
		return "", true
	}

	if analyzeDB {
		args := fs.Args()
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: %s -analyze <db> <query>\n", fs.Name())
			return "", true
		}
		if err := RunAnalyze(args[0], args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "analyze: %v\n", err)
		}
		return "", true
	}

	return configFileFlag, false
}
