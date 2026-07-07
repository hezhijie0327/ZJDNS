package cli

import (
	"flag"
	"fmt"
	"os"
	"zjdns/config"
)

// ParseFlags parses command-line arguments and handles special commands
// Returns the config file path (empty for default config) and whether the
// caller should exit (true after running a special command).
func ParseFlags(osArgs []string, versionStr string) (configFile string, exitAfter bool) {
	var (
		configFileFlag string
		generateConfig bool
		showVersion    bool
		analyzeDB      bool
	)

	fs := flag.NewFlagSet(osArgs[0], flag.ContinueOnError)
	fs.StringVar(&configFileFlag, "config", "", "Configuration file path (JSON format)")
	fs.BoolVar(&generateConfig, "generate-config", false, "Generate example configuration file")
	fs.BoolVar(&showVersion, "version", false, "Show version information and exit")
	fs.BoolVar(&analyzeDB, "analyze", false, "Run SQL query against cache database")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "ZJDNS Server - High Performance DNS Server\n\n")
		fmt.Fprintf(os.Stderr, "Version: %s\n\n", versionStr)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s -config <file>            # Start with config file\n", fs.Name())
		fmt.Fprintf(os.Stderr, "  %s -generate-config          # Generate example config\n", fs.Name())
		fmt.Fprintf(os.Stderr, "  %s -version                  # Show version information\n", fs.Name())
		fmt.Fprintf(os.Stderr, "  %s -analyze <db> <query>     # Run SQL query on cache database\n", fs.Name())
		fmt.Fprintf(os.Stderr, "  %s                            # Start with default config\n\n", fs.Name())
	}

	// Check for help flags before parsing, since custom FlagSet does not
	// auto-register -h/-help.
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
