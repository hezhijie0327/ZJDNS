package main

import (
	"flag"
	"fmt"
	"os"

	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/server"
)

func main() {
	var configFile string
	var generateConfig bool
	var showVersion bool

	flag.StringVar(&configFile, "config", "", "Configuration file path (JSON format)")
	flag.BoolVar(&generateConfig, "generate-config", false, "Generate example configuration file")
	flag.BoolVar(&showVersion, "version", false, "Show version information and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "ZJDNS Server - High Performance DNS Server\n\n")
		fmt.Fprintf(os.Stderr, "Version: %s\n\n", getVersion())
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s -config <config file>     # Start with config file\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -generate-config          # Generate example config\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -version                  # Show version information\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s                            # Start with default config\n\n", os.Args[0])
	}

	flag.Parse()

	if showVersion {
		fmt.Printf("ZJDNS Server\n")
		fmt.Printf("Version: %s\n", getVersion())
		return
	}

	if generateConfig {
		fmt.Println(config.GenerateExampleConfig())
		return
	}

	config.ProjectName = ProjectName
	config.Version = getVersion()

	cm := &config.Loader{}
	cfg, err := cm.LoadConfig(configFile)
	if err != nil {
		log.Errorf("CONFIG: Config load failed: %v", err)
		os.Exit(1)
	}

	// Detect kernel TLS (KTLS) support early so the user sees it at startup.
	// go-extension/tls handles fallback automatically — this is informational.
	if _, err := os.Stat("/sys/module/tls"); err == nil {
		log.Infof("SERVER: KTLS kernel module detected, TLS offload available")
	} else {
		log.Infof("SERVER: KTLS not available, using user-space TLS")
	}

	srv, err := server.New(cfg)
	if err != nil {
		log.Errorf("SERVER: Server creation failed: %v", err)
		os.Exit(1)
	}

	log.Infof("SERVER: ZJDNS Server started successfully!")

	if err := srv.Start(); err != nil {
		log.Errorf("SERVER: Server startup failed: %v", err)
		os.Exit(1)
	}
}
