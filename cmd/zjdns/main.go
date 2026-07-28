package main

import (
	"fmt"
	"os"
	"path/filepath"
	"zjdns/cmd/zjdns/cli"
	"zjdns/config"
	"zjdns/database"
	"zjdns/internal/log"
	"zjdns/server"
)

func main() {
	// NOTE: os.Exit(1) skips deferred functions in main(). Any future
	// defers (e.g., flushing logs) would be silently skipped on error.
	// All three os.Exit(1) calls below follow the same pattern and are safe
	// because this package has no defers.
	versionStr := getVersion()
	database.Version = Version
	configFile, exitAfter := cli.ParseFlags(os.Args, versionStr)
	if exitAfter {
		return
	}

	fmt.Print(banner(versionStr))

	config.DefaultProjectName = ProjectName
	config.DefaultVersion = versionStr

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		log.Errorf("CONFIG: Config load failed: %v", err)
		os.Exit(1)
	}

	if configFile != "" {
		server.SetRootFilesDir(filepath.Dir(configFile))
	}

	srv, err := server.New(cfg)
	if err != nil {
		log.Errorf("SERVER: Server creation failed: %v", err)
		os.Exit(1)
	}

	if err := srv.Start(); err != nil {
		log.Errorf("SERVER: Server startup failed: %v", err)
		os.Exit(1)
	}
}
