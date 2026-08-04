package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"zjdns/cmd/zjdns/cli"
	"zjdns/config"
	"zjdns/database"
	"zjdns/internal/log"
	"zjdns/server"
)

// errLogged marks an error whose message was already emitted by run() with
// the component-appropriate prefix; main must not log it again.
var errLogged = errors.New("error already logged")

func main() {
	versionStr := getVersion()
	configFile, exitAfter, exitCode := cli.ParseFlags(os.Args, versionStr)
	if exitAfter {
		os.Exit(exitCode)
	}

	if err := run(configFile, versionStr); err != nil {
		if !errors.Is(err, errLogged) {
			log.Errorf("SERVER: %v", err)
		}
		os.Exit(1)
	}
}

// run executes the server lifecycle. Errors returned here trigger a non-zero
// exit; defer statements in this function run normally (unlike in main with
// direct os.Exit calls — special commands exit via ParseFlags above).
func run(configFile, versionStr string) error {
	if _, err := fmt.Print(banner(versionStr)); err != nil {
		fmt.Fprintf(os.Stderr, "warning: writing banner: %v\n", err)
	}

	config.DefaultProjectName = ProjectName
	config.DefaultVersion = versionStr
	// Wire the pure semantic version (no "v" prefix, no build metadata) into
	// the database package so Open() runs incremental migrations on existing
	// databases. Prior to this, database.Version stayed at its "0.0.0"
	// sentinel and migrations never ran (H8).
	database.Version = Version

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		log.Errorf("CONFIG: Config load failed: %v", err)
		return errLogged
	}

	if configFile != "" {
		server.SetRootFilesDir(filepath.Dir(configFile))
	}

	srv, err := server.New(cfg)
	if err != nil {
		log.Errorf("SERVER: Server creation failed: %v", err)
		return errLogged
	}

	if err := srv.Start(); err != nil {
		log.Errorf("SERVER: Server startup failed: %v", err)
		return errLogged
	}
	return nil
}
