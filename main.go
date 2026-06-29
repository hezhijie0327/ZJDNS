package main

import (
	"os"

	"zjdns/cli"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/server"
)

func main() {
	versionStr := getVersion()
	configFile, exitAfter := cli.ParseFlags(os.Args, versionStr)
	if exitAfter {
		return
	}

	config.ProjectName = ProjectName
	config.Version = versionStr

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		log.Errorf("CONFIG: Config load failed: %v", err)
		os.Exit(1)
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
