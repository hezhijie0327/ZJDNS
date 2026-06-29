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

	// Detect kernel TLS (KTLS) support early so the user sees it at startup.
	// go-extension/tls handles fallback automatically — this is informational.
	// KTLS defaults to off. kernel_tx is usually safe; kernel_rx may cause
	// "bad record MAC" on some kernel/NIC combos.
	if _, err := os.Stat("/sys/module/tls"); err == nil {
		log.Infof("SERVER: KTLS kernel module detected, TLS offload available (enable via server.tls.ktls.kernel_tx=true, kernel_rx=true)")
	} else if os.IsNotExist(err) {
		log.Infof("SERVER: KTLS kernel module not loaded, TLS offload unavailable (load with: modprobe tls)")
	} else {
		log.Infof("SERVER: KTLS detection failed: %v, TLS offload unavailable", err)
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
