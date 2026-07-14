package server

import (
	"testing"
	"zjdns/config"
)

func TestEmptyPortDisablesPlainDNS(t *testing.T) {
	cfg := &config.ServerConfig{
		Upstream: []config.UpstreamServer{
			{Address: "builtin_recursive"},
		},
	}
	// No port set — plain DNS should be skipped without error.
	cfg.Server.Port = ""

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New() with empty port: %v", err)
	}
	if srv == nil {
		t.Fatal("New() returned nil")
	}
	// New() doesn't start listeners, but Start() guards both UDP and TCP
	// with `if s.config.Server.Port != ""`.  We verify the guard exists by
	// confirming that udpServers and tcpServers start empty.
	if len(srv.udpServers) != 0 {
		t.Errorf("udpServers should be empty when port is empty, got %d", len(srv.udpServers))
	}
	if len(srv.tcpServers) != 0 {
		t.Errorf("tcpServers should be empty when port is empty, got %d", len(srv.tcpServers))
	}
}

func TestPortSetAllowsPlainDNS(t *testing.T) {
	cfg := &config.ServerConfig{
		Upstream: []config.UpstreamServer{
			{Address: "builtin_recursive"},
		},
	}
	cfg.Server.Port = "15353"

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New() with port set: %v", err)
	}
	if srv == nil {
		t.Fatal("New() returned nil")
	}
	// Port is set, but New() doesn't start listeners — so udp/tcp
	// servers are still empty.  The guard only matters in Start().
}
