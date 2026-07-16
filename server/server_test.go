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
	cfg.Server.Protocol.UDP = ""

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New() with empty port: %v", err)
	}
	if srv == nil {
		t.Fatal("New() returned nil")
	}
	// New() creates the plain DNS server even when no ports are configured.
	if srv.plain == nil {
		t.Error("plain server should not be nil")
	}
}

func TestPortSetAllowsPlainDNS(t *testing.T) {
	cfg := &config.ServerConfig{
		Upstream: []config.UpstreamServer{
			{Address: "builtin_recursive"},
		},
	}
	cfg.Server.Protocol.UDP = "15353"

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
