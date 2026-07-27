package resolver

import (
	"context"
	"testing"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/server/defense"
	"zjdns/server/upstream"

	"codeberg.org/miekg/dns"
)

func TestConfigureServers_DefenseFlagPropagation(t *testing.T) {
	tests := []struct {
		name      string
		servers   []config.UpstreamServer
		wantFlags struct{ spoofguard, splitguard, poisonguard, hopguard bool }
	}{
		{
			name: "all flags enabled",
			servers: []config.UpstreamServer{
				{Protocol: config.ProtoRecursive, Spoofguard: true, Splitguard: true, Poisonguard: true, HopGuard: true},
			},
			wantFlags: struct{ spoofguard, splitguard, poisonguard, hopguard bool }{true, true, true, true},
		},
		{
			name: "all flags disabled",
			servers: []config.UpstreamServer{
				{Protocol: config.ProtoRecursive},
			},
			wantFlags: struct{ spoofguard, splitguard, poisonguard, hopguard bool }{false, false, false, false},
		},
		{
			name: "only spoofguard",
			servers: []config.UpstreamServer{
				{Protocol: config.ProtoRecursive, Spoofguard: true},
			},
			wantFlags: struct{ spoofguard, splitguard, poisonguard, hopguard bool }{true, false, false, false},
		},
		{
			name: "OR semantics — any server enables flag",
			servers: []config.UpstreamServer{
				{Protocol: config.ProtoRecursive, Spoofguard: false, Poisonguard: false},
				{Protocol: config.ProtoRecursive, Spoofguard: true, Poisonguard: true},
			},
			wantFlags: struct{ spoofguard, splitguard, poisonguard, hopguard bool }{true, false, true, false},
		},
		{
			name: "non-recursive servers do not affect flags",
			servers: []config.UpstreamServer{
				{Address: "8.8.8.8:53", Protocol: "udp", Spoofguard: true},
				{Protocol: config.ProtoRecursive},
			},
			wantFlags: struct{ spoofguard, splitguard, poisonguard, hopguard bool }{false, false, false, false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ednsHandler, _ := edns.NewHandler(config.ECSConfig{})
			queryClient := upstream.New()
			r := &Resolver{
				queryClient: queryClient,
				edns:        ednsHandler,
				buildMsg:    func(q Question, ecs *edns.ECSOption, rd, secure bool) *dns.Msg { return new(dns.Msg) },
				validator: &Validator{
					Poisonguard: defense.Detector{},
				},
				upstream: &upstreamSet{},
			}
			r.recursive = &Recursive{
				resolver: r,
				ctx:      context.Background(),
			}
			r.cname = &CNAME{resolver: r}

			r.ConfigureServers(tt.servers)

			if r.recursive.spoofguard != tt.wantFlags.spoofguard {
				t.Errorf("spoofguard = %v, want %v", r.recursive.spoofguard, tt.wantFlags.spoofguard)
			}
			if r.recursive.splitguard != tt.wantFlags.splitguard {
				t.Errorf("splitguard = %v, want %v", r.recursive.splitguard, tt.wantFlags.splitguard)
			}
			if r.recursive.poisonguard != tt.wantFlags.poisonguard {
				t.Errorf("poisonguard = %v, want %v", r.recursive.poisonguard, tt.wantFlags.poisonguard)
			}
			if r.recursive.hopguard != tt.wantFlags.hopguard {
				t.Errorf("hopguard = %v, want %v", r.recursive.hopguard, tt.wantFlags.hopguard)
			}
		})
	}
}

func TestConfigureServers_DefaultProtocolUDP(t *testing.T) {
	// Verify that servers with empty Protocol are assigned ProtoUDP.
	r := &Resolver{
		upstream: &upstreamSet{},
	}
	r.recursive = &Recursive{resolver: r, ctx: context.Background()}
	r.cname = &CNAME{resolver: r}

	servers := []config.UpstreamServer{
		{Address: "8.8.8.8:53"},
	}
	r.ConfigureServers(servers)

	list := r.UpstreamServers()
	if len(list) != 1 {
		t.Fatalf("expected 1 server, got %d", len(list))
	}
	if list[0].Protocol != config.ProtoUDP {
		t.Errorf("expected protocol=%q, got %q", config.ProtoUDP, list[0].Protocol)
	}
}

func TestConfigureServers_RecursiveProxyURL(t *testing.T) {
	r := &Resolver{
		upstream: &upstreamSet{},
	}
	r.recursive = &Recursive{resolver: r, ctx: context.Background()}
	r.cname = &CNAME{resolver: r}

	// Recursive server sets proxy URL.
	r.ConfigureServers([]config.UpstreamServer{
		{Protocol: config.ProtoRecursive, Proxy: "socks5://proxy:1080"},
	})

	if r.recursiveProxyURL != "socks5://proxy:1080" {
		t.Errorf("expected proxy URL, got %q", r.recursiveProxyURL)
	}
}
