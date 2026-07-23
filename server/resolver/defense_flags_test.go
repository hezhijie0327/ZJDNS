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
		fallback  []config.UpstreamServer
		wantFlags struct{ spoofguard, splitguard, poisonguard bool }
	}{
		{
			name: "all flags enabled",
			servers: []config.UpstreamServer{
				{Address: config.RecursiveIndicator, Spoofguard: true, Splitguard: true, Poisonguard: true},
			},
			wantFlags: struct{ spoofguard, splitguard, poisonguard bool }{true, true, true},
		},
		{
			name: "all flags disabled",
			servers: []config.UpstreamServer{
				{Address: config.RecursiveIndicator},
			},
			wantFlags: struct{ spoofguard, splitguard, poisonguard bool }{false, false, false},
		},
		{
			name: "only spoofguard",
			servers: []config.UpstreamServer{
				{Address: config.RecursiveIndicator, Spoofguard: true},
			},
			wantFlags: struct{ spoofguard, splitguard, poisonguard bool }{true, false, false},
		},
		{
			name: "OR semantics — any server enables flag",
			servers: []config.UpstreamServer{
				{Address: config.RecursiveIndicator, Spoofguard: false, Poisonguard: false},
				{Address: config.RecursiveIndicator, Spoofguard: true, Poisonguard: true},
			},
			wantFlags: struct{ spoofguard, splitguard, poisonguard bool }{true, false, true},
		},
		{
			name: "non-recursive servers do not affect flags",
			servers: []config.UpstreamServer{
				{Address: "8.8.8.8:53", Protocol: "udp", Spoofguard: true},
				{Address: config.RecursiveIndicator},
			},
			wantFlags: struct{ spoofguard, splitguard, poisonguard bool }{false, false, false},
		},
		{
			name: "fallback recursive OR semantics",
			servers: []config.UpstreamServer{
				{Address: config.RecursiveIndicator, Spoofguard: true},
			},
			fallback: []config.UpstreamServer{
				{Address: config.RecursiveIndicator, Splitguard: true, Poisonguard: true},
			},
			wantFlags: struct{ spoofguard, splitguard, poisonguard bool }{true, true, true},
		},
		{
			name: "fallback does not override true with false",
			servers: []config.UpstreamServer{
				{Address: config.RecursiveIndicator, Spoofguard: true, Splitguard: true, Poisonguard: true},
			},
			fallback: []config.UpstreamServer{
				{Address: config.RecursiveIndicator, Spoofguard: false, Splitguard: false, Poisonguard: false},
			},
			wantFlags: struct{ spoofguard, splitguard, poisonguard bool }{true, true, true},
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
				fallback: &upstreamSet{},
			}
			r.recursive = &Recursive{
				resolver: r,
				ctx:      context.Background(),
			}
			r.cname = &CNAME{resolver: r}

			r.ConfigureServers(tt.servers, tt.fallback)

			if r.recursive.spoofguard != tt.wantFlags.spoofguard {
				t.Errorf("spoofguard = %v, want %v", r.recursive.spoofguard, tt.wantFlags.spoofguard)
			}
			if r.recursive.splitguard != tt.wantFlags.splitguard {
				t.Errorf("splitguard = %v, want %v", r.recursive.splitguard, tt.wantFlags.splitguard)
			}
			if r.recursive.poisonguard != tt.wantFlags.poisonguard {
				t.Errorf("poisonguard = %v, want %v", r.recursive.poisonguard, tt.wantFlags.poisonguard)
			}
		})
	}
}

func TestConfigureServers_DefaultProtocolUDP(t *testing.T) {
	// Verify that servers with empty Protocol are assigned ProtoUDP.
	r := &Resolver{
		upstream: &upstreamSet{},
		fallback: &upstreamSet{},
	}
	r.recursive = &Recursive{resolver: r, ctx: context.Background()}
	r.cname = &CNAME{resolver: r}

	servers := []config.UpstreamServer{
		{Address: "8.8.8.8:53"},
	}
	r.ConfigureServers(servers, nil)

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
		fallback: &upstreamSet{},
	}
	r.recursive = &Recursive{resolver: r, ctx: context.Background()}
	r.cname = &CNAME{resolver: r}

	// Primary recursive server sets proxy URL.
	r.ConfigureServers([]config.UpstreamServer{
		{Address: config.RecursiveIndicator, Proxy: "socks5://proxy:1080"},
	}, nil)

	if r.recursiveProxyURL != "socks5://proxy:1080" {
		t.Errorf("expected proxy URL, got %q", r.recursiveProxyURL)
	}

	// Fallback does NOT override already-set proxy URL.
	r.ConfigureServers([]config.UpstreamServer{
		{Address: config.RecursiveIndicator, Proxy: "socks5://proxy:1080"},
	}, []config.UpstreamServer{
		{Address: config.RecursiveIndicator, Proxy: "socks5://other:1080"},
	})

	if r.recursiveProxyURL != "socks5://proxy:1080" {
		t.Errorf("expected original proxy URL to persist, got %q", r.recursiveProxyURL)
	}

	// Reset and test fallback sets proxy when primary doesn't.
	r2 := &Resolver{
		upstream: &upstreamSet{},
		fallback: &upstreamSet{},
	}
	r2.recursive = &Recursive{resolver: r2, ctx: context.Background()}
	r2.cname = &CNAME{resolver: r2}

	r2.ConfigureServers([]config.UpstreamServer{
		{Address: config.RecursiveIndicator},
	}, []config.UpstreamServer{
		{Address: config.RecursiveIndicator, Proxy: "socks5://fallback:1080"},
	})

	if r2.recursiveProxyURL != "socks5://fallback:1080" {
		t.Errorf("expected fallback proxy URL, got %q", r2.recursiveProxyURL)
	}
}
