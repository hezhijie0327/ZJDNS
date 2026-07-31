package server

import (
	"testing"

	"codeberg.org/miekg/dns"
)

func TestDropEDE(t *testing.T) {
	pseudo := []dns.RR{
		&dns.EDE{InfoCode: 6, ExtraText: "bogus"},
		&dns.COOKIE{Cookie: "deadbeef"},
	}
	result := dropEDE(pseudo)
	if len(result) != 1 {
		t.Fatalf("expected 1 RR after dropEDE, got %d", len(result))
	}
	if _, ok := result[0].(*dns.COOKIE); !ok {
		t.Error("COOKIE should survive dropEDE")
	}
	pseudo2 := []dns.RR{&dns.COOKIE{Cookie: "cafe"}}
	result2 := dropEDE(pseudo2)
	if len(result2) != 1 {
		t.Errorf("expected 1 RR, got %d", len(result2))
	}
}
