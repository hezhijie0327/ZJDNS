package middleware

import (
	"context"
	"net"
	"testing"
	"zjdns/config"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// aclLists builds config.ACLList values from raw entries via the production
// parser (fails the test on bad input).
func aclLists(t *testing.T, entries ...string) config.ACLList {
	t.Helper()
	settings := config.ACLSettings{Allow: entries}
	allow, _, err := settings.Parsed()
	if err != nil {
		t.Fatalf("bad test ACL entries %v: %v", entries, err)
	}
	return allow
}

func TestACL_Permits(t *testing.T) {
	inAllowNet := net.ParseIP("10.1.0.1")
	inDenyNet := net.ParseIP("192.0.2.9")
	other := net.ParseIP("203.0.113.5")

	tests := []struct {
		name   string
		allow  []string
		deny   []string
		ip     net.IP
		client string
		want   bool
	}{
		{name: "both empty permits everything", ip: other, want: true},
		{name: "deny match refuses", deny: []string{"192.0.2.0/24"}, ip: inDenyNet, want: false},
		{name: "deny miss passes", deny: []string{"192.0.2.0/24"}, ip: other, want: true},
		{
			name:  "allow net overrides deny net (exception model)",
			allow: []string{"10.0.0.0/8"},
			deny:  []string{"10.1.0.0/16"},
			ip:    inAllowNet,
			want:  true,
		},
		{
			name:  "allowlist passes member",
			allow: []string{"10.0.0.0/8"},
			ip:    inAllowNet,
			want:  true,
		},
		{
			name:  "allowlist refuses non-member (default-deny)",
			allow: []string{"10.0.0.0/8"},
			ip:    other,
			want:  false,
		},
		{name: "nil IP passes without allowlist", ip: nil, want: true},
		{
			name:  "nil IP refused in allowlist mode",
			allow: []string{"10.0.0.0/8"},
			ip:    nil,
			want:  false,
		},
		{
			name:   "allow name overrides IP deny (alice case)",
			allow:  []string{"alice"},
			deny:   []string{"203.0.113.0/24"},
			ip:     other,
			client: "alice",
			want:   true,
		},
		{
			name:   "deny name refuses unlisted client",
			deny:   []string{"badclient"},
			ip:     other,
			client: "badclient",
			want:   false,
		},
		{
			name:   "unknown name in allowlist mode refused",
			allow:  []string{"alice", "10.0.0.0/8"},
			ip:     other,
			client: "charlie",
			want:   false,
		},
		{
			name:   "name-only allowlist admits named client",
			allow:  []string{"alice"},
			ip:     other,
			client: "alice",
			want:   true,
		},
		{
			name:  "name-only allowlist refuses anonymous client",
			allow: []string{"alice"},
			ip:    other,
			want:  false,
		},
		{
			name:   "name in both lists: allow wins",
			allow:  []string{"alice"},
			deny:   []string{"alice"},
			client: "alice",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewACL(aclLists(t, tt.allow...), aclLists(t, tt.deny...))
			if got := m.permits(tt.ip, tt.client); got != tt.want {
				t.Errorf("permits(%v, %q) = %v, want %v", tt.ip, tt.client, got, tt.want)
			}
		})
	}
}

func TestACL_ChainRefusal(t *testing.T) {
	m := NewACL(config.ACLList{}, aclLists(t, "192.0.2.0/24", "badclient"))
	nextCalled := false
	h := m.Wrap(handler.QueryHandlerFunc(func(_ context.Context, _ *handler.QueryContext) error {
		nextCalled = true
		return nil
	}))

	// Denied by IP: REFUSED + EDE 18 Prohibited + Result "acl", next not reached.
	req := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	qctx := (&handler.QueryContext{Req: req, ClientIP: net.ParseIP("192.0.2.9"), Qname: "example.com.", Qtype: dns.TypeA}).InitQuestion()
	if err := h.ServeDNS(context.Background(), qctx); err != nil {
		t.Fatalf("ServeDNS error = %v", err)
	}
	if nextCalled {
		t.Error("next must not be reached for a denied client")
	}
	if qctx.Res == nil || qctx.Res.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %v, want REFUSED", qctx.Res)
	}
	if qctx.EDE == nil || qctx.EDE.InfoCode != dns.ExtendedErrorProhibited {
		t.Errorf("EDE = %v, want InfoCode ExtendedErrorProhibited (18)", qctx.EDE)
	}
	if qctx.Result != "acl" {
		t.Errorf("Result = %q, want \"acl\"", qctx.Result)
	}

	// Denied by name while the IP itself is unlisted.
	qctxN := (&handler.QueryContext{Req: req, ClientIP: net.ParseIP("198.51.100.1"), ClientName: "badclient", Qname: "example.com.", Qtype: dns.TypeA}).InitQuestion()
	if err := h.ServeDNS(context.Background(), qctxN); err != nil {
		t.Fatalf("ServeDNS error = %v", err)
	}
	if qctxN.Res == nil || qctxN.Res.Rcode != dns.RcodeRefused {
		t.Errorf("name-denied rcode = %v, want REFUSED", qctxN.Res)
	}

	// Permitted client reaches next untouched.
	qctx2 := (&handler.QueryContext{Req: req, ClientIP: net.ParseIP("203.0.113.5"), Qname: "example.com.", Qtype: dns.TypeA}).InitQuestion()
	if err := h.ServeDNS(context.Background(), qctx2); err != nil {
		t.Fatalf("ServeDNS error = %v", err)
	}
	if !nextCalled {
		t.Error("next must be reached for a permitted client")
	}
	if qctx2.Res != nil || qctx2.EDE != nil || qctx2.Result != "" {
		t.Error("permitted query must pass through without side effects")
	}
}
