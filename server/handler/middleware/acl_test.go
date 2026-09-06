package middleware

import (
	"context"
	"net"
	"testing"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// aclNets parses a CIDR list for test fixtures (fails the test on bad input).
func aclNets(t *testing.T, entries ...string) []*net.IPNet {
	t.Helper()
	nets, err := zdnsutil.ParseIPNets(entries)
	if err != nil {
		t.Fatalf("bad test CIDRs %v: %v", entries, err)
	}
	return nets
}

func TestACL_Permits(t *testing.T) {
	inAllow := net.ParseIP("10.1.0.1")
	inDeny := net.ParseIP("192.0.2.9")
	other := net.ParseIP("203.0.113.5")

	tests := []struct {
		name  string
		allow []string
		deny  []string
		ip    net.IP
		want  bool
	}{
		{name: "both empty permits everything", ip: other, want: true},
		{name: "deny match refuses", deny: []string{"192.0.2.0/24"}, ip: inDeny, want: false},
		{name: "deny miss passes", deny: []string{"192.0.2.0/24"}, ip: other, want: true},
		{
			name:  "deny wins over allow",
			allow: []string{"10.0.0.0/8"},
			deny:  []string{"10.1.0.0/16"},
			ip:    inAllow,
			want:  false,
		},
		{
			name:  "allowlist passes member",
			allow: []string{"10.0.0.0/8"},
			ip:    inAllow,
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewACL(aclNets(t, tt.allow...), aclNets(t, tt.deny...))
			if got := m.permits(tt.ip); got != tt.want {
				t.Errorf("permits(%v) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestACL_ChainRefusal(t *testing.T) {
	m := NewACL(nil, aclNets(t, "192.0.2.0/24"))
	nextCalled := false
	h := m.Wrap(handler.QueryHandlerFunc(func(_ context.Context, _ *handler.QueryContext) error {
		nextCalled = true
		return nil
	}))

	// Denied client: REFUSED + EDE 18 Prohibited + Result "acl", next not reached.
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
