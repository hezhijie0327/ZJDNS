package dnsutil

import (
	"net"
	"net/http"
	"reflect"
	"testing"
)

func mustCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("bad test CIDR %q: %v", cidr, err)
	}
	return network
}

func TestClientIPFromProxyHeaders(t *testing.T) {
	// trustedCF and trustedCF2 model two reverse proxies; the 192.0.2.0/24
	// addresses below are the real clients behind them (TEST-NET ranges).
	trusted := []*net.IPNet{mustCIDR(t, "203.0.113.0/24"), mustCIDR(t, "198.51.100.0/24")}
	proxy := net.ParseIP("203.0.113.10") // trusted direct peer
	client := net.ParseIP("192.0.2.7")   // real client behind the proxy
	client2 := net.ParseIP("192.0.2.8")  // second client IP for XFF chains
	clientV6 := net.ParseIP("2001:db8::1")

	tests := []struct {
		name     string
		remoteIP net.IP
		trusted  []*net.IPNet
		header   http.Header
		want     net.IP
	}{
		{
			name:     "no trusted list keeps socket address",
			remoteIP: proxy,
			header:   http.Header{HeaderCFConnectingIP: {client.String()}},
			want:     proxy,
		},
		{
			name:     "untrusted peer headers ignored",
			remoteIP: client,
			trusted:  trusted,
			header:   http.Header{HeaderCFConnectingIP: {"127.0.0.1"}, HeaderXForwardedFor: {"127.0.0.1"}},
			want:     client,
		},
		{
			name:     "CF-Connecting-IP wins for trusted peer",
			remoteIP: proxy,
			trusted:  trusted,
			header:   http.Header{HeaderCFConnectingIP: {client.String()}, HeaderXForwardedFor: {client2.String()}},
			want:     client,
		},
		{
			name:     "CF-Connecting-IP with list value rejected, falls to XFF",
			remoteIP: proxy,
			trusted:  trusted,
			header:   http.Header{HeaderCFConnectingIP: {client.String() + ", " + client2.String()}, HeaderXForwardedFor: {client2.String()}},
			want:     client2,
		},
		{
			name:     "CF-Connecting-IP outranks True-Client-IP",
			remoteIP: proxy,
			trusted:  trusted,
			header:   http.Header{HeaderCFConnectingIP: {client.String()}, HeaderTrueClientIP: {client2.String()}},
			want:     client,
		},
		{
			name:     "True-Client-IP outranks X-Real-IP and XFF",
			remoteIP: proxy,
			trusted:  trusted,
			header:   http.Header{HeaderTrueClientIP: {client.String()}, HeaderXRealIP: {client2.String()}, HeaderXForwardedFor: {"127.0.0.1"}},
			want:     client,
		},
		{
			name:     "X-Real-IP outranks XFF",
			remoteIP: proxy,
			trusted:  trusted,
			header:   http.Header{HeaderXRealIP: {client.String()}, HeaderXForwardedFor: {client2.String()}},
			want:     client,
		},
		{
			name:     "True-Client-IP with list value falls through to X-Real-IP",
			remoteIP: proxy,
			trusted:  trusted,
			header:   http.Header{HeaderTrueClientIP: {client.String() + ", " + client2.String()}, HeaderXRealIP: {client2.String()}},
			want:     client2,
		},
		{
			name:     "XFF single untrusted entry",
			remoteIP: proxy,
			trusted:  trusted,
			header:   http.Header{HeaderXForwardedFor: {client.String()}},
			want:     client,
		},
		{
			name:     "XFF client-injected fake loses to proxy-appended real IP",
			remoteIP: proxy,
			trusted:  trusted,
			header:   http.Header{HeaderXForwardedFor: {"127.0.0.1, " + client.String()}},
			want:     client,
		},
		{
			name:     "XFF multi-hop chain walks past trusted proxies",
			remoteIP: net.ParseIP("198.51.100.9"), // second trusted proxy
			trusted:  trusted,
			header:   http.Header{HeaderXForwardedFor: {client.String() + ", 203.0.113.10"}},
			want:     client,
		},
		{
			name:     "XFF all entries trusted falls back to socket address",
			remoteIP: proxy,
			trusted:  trusted,
			header:   http.Header{HeaderXForwardedFor: {"198.51.100.3"}},
			want:     proxy,
		},
		{
			name:     "XFF malformed rightmost entry stops the walk",
			remoteIP: proxy,
			trusted:  trusted,
			header:   http.Header{HeaderXForwardedFor: {client.String() + ", not-an-ip"}},
			want:     proxy,
		},
		{
			name:     "XFF entry with port",
			remoteIP: proxy,
			trusted:  trusted,
			header:   http.Header{HeaderXForwardedFor: {"192.0.2.9:8443"}},
			want:     net.ParseIP("192.0.2.9"),
		},
		{
			name:     "XFF IPv6 bracketed with port and bare forms",
			remoteIP: proxy,
			trusted:  trusted,
			header:   http.Header{HeaderXForwardedFor: {"[2001:db8::1]:443"}},
			want:     clientV6,
		},
		{
			name:     "no headers for trusted peer keeps socket address",
			remoteIP: proxy,
			trusted:  trusted,
			header:   http.Header{},
			want:     proxy,
		},
		{
			name:     "nil remote IP stays nil",
			remoteIP: nil,
			trusted:  trusted,
			header:   http.Header{HeaderCFConnectingIP: {client.String()}},
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClientIPFromProxyHeaders(tt.remoteIP, tt.trusted, tt.header)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ClientIPFromProxyHeaders() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseTrustedProxies(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		want    []string // expected networks in CIDR form
		wantErr bool
	}{
		{
			name:    "empty list",
			entries: nil,
			want:    []string{},
		},
		{
			name:    "blank entries skipped",
			entries: []string{"", "  "},
			want:    []string{},
		},
		{
			name:    "CIDR entries",
			entries: []string{"203.0.113.0/24", "2001:db8::/32"},
			want:    []string{"203.0.113.0/24", "2001:db8::/32"},
		},
		{
			name:    "bare IPv4 becomes /32",
			entries: []string{"203.0.113.5"},
			want:    []string{"203.0.113.5/32"},
		},
		{
			name:    "bare IPv6 becomes /128",
			entries: []string{"2001:db8::1"},
			want:    []string{"2001:db8::1/128"},
		},
		{
			name:    "invalid entry errors with index",
			entries: []string{"203.0.113.0/24", "not-a-network"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTrustedProxies(tt.entries)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseTrustedProxies(%v) error = nil, want error", tt.entries)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTrustedProxies(%v) error = %v", tt.entries, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d networks, want %d", len(got), len(tt.want))
			}
			for i, network := range got {
				if got := network.String(); got != tt.want[i] {
					t.Errorf("network[%d] = %q, want %q", i, got, tt.want[i])
				}
			}
		})
	}
}

func TestClientIPFromRequest(t *testing.T) {
	trusted := []*net.IPNet{mustCIDR(t, "203.0.113.0/24")}
	tests := []struct {
		name       string
		remoteAddr string
		header     http.Header
		want       string
	}{
		{
			name:       "trusted peer adopts CF-Connecting-IP",
			remoteAddr: "203.0.113.10:443",
			header:     http.Header{HeaderCFConnectingIP: {"192.0.2.7"}},
			want:       "192.0.2.7",
		},
		{
			name:       "socket address carries the port-free IP",
			remoteAddr: "198.51.100.20:8443",
			header:     http.Header{HeaderCFConnectingIP: {"192.0.2.7"}},
			want:       "198.51.100.20",
		},
		{
			name:       "IPv6 bracketed remote address",
			remoteAddr: "[2001:db8::5]:443",
			want:       "2001:db8::5",
		},
		{
			name:       "malformed remote address yields nil, headers not consulted",
			remoteAddr: "not-an-addr",
			header:     http.Header{HeaderCFConnectingIP: {"192.0.2.7"}},
			want:       "<nil>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClientIPFromRequest(tt.remoteAddr, trusted, tt.header)
			if s := got.String(); s != tt.want {
				t.Errorf("ClientIPFromRequest(%q) = %s, want %s", tt.remoteAddr, s, tt.want)
			}
		})
	}
}
