package tls

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// ipCaptureHandler records the client IP the pipeline entry received.
type ipCaptureHandler struct {
	got  net.IP
	name string
}

func (h *ipCaptureHandler) ServeDNS(req *dns.Msg, meta edns.RequestMeta) *dns.Msg {
	h.got = meta.ClientIP
	h.name = meta.ClientName
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, req)
	return resp
}

func TestDohCacheControl(t *testing.T) {
	if got := dohCacheControl(nil); got != "max-age=0" {
		t.Errorf("nil: got %q, want max-age=0", got)
	}
	empty := &dns.Msg{}
	if got := dohCacheControl(empty); got != "max-age=0" {
		t.Errorf("empty: got %q, want max-age=0", got)
	}
	msg := &dns.Msg{Answer: []dns.RR{
		&dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, Addr: netip.MustParseAddr("1.2.3.4")},
	}}
	if got := dohCacheControl(msg); got != "max-age=300" {
		t.Errorf("300s: got %q, want max-age=300", got)
	}
	msg2 := &dns.Msg{Answer: []dns.RR{
		&dns.A{Hdr: dns.Header{Name: "a.example.com.", Class: dns.ClassINET, TTL: 600}},
		&dns.A{Hdr: dns.Header{Name: "b.example.com.", Class: dns.ClassINET, TTL: 60}},
	}}
	if got := dohCacheControl(msg2); got != "max-age=60" {
		t.Errorf("min TTL: got %q, want max-age=60", got)
	}
}

func TestLeafNotAfterClampedToCA(t *testing.T) {
	now := time.Now()
	caNotAfter := now.Add(10 * 24 * time.Hour) // CA expires sooner than the leaf's default

	// Leaf validity longer than the CA's remaining life: clamped to the CA.
	if got := zdnsutil.LeafNotAfter(now, caNotAfter, config.DefaultServerCertValidity); !got.Equal(caNotAfter) {
		t.Errorf("leafNotAfter = %v, want clamped to CA %v", got, caNotAfter)
	}

	// Normal case: CA outlives the leaf — leaf keeps its own validity.
	caLong := now.Add(365 * 24 * time.Hour)
	want := now.Add(config.DefaultServerCertValidity)
	if got := zdnsutil.LeafNotAfter(now, caLong, config.DefaultServerCertValidity); !got.Equal(want) {
		t.Errorf("leafNotAfter = %v, want %v", got, want)
	}
}

func TestServeHTTPTrustedProxyClientIP(t *testing.T) {
	_, proxyNet, err := net.ParseCIDR("203.0.113.0/24") // TEST-NET-3 as the reverse proxy
	if err != nil {
		t.Fatal(err)
	}
	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	query.ID = 0 // dnshttp GET requires message ID 0 (fork rule)
	if err := query.Pack(); err != nil {
		t.Fatal(err)
	}
	wire := query.Data
	newRequest := func(remote, cfIP string) *http.Request {
		r := httptest.NewRequest(http.MethodGet,
			config.DefaultQueryPath+"?dns="+base64.RawURLEncoding.EncodeToString(wire), http.NoBody)
		r.RemoteAddr = remote
		if cfIP != "" {
			r.Header.Set(zdnsutil.HeaderCFConnectingIP, cfIP)
		}
		return r
	}

	tests := []struct {
		name    string
		trusted []*net.IPNet
		remote  string
		cfIP    string
		want    string
	}{
		{
			name:    "trusted peer adopts CF-Connecting-IP",
			trusted: []*net.IPNet{proxyNet},
			remote:  "203.0.113.10:443",
			cfIP:    "192.0.2.7",
			want:    "192.0.2.7",
		},
		{
			name:    "untrusted peer ignores CF-Connecting-IP",
			trusted: []*net.IPNet{proxyNet},
			remote:  "198.51.100.20:443",
			cfIP:    "192.0.2.7",
			want:    "198.51.100.20",
		},
		{
			name:   "no trusted list keeps socket address",
			remote: "203.0.113.10:443",
			cfIP:   "192.0.2.7",
			want:   "203.0.113.10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &ipCaptureHandler{}
			s := &Server{cfg: &Config{}, handler: h, trustedProxies: tt.trusted}
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, newRequest(tt.remote, tt.cfIP))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}
			if got := h.got.String(); got != tt.want {
				t.Errorf("client IP = %s, want %s", got, tt.want)
			}
		})
	}
}
