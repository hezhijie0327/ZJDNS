package tlcp

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// ipCaptureHandler records the client IP the pipeline entry received.
type ipCaptureHandler struct{ got net.IP }

func (h *ipCaptureHandler) ServeDNS(req *dns.Msg, clientIP net.IP, _ bool, _ string) *dns.Msg {
	h.got = clientIP
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, req)
	return resp
}

func TestServeDOHTrustedProxyClientIP(t *testing.T) {
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
			s := &Server{handler: h}
			s.SetTrustedProxies(tt.trusted)
			rec := httptest.NewRecorder()
			s.ServeDOH(rec, newRequest(tt.remote, tt.cfIP))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}
			if got := h.got.String(); got != tt.want {
				t.Errorf("client IP = %s, want %s", got, tt.want)
			}
		})
	}
}
