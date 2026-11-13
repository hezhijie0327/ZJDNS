package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"zjdns/config"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// TestExecuteHTTPSRejectsRedirect pins the DoH redirect policy: an upstream
// answering 302 must fail the query with the 3xx status instead of following
// the redirect — following would re-send the DNS query (dns= URL) to an
// arbitrary host, and an http:// target would bypass the eTLS transport.
func TestExecuteHTTPSRejectsRedirect(t *testing.T) {
	var followed atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		followed.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL+"/dns-query")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()

	base := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{ForceAttemptHTTP2: true}}
	c := New(base, base, nil, nil, nil, nil, nil, nil, 5*time.Second)

	msg := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	_, err := c.ExecuteHTTPS(context.Background(), msg, &config.UpstreamServer{
		Address:       upstream.URL + "/dns-query",
		SkipTLSVerify: true,
	})
	if err == nil {
		t.Fatal("redirecting DoH upstream must fail the query")
	}
	if !strings.Contains(err.Error(), "302") {
		t.Fatalf("ExecuteHTTPS error = %v, want the unfollowed HTTP 302 status", err)
	}
	if n := followed.Load(); n != 0 {
		t.Fatalf("redirect was followed: target server hit %d time(s)", n)
	}
}

// TestDOH3ClientRejectsRedirect pins the DoH3 redirect policy at the client
// construction level (CheckRedirect is enforced by net/http itself, so
// asserting the policy function suffices without a QUIC test server).
func TestDOH3ClientRejectsRedirect(t *testing.T) {
	c := New(nil, &http.Client{Timeout: 5 * time.Second}, nil, nil, nil, nil, nil, nil, 5*time.Second)

	client := c.createDOH3Client("key|example.com|false|", "example.com", "", &tls.Config{})
	if client.CheckRedirect == nil {
		t.Fatal("DoH3 client has no CheckRedirect policy")
	}
	if err := client.CheckRedirect(&http.Request{}, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect error = %v, want http.ErrUseLastResponse", err)
	}
}
