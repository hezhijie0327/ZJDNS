package latency

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"zjdns/config"

	"github.com/quic-go/quic-go/http3"
)

// httpClientPool caches HTTP clients keyed by (port, TLS, HTTP3) to avoid
// creating a new transport and TLS handshake for every probe.
type httpClientPool struct {
	mu      sync.Mutex
	clients map[httpPoolKey]*http.Client
}

type httpPoolKey struct {
	port  int
	tls   bool
	http3 bool
}

func newHTTPClientPool() *httpClientPool {
	return &httpClientPool{
		clients: make(map[httpPoolKey]*http.Client),
	}
}

// get returns the cached client for the key, creating it on first use.
// It returns an error once the pool has been closed (nil map) — callers
// must treat a nil client as a failure, not as "no client".
func (p *httpClientPool) get(port int, useTLS, useHTTP3 bool) (*http.Client, error) {
	key := httpPoolKey{port: port, tls: useTLS, http3: useHTTP3}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.clients == nil {
		return nil, errHTTPPoolClosed
	}
	if c, ok := p.clients[key]; ok {
		return c, nil
	}

	// Never follow redirects: a probe target that redirects to another
	// host would measure the wrong endpoint and leak the probe.
	checkRedirect := func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

	var client *http.Client
	if useHTTP3 {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // G402: latency probe pool — not security-critical
			NextProtos:         config.NextProtoDOH3,
		}
		client = &http.Client{
			Timeout:       config.DefaultLatencyProbeTimeout,
			Transport:     &http3.Transport{TLSClientConfig: tlsConfig},
			CheckRedirect: checkRedirect,
		}
	} else {
		tlsConfig := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // G402: latency probe pool — not security-critical
		transport := &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
			ForceAttemptHTTP2: false,
			TLSClientConfig:   tlsConfig,
			DialContext:       (&net.Dialer{}).DialContext,
		}
		client = &http.Client{
			Timeout:       config.DefaultLatencyProbeTimeout,
			Transport:     transport,
			CheckRedirect: checkRedirect,
		}
	}

	p.clients[key] = client
	return client, nil
}

// Close closes all pooled HTTP clients, releasing underlying QUIC connections
// and file descriptors. Safe to call multiple times.
func (p *httpClientPool) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, client := range p.clients {
		if key.http3 {
			if t, ok := client.Transport.(*http3.Transport); ok {
				_ = t.Close() // _ = error: best-effort close during pool shutdown
			}
		}
	}
	p.clients = nil
}
