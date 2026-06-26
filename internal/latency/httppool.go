package latency

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"

	"github.com/quic-go/quic-go/http3"

	"zjdns/config"
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

func (p *httpClientPool) get(port int, useTLS, useHTTP3 bool) *http.Client {
	key := httpPoolKey{port: port, tls: useTLS, http3: useHTTP3}

	p.mu.Lock()
	defer p.mu.Unlock()

	if c, ok := p.clients[key]; ok {
		return c
	}

	var client *http.Client
	if useHTTP3 {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         config.NextProtoDoH3,
		}
		client = &http.Client{
			Transport: &http3.Transport{TLSClientConfig: tlsConfig},
		}
	} else {
		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		transport := &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
			ForceAttemptHTTP2: false,
			TLSClientConfig:   tlsConfig,
			DialContext:       (&net.Dialer{}).DialContext,
			IdleConnTimeout:   config.DefaultLatencyProbeTimeout,
		}
		client = &http.Client{Transport: transport}
	}

	p.clients[key] = client
	return client
}
