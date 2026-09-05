package tls

import (
	"net"
	"testing"

	"codeberg.org/miekg/dns"
	eTLS "gitlab.com/go-extension/tls"
)

// rfc8998TestHandler satisfies edns.DNSHandler — handshake tests never reach
// DNS processing.
type rfc8998TestHandler struct{}

func (rfc8998TestHandler) ServeDNS(*dns.Msg, net.IP, bool, string) *dns.Msg { return nil }

// dialHandshake serves serverCfg on a loopback listener (production wrapping:
// eTLS.NewListener) and connects with clientCfg, returning both sides'
// connection states. TCP is used rather than net.Pipe: the synchronous pipe
// turns close_notify and HelloRetryRequest flights into artificial deadlocks.
func dialHandshake(t *testing.T, serverCfg, clientCfg *eTLS.Config) (serverState, clientState eTLS.ConnectionState) {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = raw.Close() }()
	ln := eTLS.NewListener(raw, serverCfg)

	type srvResult struct {
		state eTLS.ConnectionState
		err   error
	}
	srvCh := make(chan srvResult, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvCh <- srvResult{err: err}
			return
		}
		if err := conn.(*eTLS.Conn).Handshake(); err != nil {
			srvCh <- srvResult{err: err}
			return
		}
		srvCh <- srvResult{state: conn.(*eTLS.Conn).ConnectionState()}
	}()

	client, err := eTLS.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	srv := <-srvCh
	if srv.err != nil {
		t.Fatalf("server handshake: %v", srv.err)
	}
	cliState := client.ConnectionState()
	_ = client.Close()
	return srv.state, cliState
}

// newRFC8998Server builds a production Server (self-signed ECDSA cert) whose
// baseTLSConfig feeds every DoT/DoH listener.
func newRFC8998Server(t *testing.T) *Server {
	t.Helper()
	srv, err := New(rfc8998TestHandler{}, &Config{SelfSigned: true, Domain: "rfc8998.test"})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return srv
}

// TestServerNegotiatesRFC8998SM: a client that offers only an SM suite and
// CurveSM2 must complete the handshake against the production base config
// (RFC 8998 default-on).
func TestServerNegotiatesRFC8998SM(t *testing.T) {
	srv := newRFC8998Server(t)
	for _, suite := range []uint16{eTLS.TLS_SM4_GCM_SM3, eTLS.TLS_SM4_CCM_SM3} {
		t.Run(eTLS.CipherSuiteName(suite), func(t *testing.T) {
			clientCfg := &eTLS.Config{
				MinVersion:         eTLS.VersionTLS13,
				ServerName:         "rfc8998.test",
				InsecureSkipVerify: true, //nolint:gosec // self-signed test certificate
				CipherSuites:       []uint16{suite},
				CurvePreferences:   []eTLS.CurveID{eTLS.CurveSM2},
			}
			srvState, cliState := dialHandshake(t, srv.baseTLSConfig, clientCfg)
			if cliState.CipherSuite != suite {
				t.Errorf("client cipher = %s, want %s", eTLS.CipherSuiteName(cliState.CipherSuite), eTLS.CipherSuiteName(suite))
			}
			if srvState.CipherSuite != suite {
				t.Errorf("server cipher = %s, want %s", eTLS.CipherSuiteName(srvState.CipherSuite), eTLS.CipherSuiteName(suite))
			}
			if cliState.CurveID != eTLS.CurveSM2 {
				t.Errorf("client group = %s, want CurveSM2", cliState.CurveID)
			}
		})
	}
}

// TestServerStandardClientUnchangedByRFC8998: a client offering no SM suites
// must keep negotiating a standard TLS 1.3 suite.
func TestServerStandardClientUnchangedByRFC8998(t *testing.T) {
	srv := newRFC8998Server(t)
	clientCfg := &eTLS.Config{
		MinVersion:         eTLS.VersionTLS13,
		ServerName:         "rfc8998.test",
		InsecureSkipVerify: true, //nolint:gosec // self-signed test certificate
	}
	_, cliState := dialHandshake(t, srv.baseTLSConfig, clientCfg)
	if cliState.CipherSuite == eTLS.TLS_SM4_GCM_SM3 || cliState.CipherSuite == eTLS.TLS_SM4_CCM_SM3 {
		t.Errorf("standard client negotiated SM suite %s, want a non-SM suite", eTLS.CipherSuiteName(cliState.CipherSuite))
	}
}
