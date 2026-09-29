package ktls

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"net"
	"testing"
	"time"
)

// tlsPipeConn is a net.Pipe end extended with the interfaces Go 1.27
// net/http probes on accepted conns — the surface limitConn must forward.
type tlsPipeConn struct {
	net.Conn
	negotiated string
}

// chanListener hands out scripted conns from a channel.
type chanListener struct {
	conns chan net.Conn
}

func (c *tlsPipeConn) ConnectionState() stdtls.ConnectionState {
	return stdtls.ConnectionState{NegotiatedProtocol: c.negotiated}
}

func (c *tlsPipeConn) HandshakeContext(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func (l *chanListener) Accept() (net.Conn, error) {
	c, ok := <-l.conns
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}

func (l *chanListener) Close() error   { close(l.conns); return nil }
func (l *chanListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestNewLimitListenerForwardsTLSInterfaces(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()

	inner := &chanListener{conns: make(chan net.Conn, 1)}
	inner.conns <- &tlsPipeConn{Conn: server, negotiated: "h2"}

	ln := NewLimitListener(inner, 4)
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer func() { _ = conn.Close() }()

	cs, ok := conn.(interface{ ConnectionState() stdtls.ConnectionState })
	if !ok {
		t.Fatal("accepted conn does not expose ConnectionState — http.Server would serve it as plaintext")
	}
	if got := cs.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Errorf("NegotiatedProtocol = %q, want %q (forwarded from inner conn)", got, "h2")
	}

	h, ok := conn.(interface {
		HandshakeContext(context.Context) error
	})
	if !ok {
		t.Fatal("accepted conn does not expose HandshakeContext — http.Server cannot drive the handshake")
	}
	if err := h.HandshakeContext(context.Background()); err != nil {
		t.Errorf("forwarded handshake: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := h.HandshakeContext(canceled); !errors.Is(err, context.Canceled) {
		t.Errorf("forwarded handshake with canceled ctx = %v, want context.Canceled", err)
	}
}

func TestNewLimitListenerCapsAndReleases(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()

	inner := &chanListener{conns: make(chan net.Conn, 1)}
	inner.conns <- server
	ln := NewLimitListener(inner, 1)

	first, err := ln.Accept()
	if err != nil {
		t.Fatalf("first accept: %v", err)
	}

	// At the cap the next Accept must block until the first conn closes.
	blocked := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		blocked <- err
	}()
	select {
	case err := <-blocked:
		t.Fatalf("second accept returned (%v) while at cap — cap not enforced", err)
	case <-time.After(100 * time.Millisecond):
	}

	_ = first.Close() // releases the admission slot
	inner.conns <- server

	select {
	case err := <-blocked:
		if err != nil {
			t.Fatalf("second accept after release: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second accept still blocked after slot release")
	}
}

func TestNewLimitListenerZeroLimitPassthrough(t *testing.T) {
	inner := &chanListener{conns: make(chan net.Conn, 1)}
	if got := NewLimitListener(inner, 0); got != net.Listener(inner) {
		t.Error("limit <= 0 must return the listener unwrapped")
	}
}
