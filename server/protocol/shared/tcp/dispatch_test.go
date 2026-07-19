package tcp

import (
	"net"
	"testing"
)

func TestConnListener_Accept(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	cl := &connListener{conn: server}

	// First Accept returns the connection.
	conn, err := cl.Accept()
	if err != nil {
		t.Fatalf("first Accept: %v", err)
	}
	if conn != server {
		t.Error("Accept should return the original conn")
	}

	// Second Accept blocks forever — test with a goroutine.
	errCh := make(chan error, 1)
	go func() {
		_, err := cl.Accept()
		errCh <- err
	}()

	// Close the listener to unblock Accept.
	_ = cl.Close()
	if err := <-errCh; err == nil {
		t.Error("second Accept should fail after Close")
	}
}

func TestConnListener_Addr(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	cl := &connListener{conn: server}
	if cl.Addr() != server.LocalAddr() {
		t.Error("Addr should match conn.LocalAddr()")
	}
}

func TestConnListener_CloseClosesConn(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()

	cl := &connListener{conn: server}
	_ = cl.Close()

	// Socket should be closed.
	buf := make([]byte, 1)
	_, err := server.Read(buf)
	if err == nil {
		t.Error("Read should fail after Close")
	}
}
