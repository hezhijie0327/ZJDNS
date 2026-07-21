package dnsutil

import (
	"net"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func TestReadWriteTCPMsg(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)
	q.ID = 0x1234
	q.RecursionDesired = true

	errCh := make(chan error, 1)
	var got *dns.Msg
	go func() {
		var err error
		got, err = ReadTCPMsg(server)
		errCh <- err
	}()

	if err := WriteTCPMsg(client, q); err != nil {
		t.Fatalf("WriteTCPMsg: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("ReadTCPMsg: %v", err)
	}

	if got.ID != q.ID {
		t.Errorf("ID = %d, want %d", got.ID, q.ID)
	}
	if len(got.Question) != 1 {
		t.Fatalf("len(Question) = %d, want 1", len(got.Question))
	}
}

func TestReadTCPMsg_ShortRead(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	errCh := make(chan error, 1)
	go func() {
		_, err := ReadTCPMsg(server)
		errCh <- err
	}()

	_, _ = client.Write([]byte{0x00})
	_ = client.Close()

	if err := <-errCh; err == nil {
		t.Error("expected error on truncated length prefix, got nil")
	}
}
