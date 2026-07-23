package dnsutil

import (
	"net"
	"testing"
	"time"
)

func TestWriteTCPMsgSegmented_NoSegment(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	msg := []byte{0x00, 0x10, 0x01, 0x02, 0x03, 0x04}
	go func() {
		buf := make([]byte, 100)
		n, _ := server.Read(buf)
		if n != len(msg) {
			t.Errorf("expected %d bytes, got %d", len(msg), n)
		}
	}()

	n, err := WriteTCPMsgSegmented(client, msg, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(msg) {
		t.Errorf("expected %d bytes written, got %d", len(msg), n)
	}
}

func TestWriteTCPMsgSegmented_Segment(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	msg := []byte{0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD}
	go func() {
		buf := make([]byte, 100)
		var total int
		for total < len(msg) {
			n, err := server.Read(buf[total:])
			if err != nil {
				return
			}
			total += n
		}
		if total != len(msg) {
			t.Errorf("expected %d bytes total, got %d", len(msg), total)
		}
	}()

	n, err := WriteTCPMsgSegmented(client, msg, 1, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(msg) {
		t.Errorf("expected %d bytes written, got %d", len(msg), n)
	}
}

func TestWriteTCPMsgSegmented_SegSizeLargerThanPayload(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	msg := []byte{0x00, 0x03, 0x01, 0x02, 0x03}
	go func() {
		buf := make([]byte, 100)
		n, _ := server.Read(buf)
		if n != len(msg) {
			t.Errorf("expected %d bytes, got %d", len(msg), n)
		}
	}()

	n, err := WriteTCPMsgSegmented(client, msg, 100, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(msg) {
		t.Errorf("expected %d bytes written, got %d", len(msg), n)
	}
}

func TestWriteTCPMsgSegmented_Delay(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	msg := []byte{0x00, 0x02, 0x01, 0x02}
	start := time.Now()
	go func() {
		buf := make([]byte, 100)
		var total int
		for total < len(msg) {
			n, _ := server.Read(buf[total:])
			total += n
		}
	}()

	n, err := WriteTCPMsgSegmented(client, msg, 1, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(msg) {
		t.Errorf("expected %d bytes, got %d", len(msg), n)
	}
	elapsed := time.Since(start)
	if elapsed < 1*time.Millisecond {
		t.Errorf("expected at least 1ms delay, got %v", elapsed)
	}
}
