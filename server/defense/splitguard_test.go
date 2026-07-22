package defense

import (
	"net"
	"testing"
	"time"
)

func TestWriteTCPMsgSegmented_NoSegment(t *testing.T) {
	// segSize=0 → normal Write (no segmentation).
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	msg := []byte{0x00, 0x10, 0x01, 0x02, 0x03, 0x04} // 2B prefix + 4B payload
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
	// segSize=1 → first segment = 2+1=3 bytes, remaining = 1 byte each.
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	msg := []byte{0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD} // 2B prefix + 4B payload

	go func() {
		buf := make([]byte, 100)
		// Read all segments — each Write should be a separate Read.
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
	// segSize > len(msg)-2 → falls back to normal Write.
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	msg := []byte{0x00, 0x03, 0x01, 0x02, 0x03} // 2B + 3B
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
	// segSize=1 with delay — should still produce correct total bytes.
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	msg := []byte{0x00, 0x02, 0x01, 0x02} // 2B + 2B

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
	// At least 1ms delay between first (3B) and second (1B) segments.
	if elapsed < 1*time.Millisecond {
		t.Errorf("expected at least 1ms delay, got %v", elapsed)
	}
}
