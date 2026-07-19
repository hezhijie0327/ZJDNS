package shared

import "testing"

func TestClassifyRecordHeader_TLS(t *testing.T) {
	// TLS 1.3 ClientHello: ContentType=22(0x16), Version=0x0303
	hdr := []byte{0x16, 0x03, 0x03, 0x01, 0x00}
	v := ClassifyRecordHeader(hdr)
	if v != VersionTLS {
		t.Errorf("expected VersionTLS, got %d", v)
	}
}

func TestClassifyRecordHeader_TLCP(t *testing.T) {
	hdr := []byte{0x16, 0x01, 0x01, 0x01, 0x00}
	v := ClassifyRecordHeader(hdr)
	if v != VersionTLCP {
		t.Errorf("expected VersionTLCP, got %d", v)
	}
}

func TestClassifyRecordHeader_ShortPacket(t *testing.T) {
	hdr := []byte{0x16, 0x03}
	v := ClassifyRecordHeader(hdr)
	if v != VersionUnknown {
		t.Errorf("expected VersionUnknown, got %d", v)
	}
}

func TestClassifyRecordHeader_DTLS(t *testing.T) {
	// DTLS 1.2 ClientHello: ContentType=22(0x16), Version=0xFEFD
	hdr := []byte{0x16, 0xFE, 0xFD, 0x00, 0x00}
	v := ClassifyRecordHeader(hdr)
	if v != VersionDTLS {
		t.Errorf("expected VersionDTLS, got %d", v)
	}
}

func TestClassifyRecordHeader_Unknown(t *testing.T) {
	// Unknown major version (0xFF) returns the raw byte value.
	hdr := []byte{0x16, 0xFF, 0xFF, 0x01, 0x00}
	v := ClassifyRecordHeader(hdr)
	if v == VersionTLS || v == VersionTLCP || v == VersionDTLS {
		t.Errorf("unexpected known version: %d", v)
	}
}

func TestIsQUICPacket_LongHeader(t *testing.T) {
	// QUIC v1 Initial packet: long header, fixed bit set
	pkt := []byte{0xC0, 0x00, 0x00, 0x01, 0x00}
	if !IsQUICPacket(pkt) {
		t.Error("QUIC long header should be detected")
	}
}

func TestIsQUICPacket_ShortHeader(t *testing.T) {
	// QUIC v1 short header: 01xxxxxx (fixed bit + spin/reserved)
	pkt := []byte{0x40, 0x00}
	if !IsQUICPacket(pkt) {
		t.Error("QUIC short header should be detected")
	}
}

func TestIsQUICPacket_NoFixedBit(t *testing.T) {
	// Packet without fixed bit set
	pkt := []byte{0x00, 0x00}
	if IsQUICPacket(pkt) {
		t.Error("packet without fixed bit should NOT be QUIC")
	}
}

func TestIsQUICPacket_KeyPhaseBit(t *testing.T) {
	// QUIC v1 short header with Key Phase bit (0x04) set — valid during
	// key phase transitions.  Also covers QUIC v2 long-header packets
	// where version-specific bits may use the 0x0C positions.
	pkt := []byte{0x44, 0x00} // fixed bit + key phase
	if !IsQUICPacket(pkt) {
		t.Error("QUIC v1 with key-phase bit set should be detected (RFC 8999 invariant)")
	}
	// QUIC v2 style long header: fixed bit set, version-specific bits non-zero.
	pkt2 := []byte{0xcc, 0x00, 0x00, 0x01, 0x00}
	if !IsQUICPacket(pkt2) {
		t.Error("QUIC v2 (or non-v1) with version-specific bits set should be detected")
	}
}

func TestIsQUICPacket_DTLS(t *testing.T) {
	// DTLS ClientHello: ContentType=22(0x16)
	pkt := []byte{0x16, 0xFE, 0xFD}
	if IsQUICPacket(pkt) {
		t.Error("DTLS packet should NOT be detected as QUIC")
	}
}

func TestIsQUICPacket_Empty(t *testing.T) {
	if IsQUICPacket(nil) {
		t.Error("nil should not be QUIC")
	}
	if IsQUICPacket([]byte{}) {
		t.Error("empty should not be QUIC")
	}
}
