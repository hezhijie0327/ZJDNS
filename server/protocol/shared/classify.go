package shared

// RecordVersion is the protocol major version from a TLS/DTLS record layer
// header.
type RecordVersion byte

const (
	VersionUnknown RecordVersion = 0
	VersionTLCP    RecordVersion = 0x01 // TLCP (GB/T 38636-2020) + DTLCP (GM/T 0128-2023)
	VersionTLS     RecordVersion = 0x03 // TLS 1.0–1.3 (0x0301–0x0304)
	VersionDTLS    RecordVersion = 0xFE // DTLS 1.0/1.2 (0xFEFD/0xFEFF)
)

// recordHeaderLen is the size of the TLS/TLCP/DTLS record layer header:
//
//	ContentType     (1 byte)
//	ProtocolVersion (2 bytes)
//	Length          (2 bytes)
const RecordHeaderLen = 5

// ClassifyRecordHeader peeks at the TLS/DTLS record layer header and returns
// the protocol major version.  pkt must be at least recordHeaderLen bytes;
// shorter packets return VersionUnknown.
//
// Used by both TCP (SharedTCPListener) and UDP (SharedUDPListener, UDPDemux)
// paths to distinguish TLS/DTLS from TLCP/DTLCP.
func ClassifyRecordHeader(pkt []byte) RecordVersion {
	if len(pkt) < RecordHeaderLen {
		return VersionUnknown
	}
	return RecordVersion(pkt[1])
}

// IsQUICPacket reports whether the first byte of pkt indicates a QUIC packet.
// Only the Fixed Bit (0x40) is an invariant across all QUIC versions (RFC 8999
// §3.1).  The 0x0C reserved-bit check was QUIC v1-specific — it rejects valid
// QUIC v2 (RFC 9369) packets as well as QUIC v1 short-header packets during
// key-phase transitions where bit 0x04 (Key Phase) is set.
func IsQUICPacket(pkt []byte) bool {
	if len(pkt) < 1 {
		return false
	}
	return pkt[0]&0x40 != 0
}
