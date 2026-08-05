package edns

import (
	"encoding/binary"
	"encoding/hex"
	"math/rand/v2"

	"codeberg.org/miekg/dns"
)

const paddingHeaderSize = 4

// HasPaddingOption checks whether the client's EDNS(0) request includes a
// padding option. If the client sent EDNS without padding, it explicitly opted
// out (dig +nopadding / +noalignment). If the client sent no EDNS at all, we
// default to padding for privacy.
func HasPaddingOption(req *dns.Msg) bool {
	if req == nil {
		return false
	}
	// EDNS presence is UDPSize != 0 — in this fork Msg.Pseudo holds only the
	// EDNS0 options, while the OPT record itself is merged into the header
	// fields on Unpack. An OPT record with an empty option list is an
	// explicit opt-out (dig +nopadding / +noalignment) and must NOT be
	// treated as a legacy no-EDNS client.
	hasEDNS := req.UDPSize != 0
	for _, o := range req.Pseudo {
		if _, ok := o.(*dns.PADDING); ok {
			return true
		}
	}
	// No EDNS: legacy client, pad by default. EDNS without a PADDING option
	// is an explicit opt-out.
	return !hasEDNS
}

func addPadding(msg *dns.Msg, isSecureConnection bool, blockSize int, clientWantsPadding bool) int {
	if !isSecureConnection || !clientWantsPadding {
		return 0
	}

	// Pack first to get the real compressed wire size — msg.Len()
	// returns uncompressed size which overestimates by 100+ bytes
	// when name compression is active, causing padding to fall short
	// of the target block size.
	if err := msg.Pack(); err != nil {
		// A failed pack leaves msg.Data nil/stale — do not size padding
		// against incorrect data on a privacy-sensitive path.
		return 0
	}
	currentSize := len(msg.Data)
	targetSize := ((currentSize + blockSize - 1) / blockSize) * blockSize
	paddingDataSize := targetSize - currentSize - paddingHeaderSize
	// An empty PADDING option (4-byte header, zero data) is exactly what is
	// needed to land on the block boundary — the >= 0 guard (not > 0) keeps it.
	if paddingDataSize >= 0 {
		paddingBytes := make([]byte, paddingDataSize)
		// 4 bytes per rand.Uint32() call — the global ChaCha8 RNG is
		// concurrency-safe (locked), and math/rand/v2 has no package-level
		// Read.  Per-byte extraction would quadruple the lock traffic.
		for i := 0; i+4 <= len(paddingBytes); i += 4 {
			binary.BigEndian.PutUint32(paddingBytes[i:], rand.Uint32()) //nolint:gosec // math/rand acceptable for padding — non-crypto use
		}
		for i := len(paddingBytes) &^ 3; i < len(paddingBytes); i++ {
			paddingBytes[i] = byte(rand.Uint32()) //nolint:gosec // math/rand acceptable for padding — non-crypto use
		}
		msg.Pseudo = append(msg.Pseudo, &dns.PADDING{
			Padding: hex.EncodeToString(paddingBytes),
		})
		// Repack so msg.Data includes the PADDING option — bridge.go serves
		// this wire directly (skipping its own packSafe), so the sizing pack
		// above is the only one.
		if err := msg.Pack(); err != nil {
			return 0
		}
		return paddingDataSize
	}

	return 0
}
