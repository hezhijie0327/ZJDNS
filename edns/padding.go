package edns

import (
	"encoding/hex"

	"codeberg.org/miekg/dns"
)

const paddingHeaderSize = 4

// HasPaddingOption checks whether the client's EDNS(0) request includes a
// padding option. If the client sent EDNS without padding, it explicitly opted
// out (dig +nopadding / +noalignment). If the client sent no EDNS at all, we
// default to padding for privacy.
func HasPaddingOption(req *dns.Msg) bool {
	if len(req.Pseudo) > 0 {
		for _, o := range req.Pseudo {
			if _, ok := o.(*dns.PADDING); ok {
				return true
			}
		}
		return false
	}
	return true // No EDNS: legacy client, pad by default
}

func addPaddingV2(msg *dns.Msg, isSecureConnection bool, blockSize int, clientWantsPadding bool) int {
	if !isSecureConnection || !clientWantsPadding {
		return 0
	}

	// Use Len() to compute current wire size.
	currentSize := msg.Len()
	targetSize := ((currentSize + blockSize - 1) / blockSize) * blockSize
	paddingDataSize := targetSize - currentSize - paddingHeaderSize
	if paddingDataSize > 0 {
		paddingBytes := make([]byte, paddingDataSize)
		msg.Pseudo = append(msg.Pseudo, &dns.PADDING{
			Padding: hex.EncodeToString(paddingBytes),
		})
		return paddingDataSize
	}

	return 0
}
