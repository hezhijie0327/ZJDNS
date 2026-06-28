package edns

import (
	"github.com/miekg/dns"

	"zjdns/internal/pool"
)

// paddingBlockSize is the block size boundary for DNS message padding on secure
// transports (RFC 8467 §4). 468 bytes aligns responses to a 128-byte boundary
// within a 512-byte block, reducing the risk of traffic analysis via
// encrypted DNS message length. This matches config.DefaultPaddingBlockSize but
// is defined locally because the edns package cannot import config (import cycle).
const paddingBlockSize = 468

const paddingHeaderSize = 4

func addPadding(msg *dns.Msg, options []dns.EDNS0, isSecureConnection bool) ([]dns.EDNS0, int) {
	if !isSecureConnection {
		return options, 0
	}

	tmpOpt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  pool.UDPBufferSize,
		},
	}
	tmpOpt.Option = options
	savedExtra := msg.Extra
	msg.Extra = append(msg.Extra, tmpOpt)

	// Use Len() instead of Pack() to compute wire size without serializing.
	// The DNS library's response writer calls msg.Pack() again during WriteMsg,
	// so serializing here would double-pack every secure-transport response.
	currentSize := msg.Len()
	targetSize := ((currentSize + paddingBlockSize - 1) / paddingBlockSize) * paddingBlockSize
	paddingDataSize := targetSize - currentSize - paddingHeaderSize
	if paddingDataSize > 0 {
		msg.Extra = savedExtra
		return append(options, &dns.EDNS0_PADDING{
			Padding: make([]byte, paddingDataSize),
		}), paddingDataSize
	}

	msg.Extra = savedExtra
	return options, 0
}
