package edns

import (
	"github.com/miekg/dns"

	"zjdns/internal/pool"
)

// paddingRequestBlockSize aligns outgoing DNS queries to a 128-byte boundary
// (RFC 8467). Most queries are 50–110 bytes, so a single 128-byte block obscures
// the exact query name while minimising upload-bandwidth waste.
const paddingRequestBlockSize = 128

// paddingResponseBlockSize aligns DNS responses to a 468-byte boundary. This is
// the largest multiple of 128 that fits safely below the 512-byte standard DNS
// UDP limit (512 − 44 bytes of IP/UDP/buffer headroom), so nearly all responses
// in the 0–468 range share the same size. This matches
// config.DefaultPaddingResponseBlockSize but is defined locally because the edns
// package cannot import config (import cycle).
const paddingResponseBlockSize = 468

const paddingHeaderSize = 4

// HasPaddingOption checks whether the client's EDNS(0) request includes a
// padding option. If the client sent EDNS without padding, it explicitly opted
// out (dig +nopadding / +noalignment). If the client sent no EDNS at all, we
// default to padding for privacy.
func HasPaddingOption(req *dns.Msg) bool {
	if opt := req.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if _, ok := o.(*dns.EDNS0_PADDING); ok {
				return true
			}
		}
		return false
	}
	return true // No EDNS: legacy client, pad by default
}

func addPadding(msg *dns.Msg, options []dns.EDNS0, isSecureConnection bool, blockSize int, clientWantsPadding bool) ([]dns.EDNS0, int) {
	if !isSecureConnection || !clientWantsPadding {
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
	targetSize := ((currentSize + blockSize - 1) / blockSize) * blockSize
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
