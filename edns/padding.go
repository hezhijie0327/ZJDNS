package edns

import (
	"github.com/miekg/dns"

	"zjdns/internal/pool"
)

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
