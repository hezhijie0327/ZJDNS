package edns

import "github.com/miekg/dns"

// PaddingSize is the block size boundary (468 bytes) for DNS message padding
// on secure transports.
const PaddingSize = 468

func addPadding(msg *dns.Msg, options []dns.EDNS0, isSecureConnection bool) ([]dns.EDNS0, int) {
	if !isSecureConnection {
		return options, 0
	}

	tmpOpt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  1232,
		},
	}
	tmpOpt.Option = options
	savedExtra := msg.Extra
	msg.Extra = append(msg.Extra, tmpOpt)

	// Use Len() instead of Pack() to compute wire size without serializing.
	// The DNS library's response writer calls msg.Pack() again during WriteMsg,
	// so serializing here would double-pack every secure-transport response.
	currentSize := msg.Len()
	targetSize := ((currentSize + PaddingSize - 1) / PaddingSize) * PaddingSize
	paddingDataSize := targetSize - currentSize - 4
	if paddingDataSize > 0 {
		msg.Extra = savedExtra
		return append(options, &dns.EDNS0_PADDING{
			Padding: make([]byte, paddingDataSize),
		}), paddingDataSize
	}

	msg.Extra = savedExtra
	return options, 0
}
