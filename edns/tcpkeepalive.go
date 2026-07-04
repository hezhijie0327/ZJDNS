package edns

import (
	"codeberg.org/miekg/dns"
)

// ParseTCPKeepalive extracts the EDNS0 TCP keepalive timeout from a DNS
// message. Returns 0 if no EDNS0_TCP_KEEPALIVE option is present.
func ParseTCPKeepalive(msg *dns.Msg) uint16 {
	for _, rr := range msg.Pseudo {
		if keepalive, ok := rr.(*dns.TCPKEEPALIVE); ok {
			return keepalive.Timeout
		}
	}
	return 0
}

// HasTCPKeepaliveOption reports whether the message includes an EDNS0 TCP
// keepalive option (with any timeout value, including zero).
func HasTCPKeepaliveOption(msg *dns.Msg) bool {
	for _, rr := range msg.Pseudo {
		if _, ok := rr.(*dns.TCPKEEPALIVE); ok {
			return true
		}
	}
	return false
}
