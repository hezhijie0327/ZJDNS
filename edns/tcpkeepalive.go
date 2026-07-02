package edns

import (
	"github.com/miekg/dns"
)

// ParseTCPKeepalive extracts the EDNS0 TCP keepalive timeout from a DNS
// message. Returns 0 if no EDNS0_TCP_KEEPALIVE option is present.
func ParseTCPKeepalive(msg *dns.Msg) uint16 {
	if opt := msg.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if keepalive, ok := o.(*dns.EDNS0_TCP_KEEPALIVE); ok {
				return keepalive.Timeout
			}
		}
	}
	return 0
}

// HasTCPKeepaliveOption reports whether the message includes an EDNS0 TCP
// keepalive option (with any timeout value, including zero).
func HasTCPKeepaliveOption(msg *dns.Msg) bool {
	if opt := msg.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if _, ok := o.(*dns.EDNS0_TCP_KEEPALIVE); ok {
				return true
			}
		}
	}
	return false
}
