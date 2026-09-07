package edns

import (
	"time"
	"zjdns/config"

	"codeberg.org/miekg/dns"
)

// QueryTCPKeepalive reports whether the query carries the EDNS TCP Keepalive
// option — the client asking the server to advertise its idle timeout in the
// response (RFC 7828 §3.2).
func QueryTCPKeepalive(req *dns.Msg) bool {
	if req == nil {
		return false
	}
	for _, o := range req.Pseudo {
		if _, ok := o.(*dns.TCPKEEPALIVE); ok {
			return true
		}
	}
	return false
}

// TCPKeepaliveTimeout returns the option value to advertise in a response
// over a stream transport: the listener's actual per-message idle read
// deadline in 100ms units (RFC 7828 §3.3.2 — the server MUST specify the
// timeout currently associated with the session). Zero for non-stream
// transports (§3.3.1: the option is TCP-only; a query carrying it over
// anything else has the option ignored).
func TCPKeepaliveTimeout(protocol string) uint16 {
	switch protocol {
	case config.ProtoTCP:
		return keepaliveUnits(config.DefaultTCPIdleTimeout)
	case config.ProtoTLS, config.ProtoTLCP:
		return keepaliveUnits(config.DefaultTCPPoolIdleTimeout)
	}
	return 0
}

func keepaliveUnits(d time.Duration) uint16 {
	return uint16(d / (100 * time.Millisecond)) //nolint:gosec // G115: bounded by config constants
}
