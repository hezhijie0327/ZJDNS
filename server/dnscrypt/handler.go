// Package dnscrypt provides a DNSCrypt v2 server wrapper and handler adapter
// using the github.com/AdguardTeam/dnscrypt library.
package dnscrypt

import (
	"context"
	"net"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/miekg/dns"

	"zjdns/internal/log"
)

// DNSHandler is the interface for processing incoming DNS queries.
// This mirrors the tls.DNSHandler interface to avoid a circular import.
type DNSHandler interface {
	ServeDNS(req *dns.Msg, clientIP net.IP, isSecure bool, protocol string) *dns.Msg
}

// handlerAdapter adapts our DNSHandler to the dnscrypt.Handler interface.
type handlerAdapter struct {
	inner DNSHandler
}

// ServeDNS implements the dnscrypt.Handler interface.
func (h *handlerAdapter) ServeDNS(ctx context.Context, rw dnscrypt.ResponseWriter, req *dns.Msg) error {
	clientIP := extractClientIP(rw)

	log.Debugf("DNSCRYPT: DNSCrypt query from %s for %s", clientIP, req.Question[0].Name)

	response := h.inner.ServeDNS(req, clientIP, false, "DNSCrypt")
	if response == nil {
		return nil
	}

	return rw.WriteMsg(ctx, response)
}

func extractClientIP(rw dnscrypt.ResponseWriter) net.IP {
	addr := rw.RemoteAddr()
	if addr == nil {
		return nil
	}
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP
	case *net.TCPAddr:
		return a.IP
	default:
		return nil
	}
}
