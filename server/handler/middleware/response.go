package middleware

import (
	"context"
	"net"
	"strings"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
)

// ResponseMiddleware is the outermost middleware.  It applies EDNS options
// (ECS, Cookie, EDE, padding, TCP keepalive) to the final response and
// restores the original qname if it was rewritten by a zone rule.
// It always runs — for short-circuited and freshly resolved responses alike.
type ResponseMiddleware struct {
	edns handler.EDNSHandler
}

// Wrap implements Middleware.
func (m *ResponseMiddleware) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		err := next.ServeDNS(ctx, qctx)

		if qctx.Res == nil {
			return err
		}

		m.finalizeResponse(qctx)
		return err
	})
}

func (m *ResponseMiddleware) finalizeResponse(qctx *handler.QueryContext) {
	msg := qctx.Res
	req := qctx.Req

	// Parse ECS if EDNSMiddleware didn't run (early short-circuit).
	ecsOpt := qctx.ECSOpt
	if ecsOpt == nil {
		ecsOpt = m.edns.ParseFromDNS(req)
		if ecsOpt == nil && len(req.Question) > 0 {
			ecsOpt = m.edns.ECSForQType(dns.RRToType(req.Question[0]))
		}
	}

	clientWantsPadding := qctx.ClientWantsPadding
	if !clientWantsPadding {
		clientWantsPadding = edns.HasPaddingOption(req)
	}

	cookieStr := m.generateCookieStr(qctx.CookieOpt, qctx.ClientIP)

	shouldAddEDNS := ecsOpt != nil || qctx.ClientRequestedDNSSEC || cookieStr != "" ||
		qctx.EDE != nil || qctx.IsSecure || qctx.TCPKeepalive > 0

	if shouldAddEDNS {
		m.edns.ApplyToMessage(msg, ecsOpt, qctx.IsSecure, cookieStr, qctx.EDE, false, clientWantsPadding, qctx.TCPKeepalive)
	}

	// Restore original domain name if zone rule rewrote it.
	if qctx.OriginalName != "" {
		currentName := req.Question[0].Header().Name
		m.restoreDomain(msg, currentName, qctx.OriginalName)
	}
}

func (m *ResponseMiddleware) generateCookieStr(cookieOpt *edns.CookieOption, clientIP net.IP) string {
	if m.edns == nil || cookieOpt == nil {
		return ""
	}

	if clientIP == nil {
		clientIP = net.ParseIP(config.FallbackClientIP)
	}

	if len(cookieOpt.ClientCookie) != edns.DefaultCookieClientLen {
		log.Debugf("EDNS: invalid client cookie length %d (expected %d)", len(cookieOpt.ClientCookie), edns.DefaultCookieClientLen)
		return ""
	}

	var serverCookie []byte
	if len(cookieOpt.ServerCookie) == edns.DefaultCookieServerLen {
		status := m.edns.IsServerCookieValid(clientIP, cookieOpt.ClientCookie, cookieOpt.ServerCookie)
		if status == edns.CookieValid {
			serverCookie = cookieOpt.ServerCookie
		} else {
			log.Debugf("EDNS: server cookie status=%d for %s, renewing", status, clientIP)
			serverCookie = m.edns.GenerateServerCookie(clientIP, cookieOpt.ClientCookie)
		}
	} else {
		serverCookie = m.edns.GenerateServerCookie(clientIP, cookieOpt.ClientCookie)
	}

	if serverCookie == nil {
		return ""
	}
	return edns.BuildCookieResponse(cookieOpt.ClientCookie, serverCookie)
}

func (m *ResponseMiddleware) restoreDomain(msg *dns.Msg, currentName, originalName string) {
	if msg == nil || strings.EqualFold(currentName, originalName) {
		return
	}
	for _, rr := range msg.Answer {
		if rr != nil && strings.EqualFold(rr.Header().Name, currentName) {
			rr.Header().Name = originalName
		}
	}
	for _, rr := range msg.Ns {
		if rr != nil && strings.EqualFold(rr.Header().Name, currentName) {
			rr.Header().Name = originalName
		}
	}
	for _, rr := range msg.Extra {
		if rr != nil && strings.EqualFold(rr.Header().Name, currentName) {
			rr.Header().Name = originalName
		}
	}
}
