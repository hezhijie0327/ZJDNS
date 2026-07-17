package handler

import (
	"context"
	"net"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

// EDNSMiddleware parses EDNS options (ECS, Cookie, DNSSEC OK) from the
// incoming request and validates the DNS Cookie per RFC 7873.  Invalid
// cookies receive a BADCOOKIE response.
type EDNSMiddleware struct {
	edns   *edns.Handler
	config *config.ServerConfig
}

// Wrap implements Middleware.
func (m *EDNSMiddleware) Wrap(next QueryHandler) QueryHandler {
	return QueryHandlerFunc(func(ctx context.Context, qctx *QueryContext) error {
		req := qctx.Req

		// Force a full unpack so EDNS flags are available.
		_ = req.Unpack()

		qctx.ClientRequestedDNSSEC = req.Security
		qctx.ECSOpt = m.edns.ParseFromDNS(req)
		qctx.CookieOpt = m.edns.ParseCookie(req)
		qctx.ClientWantsPadding = edns.HasPaddingOption(req)

		cookieOpt := qctx.CookieOpt

		// RFC 7873: Short server cookie (1-15 bytes) → BADCOOKIE.
		if cookieOpt != nil && len(cookieOpt.ServerCookie) > 0 && len(cookieOpt.ServerCookie) < edns.DefaultCookieServerLen {
			log.Debugf("EDNS: short server cookie (%d bytes) from %s, returning BADCOOKIE", len(cookieOpt.ServerCookie), qctx.ClientIP)
			qctx.Res = m.buildBadCookieResponse(req, qctx.ClientIP, cookieOpt)
			return nil
		}

		// RFC 7873: Full server cookie (16 bytes) → cryptographic validation.
		if cookieOpt != nil && len(cookieOpt.ServerCookie) == edns.DefaultCookieServerLen {
			status := m.edns.CookieGenerator.IsServerCookieValid(qctx.ClientIP, cookieOpt.ClientCookie, cookieOpt.ServerCookie)
			if status == edns.CookieExpired || status == edns.CookieFuture || status == edns.CookieInvalid {
				log.Debugf("EDNS: bad server cookie (status=%d) from %s, returning BADCOOKIE", status, qctx.ClientIP)
				qctx.Res = m.buildBadCookieResponse(req, qctx.ClientIP, cookieOpt)
				return nil
			}
		}

		// Apply default ECS if no ECS was sent.
		if qctx.ECSOpt == nil && len(req.Question) > 0 {
			qctx.ECSOpt = m.edns.ECSForQType(dns.RRToType(req.Question[0]))
		}

		return next.ServeDNS(ctx, qctx)
	})
}

func (m *EDNSMiddleware) buildBadCookieResponse(req *dns.Msg, clientIP net.IP, cookieOpt *edns.CookieOption) *dns.Msg {
	msg := buildResponseMsg(req)
	msg.Rcode = dns.RcodeFormatError

	serverCookie := m.edns.CookieGenerator.GenerateServerCookie(clientIP, cookieOpt.ClientCookie)
	cookieStr := edns.BuildCookieResponse(cookieOpt.ClientCookie, serverCookie)

	ecsOpt := m.edns.ParseFromDNS(req)
	m.edns.ApplyToMessage(msg, ecsOpt, false, cookieStr, nil, false, edns.HasPaddingOption(req), 0)
	return msg
}
