package middleware

import (
	"context"
	"net"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
)

// EDNS parses EDNS options (ECS, Cookie, DNSSEC OK) from the
// incoming request and validates the DNS Cookie per RFC 7873.  Invalid
// cookies receive a BADCOOKIE response.
type EDNS struct {
	edns   handler.EDNSHandler
	config *config.ServerConfig
}

// Wrap implements Wrapper.
func (m *EDNS) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		req := qctx.Req

		// The miekg/dns server only unpacks the question section by default
		// (MsgOptionUnpackQuestion) for routing.  Force a full unpack so that
		// EDNS options (ECS, Cookie, etc.) in the OPT record are extracted into
		// req.Pseudo.  If this second pass fails, the message is malformed —
		// reject it rather than silently operating on a partially-parsed message.
		req.Options = 0
		if err := req.Unpack(); err != nil {
			log.Debugf("EDNS: full unpack failed: %v", err)
			msg := handler.BuildResponseMsg(req)
			msg.Rcode = dns.RcodeFormatError
			qctx.Res = msg
			return nil
		}

		qctx.ClientRequestedDNSSEC = req.Security
		qctx.ECSOpt = m.edns.ParseFromDNS(req)
		if qctx.ECSOpt != nil {
			log.Debugf("EDNS: client ECS parsed: family=%d addr=%s/%d scope=%d",
				qctx.ECSOpt.Family, qctx.ECSOpt.Address, qctx.ECSOpt.SourcePrefix, qctx.ECSOpt.ScopePrefix)
		} else {
			log.Debugf("EDNS: no ECS from client")
		}
		// RFC 7871 §6: reject malformed ECS options with FORMERR. The
		// malformed state must be cleared and the SUBNET stripped from
		// Pseudo: the outer Response middleware re-applies qctx.ECSOpt (and
		// falls back to re-parsing req.Pseudo) for every non-BADCOOKIE
		// response, which would echo the invalid option back to the client.
		if qctx.ECSOpt != nil && !qctx.ECSOpt.IsValid() {
			log.Debugf("EDNS: malformed ECS option from %s", qctx.ClientIP)
			qctx.ECSOpt = nil
			pseudo := qctx.Req.Pseudo[:0]
			for _, opt := range qctx.Req.Pseudo {
				if _, isSubnet := opt.(*dns.SUBNET); !isSubnet {
					pseudo = append(pseudo, opt)
				}
			}
			qctx.Req.Pseudo = pseudo
			msg := handler.BuildResponseMsg(req)
			msg.Rcode = dns.RcodeFormatError
			qctx.Res = msg
			return nil
		}
		var cookieMalformed bool
		qctx.CookieOpt, cookieMalformed = m.edns.ParseCookie(req)
		if cookieMalformed {
			// RFC 7873 §5.3: a malformed client cookie is rejected with
			// FORMERR, not silently treated as absent.
			log.Debugf("EDNS: malformed client cookie from %s", qctx.ClientIP)
			msg := handler.BuildResponseMsg(req)
			msg.Rcode = dns.RcodeFormatError
			qctx.Res = msg
			return nil
		}
		qctx.ClientWantsPadding = edns.HasPaddingOption(req)

		cookieOpt := qctx.CookieOpt

		// RFC 7873: Server cookie length != 16 bytes → BADCOOKIE.
		if cookieOpt != nil && len(cookieOpt.ServerCookie) > 0 && len(cookieOpt.ServerCookie) != edns.DefaultCookieServerLen {
			log.Debugf("EDNS: bad server cookie length %d (expected %d) from %s, returning BADCOOKIE", len(cookieOpt.ServerCookie), edns.DefaultCookieServerLen, qctx.ClientIP)
			qctx.Res = m.buildBadCookieResponse(req, qctx.ClientIP, cookieOpt, qctx.ECSOpt)
			return nil
		}

		// RFC 7873: Full server cookie (16 bytes) → cryptographic validation.
		if cookieOpt != nil && len(cookieOpt.ServerCookie) == edns.DefaultCookieServerLen {
			status := m.edns.IsServerCookieValid(qctx.ClientIP, cookieOpt.ClientCookie, cookieOpt.ServerCookie)
			if status == edns.CookieExpired || status == edns.CookieFuture || status == edns.CookieInvalid {
				log.Debugf("EDNS: bad server cookie (status=%d) from %s, returning BADCOOKIE", status, qctx.ClientIP)
				qctx.Res = m.buildBadCookieResponse(req, qctx.ClientIP, cookieOpt, qctx.ECSOpt)
				return nil
			}
		}

		// Apply default ECS if no ECS was sent.
		if qctx.ECSOpt == nil && len(req.Question) > 0 {
			qctx.ECSOpt = m.edns.ECSForQType(dns.RRToType(req.Question[0]))
			if qctx.ECSOpt != nil {
				log.Debugf("EDNS: using default ECS: family=%d addr=%s/%d",
					qctx.ECSOpt.Family, qctx.ECSOpt.Address, qctx.ECSOpt.SourcePrefix)
			}
		}

		return next.ServeDNS(ctx, qctx)
	})
}

func (m *EDNS) buildBadCookieResponse(req *dns.Msg, clientIP net.IP, cookieOpt *edns.CookieOption, ecsOpt *edns.ECSOption) *dns.Msg {
	msg := handler.BuildResponseMsg(req)
	msg.Rcode = dns.RcodeBadCookie
	if cookieOpt == nil || len(cookieOpt.ClientCookie) != edns.DefaultCookieClientLen {
		// RFC 7873 §5.3: the echoed client cookie must be exactly 8 octets.
		log.Debugf("EDNS: bad cookie length %d from %s, returning FORMERR", len(cookieOpt.ClientCookie), clientIP)
		msg.Rcode = dns.RcodeFormatError
		return msg
	}

	serverCookie := m.edns.GenerateServerCookie(clientIP, cookieOpt.ClientCookie)
	cookieStr := edns.BuildCookieResponse(cookieOpt.ClientCookie, serverCookie)

	m.edns.ApplyToMessage(msg, ecsOpt, false, cookieStr, nil, false, edns.HasPaddingOption(req), 0)
	return msg
}
