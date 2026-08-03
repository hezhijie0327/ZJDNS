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

// Response is the outermost middleware.  It applies EDNS options
// (ECS, Cookie, EDE, padding, TCP keepalive) to the final response and
// restores the original qname if it was rewritten by a zone rule.
// It always runs — for short-circuited and freshly resolved responses alike.
type Response struct {
	edns handler.EDNSHandler
}

var fallbackClientIP = net.ParseIP(config.FallbackClientIP) // pre-parsed to avoid per-query allocation

// Wrap implements Wrapper.
func (m *Response) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		err := next.ServeDNS(ctx, qctx)

		// No final response was produced — a partial response (Res set
		// without Responded) is still finalized here.
		if qctx.Res == nil && !qctx.Responded {
			return err
		}

		m.finalizeResponse(qctx)
		return err
	})
}

func (m *Response) finalizeResponse(qctx *handler.QueryContext) {
	msg := qctx.Res
	req := qctx.Req

	// Parse ECS if EDNS didn't run (early short-circuit).
	ecsOpt := qctx.ECSOpt
	if ecsOpt == nil && m.edns != nil {
		ecsOpt = m.edns.ParseFromDNS(req)
		if ecsOpt == nil && len(req.Question) > 0 {
			ecsOpt = m.edns.ECSForQType(dns.RRToType(req.Question[0]))
		}
	}

	if ecsOpt != nil {
		log.Debugf("EDNS: response ECS: family=%d addr=%s/%d scope=%d fromClient=%t",
			ecsOpt.Family, ecsOpt.Address, ecsOpt.SourcePrefix, ecsOpt.ScopePrefix, qctx.ECSOpt != nil)
	}

	clientWantsPadding := qctx.ClientWantsPadding
	// Fallback for early short-circuit paths where EDNS middleware didn't run.
	if !clientWantsPadding {
		clientWantsPadding = edns.HasPaddingOption(req)
	}

	cookieStr := m.generateCookieStr(qctx.CookieOpt, qctx.ClientIP)

	// Only add EDNS if the request actually carried an OPT record (RFC 6891
	// §6.1.1) — a plain non-EDNS query over a secure transport must not get
	// an unsolicited OPT, and an invented default ECS must not be attached
	// either. qctx.EDE alone should NOT trigger adding OPT to non-EDNS
	// queries. Padding is gated separately by clientWantsPadding.
	hasRequestEDNS := qctx.Req.UDPSize != 0 || len(qctx.Req.Pseudo) > 0
	// qctx.EDE also requires an OPT carrier: on the plain UDP/TCP path the
	// fork unpacks only the question, so a request that DID carry OPT (and
	// was then rejected by Validation with an EDE) leaves Pseudo empty —
	// without this term the EDE set by Validation/EDNS middleware would be
	// silently dropped on those short-circuit responses.
	shouldAddEDNS := hasRequestEDNS || qctx.ClientRequestedDNSSEC || cookieStr != "" || qctx.EDE != nil

	// BADCOOKIE responses already have EDNS applied by the EDNS middleware.
	if shouldAddEDNS && m.edns != nil && msg.Rcode != dns.RcodeBadCookie {
		if ecsOpt != nil && qctx.ResolutionResult != nil && qctx.ResolutionResult.ECS != nil {
			// Copy before writing: without client ECS, ecsOpt is the shared
			// default-ECS singleton (ECSForQType atomic load) — mutating its
			// ScopePrefix in place races every concurrent query and leaks
			// one query's scope into another's cache partitioning decision.
			ecs := *ecsOpt
			ecs.ScopePrefix = qctx.ResolutionResult.ECS.ScopePrefix
			ecsOpt = &ecs
		}
		m.edns.ApplyToMessage(msg, ecsOpt, qctx.IsSecure, cookieStr, qctx.EDE, false, clientWantsPadding, qctx.TCPKeepalive)
	}
}

func (m *Response) generateCookieStr(cookieOpt *edns.CookieOption, clientIP net.IP) string {
	if m.edns == nil || cookieOpt == nil {
		return ""
	}

	if clientIP == nil {
		clientIP = fallbackClientIP
	}

	if len(cookieOpt.ClientCookie) != edns.DefaultCookieClientLen {
		log.Debugf("EDNS: invalid client cookie length %d (expected %d)", len(cookieOpt.ClientCookie), edns.DefaultCookieClientLen)
		return ""
	}

	var serverCookie []byte
	if len(cookieOpt.ServerCookie) == edns.DefaultCookieServerLen {
		status := m.edns.IsServerCookieValid(clientIP, cookieOpt.ClientCookie, cookieOpt.ServerCookie)
		if status == edns.CookieValid || status == edns.CookieValidRenew {
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
