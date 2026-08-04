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

		if qctx.Res == nil {
			return err
		}

		// Pre-packed response: unpack the pre-built wire so the normal
		// EDNS + Pack pipeline can continue.  TTLs were already adjusted
		// in-place by buildFromPrePacked.  Clear Data after Unpack so
		// bridge.go calls Pack() with the EDNS options applied below.
		// Overwrite the message ID — the pre-packed wire carries the
		// ID from Set() time; the response must echo the client's ID.
		if qctx.Res.Data != nil {
			if err := qctx.Res.Unpack(); err != nil {
				log.Debugf("RESPONSE: unpack pre-packed response: %v", err)
				qctx.Res.Rcode = dns.RcodeServerFailure
				return err
			}
			qctx.Res.ID = qctx.Req.ID
			qctx.Res.Data = nil
		}

		m.finalizeResponse(qctx)
		return err
	})
}

func (m *Response) finalizeResponse(qctx *handler.QueryContext) {
	msg := qctx.Res
	req := qctx.Req
	if req == nil {
		// Defensive: the chain guarantees a request, but the Response
		// middleware must not crash on a nil req (restoreDomain and the
		// EDNS fallback both dereference it).
		return
	}

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
	if !clientWantsPadding {
		clientWantsPadding = edns.HasPaddingOption(req)
	}

	cookieStr := m.generateCookieStr(qctx.CookieOpt, qctx.ClientIP)

	shouldAddEDNS := ecsOpt != nil || qctx.ClientRequestedDNSSEC || cookieStr != "" ||
		qctx.EDE != nil || qctx.IsSecure || qctx.TCPKeepalive > 0 || len(qctx.Req.Pseudo) > 0

	if shouldAddEDNS && m.edns != nil && !msgHasEDNSOptions(msg) {
		// Skip when the response already carries EDNS options: a BADCOOKIE
		// response built by the EDNS middleware applied its own
		// SUBNET/COOKIE/padding, and re-applying would duplicate options
		// inside a single OPT (RFC 7873: at most one COOKIE per message).
		m.edns.ApplyToMessage(msg, ecsOpt, qctx.IsSecure, cookieStr, qctx.EDE, false, clientWantsPadding, qctx.TCPKeepalive)
	}

	// Restore original domain name if zone rule rewrote it.
	if qctx.OriginalName != "" {
		currentName := qctx.RewrittenName
		if currentName == "" {
			currentName = req.Question[0].Header().Name
		}
		m.restoreDomain(msg, currentName, qctx.OriginalName)
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

// msgHasEDNSOptions reports whether the response already carries EDNS
// options in its OPT pseudo-record.
func msgHasEDNSOptions(msg *dns.Msg) bool {
	for _, rr := range msg.Pseudo {
		if _, ok := rr.(*dns.COOKIE); ok {
			return true
		}
		if _, ok := rr.(*dns.SUBNET); ok {
			return true
		}
	}
	return false
}

// restoreDomain rewrites owner names of RRs that exactly match currentName
// back to originalName. It is called after zone wildcard rewrites.
//
// Limitation: only exact owner name matches are restored. Intermediate CNAME
// targets in a wildcard chain (e.g., *.example.com → <random>.cdn.net) are
// not matched, so their names remain in rewritten form. This is acceptable
// because wildcard-rewritten responses rarely contain CNAME chains, and the
// restored original name is sufficient for client-side validation.
func (m *Response) restoreDomain(msg *dns.Msg, currentName, originalName string) {
	if msg == nil || dns.EqualName(currentName, originalName) {
		return
	}
	for _, rr := range msg.Answer {
		if rr != nil && dns.EqualName(rr.Header().Name, currentName) {
			rr.Header().Name = originalName
		}
	}
	for _, rr := range msg.Ns {
		if rr != nil && dns.EqualName(rr.Header().Name, currentName) {
			rr.Header().Name = originalName
		}
	}
	for _, rr := range msg.Extra {
		if rr != nil && dns.EqualName(rr.Header().Name, currentName) {
			rr.Header().Name = originalName
		}
	}
}
