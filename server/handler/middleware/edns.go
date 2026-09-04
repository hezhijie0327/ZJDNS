package middleware

import (
	"context"
	"net"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
)

// EDNS parses EDNS options (ECS, Cookie, DNSSEC OK) from the
// incoming request and validates the DNS Cookie per RFC 7873.  Invalid
// cookies receive a BADCOOKIE response.
type EDNS struct {
	edns handler.EDNSHandler
}

// Wrap implements Wrapper.
func (m *EDNS) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		req := qctx.Req

		// (MsgOptionUnpackQuestion) for routing.  When the OPT record is
		// already present in Pseudo (full unpack already done), skip the
		// redundant second parse to avoid per-query CPU and allocation cost.
		// Otherwise force a full unpack so that EDNS options (ECS, Cookie,
		// etc.) are extracted into req.Pseudo.  If this pass fails, the
		// message is malformed — reject it rather than silently operating on
		// a partially-parsed message.
		//
		// Data == nil means the caller built the request from fields
		// (direct ServeDNS calls, benchmarks) — there is no wire to unpack
		// and Pseudo cannot exist; treat it as a no-EDNS request instead of
		// FORMERRing on a nil Data (chain-reorder regression: EDNS now runs
		// before the Zone short-circuit, so this path executes for every
		// zone-matched query).
		if len(req.Pseudo) == 0 && req.Data != nil {
			req.Options = 0
			if err := req.Unpack(); err != nil {
				log.Debugf("EDNS: full unpack failed: %v", err)
				msg := handler.BuildResponseMsg(req)
				msg.Rcode = dns.RcodeFormatError
				qctx.Res = msg
				return nil
			}
		}

		// RFC 6891 §6.1.3 MUST: a request carrying an unsupported EDNS
		// version is answered with RCODE=BADVERS and an OPT that carries the
		// version this responder supports (0). Unpack folds the OPT version
		// into req.Version. The PADDING option is a zero-byte carrier: it
		// forces OPT generation at pack time, where Rcode=16 (extended
		// rcode) and UDPSize are folded into the OPT.
		if req.Version != 0 {
			log.Debugf("EDNS: unsupported EDNS version %d from %s, returning BADVERS", req.Version, qctx.ClientIP)
			msg := handler.BuildResponseMsg(req)
			msg.Rcode = dns.RcodeBadVers
			msg.UDPSize = pool.UDPBufferSize
			msg.Pseudo = append(msg.Pseudo, &dns.PADDING{})
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
			// RFC 7873 §5.2.2: a malformed client cookie is rejected with
			// FORMERR, not silently treated as absent.
			log.Debugf("EDNS: malformed client cookie from %s", qctx.ClientIP)
			msg := handler.BuildResponseMsg(req)
			msg.Rcode = dns.RcodeFormatError
			qctx.Res = msg
			return nil
		}
		qctx.ClientWantsPadding = edns.HasPaddingOption(req)

		cookieOpt := qctx.CookieOpt

		// RFC 7873 §5.2.2: valid COOKIE option lengths are 8 and 16-40.
		// Lengths 9-15 and >40 are malformed → FORMERR. Within 16-40, a
		// server cookie ≠ 16 bytes is an invalid server cookie → BADCOOKIE
		// (§5.2.4).
		if cookieOpt != nil && len(cookieOpt.ServerCookie) > 0 {
			total := edns.DefaultCookieClientLen + len(cookieOpt.ServerCookie)
			if total < edns.DefaultCookieServerLen || total > edns.MaxCookieLen {
				log.Debugf("EDNS: malformed cookie option length %d from %s, returning FORMERR", total, qctx.ClientIP)
				msg := handler.BuildResponseMsg(req)
				msg.Rcode = dns.RcodeFormatError
				qctx.Res = msg
				return nil
			}
			if len(cookieOpt.ServerCookie) != edns.DefaultCookieServerLen {
				log.Debugf("EDNS: bad server cookie length %d (expected %d) from %s, returning BADCOOKIE", len(cookieOpt.ServerCookie), edns.DefaultCookieServerLen, qctx.ClientIP)
				qctx.Res = m.buildBadCookieResponse(req, qctx.ClientIP, cookieOpt, qctx.ECSOpt)
				return nil
			}
		}

		// RFC 7873: Full server cookie (16 bytes) → cryptographic validation.
		var cookieStatus edns.CookieValStatus
		if cookieOpt != nil && len(cookieOpt.ServerCookie) == edns.DefaultCookieServerLen {
			cookieStatus = m.edns.IsServerCookieValid(qctx.ClientIP, cookieOpt.ClientCookie, cookieOpt.ServerCookie)
			if cookieStatus == edns.CookieExpired || cookieStatus == edns.CookieFuture || cookieStatus == edns.CookieInvalid {
				log.Debugf("EDNS: bad server cookie (status=%d) from %s, returning BADCOOKIE", cookieStatus, qctx.ClientIP)
				qctx.Res = m.buildBadCookieResponse(req, qctx.ClientIP, cookieOpt, qctx.ECSOpt)
				return nil
			}
		}

		// Compute the response COOKIE string once here and cache it in
		// qctx.CookieStr — the Response middleware must never re-run the
		// server-cookie HMAC per response.
		qctx.CookieStr = m.cookieResponseStr(cookieOpt, qctx.ClientIP, cookieStatus)

		// Apply default ECS if no ECS was sent.
		if qctx.ECSOpt == nil && len(req.Question) > 0 {
			qctx.ECSOpt = m.edns.ECSForQType(dns.RRToType(req.Question[0]))
			if qctx.ECSOpt != nil {
				log.Debugf("EDNS: using default ECS: family=%d addr=%s/%d",
					qctx.ECSOpt.Family, qctx.ECSOpt.Address, qctx.ECSOpt.SourcePrefix)
			}
		}

		qctx.EDNSParsed = true

		return next.ServeDNS(ctx, qctx)
	})
}

func (m *EDNS) buildBadCookieResponse(req *dns.Msg, clientIP net.IP, cookieOpt *edns.CookieOption, ecsOpt *edns.ECSOption) *dns.Msg {
	msg := handler.BuildResponseMsg(req)
	msg.Rcode = dns.RcodeBadCookie
	if cookieOpt == nil {
		// RFC 7873 §5.2.2: nothing to echo — FORMERR. Kept separate from the
		// length check: logging len(cookieOpt.ClientCookie) on the nil path
		// would dereference a nil pointer.
		log.Debugf("EDNS: missing client cookie from %s, returning FORMERR", clientIP)
		msg.Rcode = dns.RcodeFormatError
		return msg
	}
	if len(cookieOpt.ClientCookie) != edns.DefaultCookieClientLen {
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

// cookieResponseStr computes the COOKIE string for the response ("" when the
// option is absent or the client cookie malformed).  Called once per query
// during EDNS validation; the result is cached in qctx.CookieStr so the
// Response middleware never re-runs the HMAC.  validatedStatus carries the
// verification result for a full 16-byte server cookie (CookieValStatus zero
// value = not verified here, i.e. client-only cookie).
func (m *EDNS) cookieResponseStr(cookieOpt *edns.CookieOption, clientIP net.IP, validatedStatus edns.CookieValStatus) string {
	if cookieOpt == nil {
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
		if validatedStatus == edns.CookieValid || validatedStatus == edns.CookieValidRenew {
			serverCookie = cookieOpt.ServerCookie
		} else {
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
