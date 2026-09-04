package middleware

import (
	"context"
	"encoding/binary"
	"net"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
)

// Response is the outermost middleware.  It applies EDNS options
// (ECS, Cookie, EDE, padding, TCP keepalive) to the final response.
// It always runs — for short-circuited and freshly resolved responses alike.
type Response struct {
	edns handler.EDNSHandler
}

// ednsState is the precomputed EDNS decision state for one response, computed
// once per response so the pre-packed fast path and finalizeResponse share it.
type ednsState struct {
	ecsOpt         *edns.ECSOption
	cookieStr      string
	clientWantsPad bool
	shouldAddEDNS  bool
}

var fallbackClientIP = net.ParseIP(config.FallbackClientIP) // pre-parsed to avoid per-query allocation

// Wrap implements Wrapper.
func (m *Response) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		err := next.ServeDNS(ctx, qctx)

		if qctx.Res == nil {
			return err
		}

		st := m.ednsStateFor(qctx)

		if qctx.Res.Data != nil {
			// Pre-packed response: when no EDNS option is needed, serve the
			// wire directly — only the client's message ID must be patched in
			// (bytes 0..1; the pre-packed wire carries the ID from cache
			// Set() time).  In debug mode the RESULT log reads RR fields, so
			// unpack for accurate counts.
			// DO=1 clients always take the unpack path (shouldAddEDNS includes
			// ClientRequestedDNSSEC — the response OPT must echo DO), so this
			// gate only runs for DO=0 clients: the wire must be free of DNSSEC
			// proofs (upstream queries always carry DO=1, so the raw cached
			// wire may contain RRSIG/NSEC/NSEC3/DNSKEY/DS) — otherwise the
			// unpack+filter path below runs.
			if !st.shouldAddEDNS && !log.IsDebug() &&
				!qctx.ResHasDNSSEC {
				binary.BigEndian.PutUint16(qctx.Res.Data[0:2], qctx.Req.ID)
				// RFC 1035 §4.1.1: RD is copied from the query — the cached
				// wire carries RD from cache Set() time.
				if qctx.Req.RecursionDesired {
					qctx.Res.Data[2] |= 0x01
				} else {
					qctx.Res.Data[2] &^= 0x01
				}
				return err
			}
			// EDNS options are needed — unpack the pre-built wire so the
			// EDNS + Pack pipeline below can modify the message.  TTLs were
			// already adjusted by buildFromPrePacked.
			if err := qctx.Res.Unpack(); err != nil {
				if log.IsDebug() {
					log.Debugf("RESPONSE: unpack pre-packed response: %v", err)
				}
				qctx.Res.Rcode = dns.RcodeServerFailure
				return err
			}
			qctx.Res.ID = qctx.Req.ID
			qctx.Res.RecursionDesired = qctx.Req.RecursionDesired
			// Filter DNSSEC proofs for DO=0 clients, mirroring the miss path
			// (ProcessRecords with dnssecOK).
			if !qctx.ClientRequestedDNSSEC {
				qctx.Res.Answer = cache.ProcessRecords(qctx.Res.Answer, 0, false, false)
				qctx.Res.Ns = cache.ProcessRecords(qctx.Res.Ns, 0, false, false)
				qctx.Res.Extra = cache.ProcessRecords(qctx.Res.Extra, 0, false, false)
			}
			qctx.Res.Data = nil
		}

		m.finalizeResponse(qctx, st)
		return err
	})
}

// ednsStateFor computes the EDNS decision state for a response.  Shared by the
// pre-packed fast path (deciding whether the wire can be served as-is) and
// finalizeResponse (applying the options) so the parse work runs once.
func (m *Response) ednsStateFor(qctx *handler.QueryContext) ednsState {
	// Parse ECS if EDNS didn't run (early short-circuit).  When EDNS already
	// ran, ECSOpt == nil definitively means "no ECS" — the fallback re-parse
	// of req.Pseudo (and the padding re-scan) is redundant work per response.
	ecsOpt := qctx.ECSOpt
	if ecsOpt == nil && !qctx.EDNSParsed && m.edns != nil {
		ecsOpt = m.edns.ParseFromDNS(qctx.Req)
		if ecsOpt == nil {
			ecsOpt = m.edns.ECSForQType(qctx.Qtype)
		}
	}

	clientWantsPadding := qctx.ClientWantsPadding
	if !clientWantsPadding && !qctx.EDNSParsed {
		clientWantsPadding = edns.HasPaddingOption(qctx.Req)
	}

	// CookieStr was computed during EDNS validation (single HMAC per query);
	// the fallback compute only serves early short-circuits before EDNS.
	cookieStr := qctx.CookieStr
	if cookieStr == "" && !qctx.EDNSParsed {
		cookieStr = m.generateCookieStr(qctx.CookieOpt, qctx.ClientIP)
	}

	// qctx.IsSecure is deliberately NOT part of shouldAddEDNS — including it
	// forced every TLS-family listener (DoT/DoQ/DoH/DoH3/DTLS/TLCP/DTLCP)
	// onto the unpack+re-Pack path, silently disabling the pre-packed
	// direct-wire fast path on 7 of 8 protocol families (R3-M1).  Padding —
	// the only consumer of IsSecure — is added exactly when
	// (isSecure && clientWantsPadding): legacy no-EDNS clients on secure
	// transports get padded by default (HasPaddingOption returns true for
	// them), EDNS clients that send no PADDING option opt out explicitly and
	// can take the fast path, and plain transports never pad.
	return ednsState{
		ecsOpt:         ecsOpt,
		cookieStr:      cookieStr,
		clientWantsPad: clientWantsPadding,
		shouldAddEDNS: ecsOpt != nil || qctx.ClientRequestedDNSSEC || cookieStr != "" ||
			qctx.EDE != nil || (qctx.IsSecure && clientWantsPadding) ||
			len(qctx.Req.Pseudo) > 0,
	}
}

func (m *Response) finalizeResponse(qctx *handler.QueryContext, st ednsState) {
	msg := qctx.Res
	req := qctx.Req
	if req == nil {
		// Defensive: the chain guarantees a request, but the Response
		// middleware must not crash on a nil req (the EDNS fallback
		// dereferences it).
		return
	}

	if st.ecsOpt != nil {
		if log.IsDebug() {
			log.Debugf("EDNS: response ECS: family=%d addr=%s/%d scope=%d fromClient=%t",
				st.ecsOpt.Family, st.ecsOpt.Address, st.ecsOpt.SourcePrefix, st.ecsOpt.ScopePrefix, qctx.ECSOpt != nil)
		}
	}

	if st.shouldAddEDNS && m.edns != nil && !msgHasEDNSOptions(msg) {
		// Skip when the response already carries EDNS options: a BADCOOKIE
		// response built by the EDNS middleware applied its own
		// SUBNET/COOKIE/padding, and re-applying would duplicate options
		// inside a single OPT (RFC 7873: at most one COOKIE per message).
		m.edns.ApplyToMessage(msg, st.ecsOpt, qctx.IsSecure, st.cookieStr, qctx.EDE, false, st.clientWantsPad, 0)
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
		if log.IsDebug() {
			log.Debugf("EDNS: invalid client cookie length %d (expected %d)", len(cookieOpt.ClientCookie), edns.DefaultCookieClientLen)
		}
		return ""
	}

	var serverCookie []byte
	if len(cookieOpt.ServerCookie) == edns.DefaultCookieServerLen {
		status := m.edns.IsServerCookieValid(clientIP, cookieOpt.ClientCookie, cookieOpt.ServerCookie)
		if status == edns.CookieValid || status == edns.CookieValidRenew {
			serverCookie = cookieOpt.ServerCookie
		} else {
			if log.IsDebug() {
				log.Debugf("EDNS: server cookie status=%d for %s, renewing", status, clientIP)
			}
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
