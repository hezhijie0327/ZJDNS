package middleware

import (
	"context"
	"net"
	"zjdns/internal/log"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
)

// ACL enforces the IP-based access control list (server.acl) on the real
// client address in qctx.ClientIP — the socket peer, or the proxy-header
// address when the peer is a trusted proxy.  Semantics: a deny match always
// refuses; a non-empty allow list switches to default-deny.  A nil client IP
// (no address available) passes only when no allow list is configured.
//
// Denied queries get REFUSED annotated with EDE 18 (Prohibited) — RFC 8914
// §4.19 reserves exactly this code for "unauthorized client" refusals
// (queries from outside the network, blocklisted IPs, local policy).  The
// outcome is journaled as Result "acl" so Stats distinguishes policy
// refusals from upstream REFUSED answers.
//
// Positioned between Validation and Zone: policy refusals outrank zone
// rules and never reach the cache layers (no lookup, no stale refresh).
type ACL struct {
	allow []*net.IPNet
	deny  []*net.IPNet
}

// NewACL builds the middleware from pre-parsed networks
// (config.ACLSettings.Parsed).
func NewACL(allow, deny []*net.IPNet) *ACL {
	return &ACL{allow: allow, deny: deny}
}

// Wrap implements Wrapper.
func (m *ACL) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		if m.permits(qctx.ClientIP) {
			return next.ServeDNS(ctx, qctx)
		}
		msg := handler.BuildResponseMsg(qctx.Req)
		msg.Rcode = dns.RcodeRefused
		qctx.Res = msg
		qctx.Result = "acl"
		qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorProhibited}
		if log.IsDebug() {
			log.Debugf("SECURITY: ACL refused %s query for %s from %s",
				dns.TypeToString[qctx.Qtype], qctx.Qname, qctx.ClientIP)
		}
		return nil
	})
}

// permits reports whether ip passes the list: deny is checked first (it
// wins over allow), then the allowlist gate.  In allowlist mode a nil IP is
// refused — an unverifiable client is not trusted.
func (m *ACL) permits(ip net.IP) bool {
	if ip != nil {
		for _, n := range m.deny {
			if n.Contains(ip) {
				return false
			}
		}
	}
	if len(m.allow) == 0 {
		return true
	}
	if ip == nil {
		return false
	}
	for _, n := range m.allow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
