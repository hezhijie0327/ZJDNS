package middleware

import (
	"context"
	"net"
	"slices"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
)

// ACL enforces the access control list (server.acl) on the client identity
// in qctx — the real client address (socket peer, or the proxy-header
// address when the peer is a trusted proxy) and the presented client-name
// credential (DoH path segment or TLS/QUIC SNI).  Entries are CIDR blocks,
// bare IPs, or client names.
//
// Semantics (allow-wins, the exception model Pi-hole/AdGuard use): an allow
// match — by name or IP — always grants; deny then refuses on a match; a
// non-empty allow list switches to default-deny.  The explicit grant is the
// point: "alice" in allow lifts her out of a denied IP range (her name is
// the credential she presents deliberately; the range block holds for the
// anonymous traffic around her).  config.OverlapEntries warns at startup
// when an allow entry silently overrides a deny entry.
//
// Denied queries get REFUSED annotated with EDE 18 (Prohibited) — RFC 8914
// §4.19 reserves exactly this code for "unauthorized client" refusals.  The
// outcome is journaled as Result "acl" so Stats distinguishes policy
// refusals from upstream REFUSED answers.
//
// Positioned between Validation and Zone: policy refusals outrank zone
// rules and never reach the cache layers (no lookup, no stale refresh).
type ACL struct {
	allow config.ACLList
	deny  config.ACLList
}

// NewACL builds the middleware from the pre-parsed lists
// (config.ACLSettings.Parsed).
func NewACL(allow, deny config.ACLList) *ACL {
	return &ACL{allow: allow, deny: deny}
}

// Wrap implements Wrapper.
func (m *ACL) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		if m.permits(qctx.ClientIP, qctx.ClientName) {
			return next.ServeDNS(ctx, qctx)
		}
		msg := handler.BuildResponseMsg(qctx.Req)
		msg.Rcode = dns.RcodeRefused
		qctx.Res = msg
		qctx.Result = "acl"
		qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorProhibited}
		if log.IsDebug() {
			log.Debugf("SECURITY: ACL refused %s query for %s from %s (name=%q)",
				dns.TypeToString[qctx.Qtype], qctx.Qname, qctx.ClientIP, qctx.ClientName)
		}
		return nil
	})
}

// permits reports whether the identity passes: allow match (name or IP)
// first — the explicit grant overrides deny; then deny match refuses;
// otherwise the default, which is deny whenever any allow entry exists
// (allowlist mode).  A nil IP never matches a network; an empty name never
// matches a name entry.
func (m *ACL) permits(ip net.IP, name string) bool {
	if name != "" && slices.Contains(m.allow.Names, name) {
		return true
	}
	if ip != nil && ipInNetworks(ip, m.allow.Nets) {
		return true
	}
	if name != "" && slices.Contains(m.deny.Names, name) {
		return false
	}
	if ip != nil && ipInNetworks(ip, m.deny.Nets) {
		return false
	}
	return len(m.allow.Nets) == 0 && len(m.allow.Names) == 0
}

func ipInNetworks(ip net.IP, networks []*net.IPNet) bool {
	for _, n := range networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
