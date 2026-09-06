package config

import (
	"fmt"
	"net"

	zdnsutil "zjdns/internal/dnsutil"
)

// ACLSettings is the IP-based access control list applied at the query
// pipeline entry.  Entries are CIDR blocks or bare IPs, matched against the
// real client address (socket peer, or the proxy-header address when the
// peer is in trusted_proxies).  Semantics: a deny match always refuses; a
// non-empty allow list switches to default-deny for unmatched clients.
// Empty ACL (both lists empty) disables the middleware entirely.
type ACLSettings struct {
	Allow []string `json:"allow,omitzero"`
	Deny  []string `json:"deny,omitzero"`
}

// IsEmpty reports whether no ACL rule is configured — the middleware is not
// wired into the chain, so the hot path pays nothing.
func (a *ACLSettings) IsEmpty() bool {
	return len(a.Allow) == 0 && len(a.Deny) == 0
}

// Parsed parses both lists into networks.  Load-time validation guarantees
// success for file-loaded configs; the error still flows for direct
// constructors.
func (a *ACLSettings) Parsed() (allow, deny []*net.IPNet, err error) {
	allow, err = zdnsutil.ParseIPNets(a.Allow)
	if err != nil {
		return nil, nil, fmt.Errorf("server.acl.allow: %w", err)
	}
	deny, err = zdnsutil.ParseIPNets(a.Deny)
	if err != nil {
		return nil, nil, fmt.Errorf("server.acl.deny: %w", err)
	}
	return allow, deny, nil
}
