package config

import (
	"fmt"
	"net"
	"slices"
	"strings"

	zdnsutil "zjdns/internal/dnsutil"
)

// ACLSettings is the IP-based access control list applied at the query
// pipeline entry.  Each entry is a CIDR block, a bare IP, or a client name
// (the path/SNI credential; any non-IP string that parses as one).  Matching
// runs against the real client address and the presented client name;
// semantics: an allow match always wins (exception model, Pi-hole/AdGuard
// style), then a deny match refuses, and a non-empty allow list switches to
// default-deny.  Empty ACL (both lists empty) disables the middleware.
type ACLSettings struct {
	Allow []string `json:"allow,omitzero"`
	Deny  []string `json:"deny,omitzero"`
}

// ACLList is one parsed ACL list: CIDR/IP networks plus client names.
type ACLList struct {
	Nets  []*net.IPNet
	Names []string
}

// IsEmpty reports whether no ACL rule is configured — the middleware is not
// wired into the chain, so the hot path pays nothing.
func (a *ACLSettings) IsEmpty() bool {
	return len(a.Allow) == 0 && len(a.Deny) == 0
}

// Parsed parses both lists.  Load-time validation guarantees success for
// file-loaded configs; the error still flows for direct constructors.
func (a *ACLSettings) Parsed() (allow, deny ACLList, err error) {
	allow, err = parseACLList("allow", a.Allow)
	if err != nil {
		return ACLList{}, ACLList{}, err
	}
	deny, err = parseACLList("deny", a.Deny)
	if err != nil {
		return ACLList{}, ACLList{}, err
	}
	return allow, deny, nil
}

// parseACLList resolves each entry to a network or a client name.  The
// strict name charset ([a-z0-9-], no dots/slashes) means a mistyped CIDR
// fails all three branches and errors instead of silently becoming a name.
func parseACLList(field string, entries []string) (ACLList, error) {
	list := ACLList{Nets: make([]*net.IPNet, 0, len(entries)), Names: make([]string, 0, len(entries))}
	for i, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(entry); err == nil {
			list.Nets = append(list.Nets, network)
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			list.Nets = append(list.Nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		if name := zdnsutil.ParseClientName(entry); name != "" {
			list.Names = append(list.Names, name)
			continue
		}
		return ACLList{}, fmt.Errorf("server.acl.%s[%d]: invalid CIDR, IP, or client name %q", field, i, entry)
	}
	return list, nil
}

// OverlapEntries lists allow entries that override a deny entry under the
// allow-wins semantics: names present in both lists and nested CIDR pairs
// (CIDR blocks nest or are disjoint, so mutual network-address containment
// is exact).  Returned for the startup warning — an intentional exception is
// fine, but a silently neutralised deny list should be visible.
func OverlapEntries(allow, deny ACLList) []string {
	var overlaps []string
	for _, name := range allow.Names {
		if slices.Contains(deny.Names, name) {
			overlaps = append(overlaps, name)
		}
	}
	for _, a := range allow.Nets {
		for _, d := range deny.Nets {
			if a.Contains(d.IP) || d.Contains(a.IP) {
				overlaps = append(overlaps, a.String()+" ⊃ "+d.String())
			}
		}
	}
	return overlaps
}
