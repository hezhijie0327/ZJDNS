package dnsutil

import (
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
)

// Proxy client-IP headers, in canonical MIME form (http.Header.Get/Set
// canonicalize anyway — a canonical literal skips that work): the common
// single-value conventions (Cloudflare, CDN enterprise, nginx) plus the de
// facto standard append-chain.
const (
	HeaderCFConnectingIP = "Cf-Connecting-Ip"
	HeaderTrueClientIP   = "True-Client-Ip"
	HeaderXRealIP        = "X-Real-Ip"
	HeaderXForwardedFor  = "X-Forwarded-For"
)

// singleValueProxyHeaders lists the overwrite-style client-IP headers checked
// in priority order before the X-Forwarded-For append-chain.  A fixed array —
// ranging over it allocates nothing on the per-request path.
var singleValueProxyHeaders = [3]string{HeaderCFConnectingIP, HeaderTrueClientIP, HeaderXRealIP}

// ClientIPFromAddr extracts the client IP address from a net.Addr, handling
// TCP, UDP, IP, and other address types. Returns nil for unknown or nil
// addresses.
func ClientIPFromAddr(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		if a == nil { // typed nil interface — dereferencing would panic
			return nil
		}
		return a.IP
	case *net.UDPAddr:
		if a == nil {
			return nil
		}
		return a.IP
	case *net.IPAddr:
		if a == nil {
			return nil
		}
		return a.IP
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return nil
		}
		return net.ParseIP(host)
	}
}

// ParseIPNets parses network entries (CIDR blocks or bare IPs) into
// networks.  A bare IPv4 becomes /32, a bare IPv6 /128.  Empty entries
// are skipped.  Shared by trusted_proxies and ACL list parsing.
func ParseIPNets(entries []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(entries))
	for i, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(entry); err == nil {
			nets = append(nets, network)
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		return nil, fmt.Errorf("entry %d: invalid CIDR or IP %q", i, entry)
	}
	return nets, nil
}

// ClientIPFromRequest resolves the client IP for an HTTP-based DNS request
// (DoH, DoH3, HTTPTLCP): it parses the request's remote address, then lets
// ClientIPFromProxyHeaders take over — proxy headers win when the socket peer
// is trusted, the socket address is the fallback (and the gate), so the
// precedence lives in one place.
func ClientIPFromRequest(remoteAddr string, trusted []*net.IPNet, header http.Header) net.IP {
	var remoteIP net.IP
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteIP = net.ParseIP(host)
	}
	return ClientIPFromProxyHeaders(remoteIP, trusted, header)
}

// ClientIPFromProxyHeaders resolves the real client IP for an HTTP-based DNS
// request (DoH, DoH3, HTTPTLCP) arriving through a reverse proxy.  Headers are
// only honoured when the direct peer (remoteIP, from the socket) is listed in
// trusted — otherwise any client could forge its IP and bypass the DNS-cookie
// keying, zone CIDR rules, and the CHAOS loopback guard.  Header priority:
//
//  1. CF-Connecting-IP — Cloudflare's own; it overwrites anything the
//     client sent.
//  2. True-Client-IP — Cloudflare Enterprise / Akamai convention.
//  3. X-Real-IP — nginx convention (proxy_set_header X-Real-IP).
//  4. X-Forwarded-For — walked right-to-left, skipping trusted proxies;
//     the first untrusted address is the client.  Proxies append the peer
//     they saw, so client-injected fakes sit on the (untrusted) left.
//
// The first three are single-value headers the trusted proxy overwrites, so
// each outranks the append-chain; parseHeaderIP rejects comma lists in them.
// A malformed X-Forwarded-For entry stops the walk — nothing left of it is
// trustworthy.  When no header yields an address, remoteIP is returned
// unchanged.
func ClientIPFromProxyHeaders(remoteIP net.IP, trusted []*net.IPNet, header http.Header) net.IP {
	if len(trusted) == 0 || remoteIP == nil || !ipInNetworks(remoteIP, trusted) {
		return remoteIP
	}
	for _, name := range &singleValueProxyHeaders {
		if ip := parseHeaderIP(header.Get(name)); ip != nil {
			return ip
		}
	}
	if xff := header.Get(HeaderXForwardedFor); xff != "" {
		entries := strings.Split(xff, ",")
		for _, entrie := range slices.Backward(entries) {
			ip := parseHeaderIP(entrie)
			if ip == nil {
				break
			}
			if !ipInNetworks(ip, trusted) {
				return ip
			}
		}
	}
	return remoteIP
}

// parseHeaderIP parses one header address: bare IP, or IP:port (bracketed for
// IPv6).  Comma-separated lists are rejected — only single values are valid.
func parseHeaderIP(value string) net.IP {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, ",") {
		return nil
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return net.ParseIP(host)
	}
	return nil
}

func ipInNetworks(ip net.IP, networks []*net.IPNet) bool {
	for _, n := range networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
