// Package dnsutil provides DNS utility functions including address binding.
package dnsutil

import (
	"fmt"
	"net"
	"zjdns/internal/log"
)

// ResolveBindAddrs returns the list of addresses to bind for the given network
// and port. It enumerates all non-link-local unicast IPs and returns each one
// as a host:port string, skipping any that are already occupied (EADDRINUSE)
// or otherwise unavailable.
func ResolveBindAddrs(network, port string) ([]string, error) {
	if port == "" || port == "0" {
		return nil, fmt.Errorf("bind port must be a fixed port, got %q", port)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerate interfaces: %w", err)
	}

	var addrs []string
	var skipped []string
	seen := make(map[string]struct{})
	for _, iface := range ifaces {
		ips, err := iface.Addrs()
		if err != nil {
			log.Warnf("SERVER: cannot enumerate addresses of interface %s: %v", iface.Name, err)
			continue
		}
		for _, ip := range ips {
			var ipAddr net.IP
			switch a := ip.(type) {
			case *net.IPNet:
				ipAddr = a.IP
			case *net.IPAddr:
				ipAddr = a.IP
			default:
				continue
			}
			if ipAddr == nil || ipAddr.IsLinkLocalUnicast() {
				continue
			}
			// The same IP can appear on multiple interfaces (lo, veth,
			// bridge) — binding it twice would fail on the second attempt.
			if _, dup := seen[ipAddr.String()]; dup {
				continue
			}
			seen[ipAddr.String()] = struct{}{}
			addr := net.JoinHostPort(ipAddr.String(), port)
			if err := TryBind(network, addr); err != nil {
				skipped = append(skipped, addr)
				continue
			}
			addrs = append(addrs, addr)
		}
	}

	if len(skipped) > 0 {
		log.Warnf("SERVER: skipping %d %s address(es): %v", len(skipped), network, skipped)
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("no available %s addresses for port %s", network, port)
	}
	return addrs, nil
}

// TryBind attempts to bind a listener of the given network to addr and
// immediately closes it. Returns nil on success, the bind error otherwise.
//
// NOTE: This function is subject to TOCTOU (time-of-check-time-of-use) races
// — the address may become unavailable between the check and the actual bind.
// Callers should treat TryBind as a best-effort preflight and handle bind
// failures at the actual listen step.
func TryBind(network, addr string) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
		l, err := net.Listen(network, addr)
		if err != nil {
			return err
		}
		_ = l.Close() // _ = error: best-effort close during startup preflight
		return nil
	default:
		pc, err := net.ListenPacket(network, addr)
		if err != nil {
			return err
		}
		_ = pc.Close() // _ = error: best-effort close during startup preflight
		return nil
	}
}
