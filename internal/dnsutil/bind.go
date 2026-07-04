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
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerate interfaces: %w", err)
	}

	var addrs []string
	for _, iface := range ifaces {
		ips, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, ip := range ips {
			ipNet, ok := ip.(*net.IPNet)
			if !ok {
				continue
			}
			addr := net.JoinHostPort(ipNet.IP.String(), port)
			if err := TryBind(network, addr); err != nil {
				log.Warnf("SERVER: skipping %s address %s: %v", network, addr, err)
				continue
			}
			addrs = append(addrs, addr)
		}
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("no available %s addresses for port %s", network, port)
	}
	return addrs, nil
}

// TryBind attempts to bind a listener of the given network to addr and
// immediately closes it. Returns nil on success, the bind error otherwise.
func TryBind(network, addr string) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
		l, err := net.Listen(network, addr)
		if err != nil {
			return err
		}
		_ = l.Close()
		return nil
	default:
		pc, err := net.ListenPacket(network, addr)
		if err != nil {
			return err
		}
		_ = pc.Close()
		return nil
	}
}
