// Package dnsutil provides DNS utility functions including address binding.
package dnsutil

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"zjdns/internal/log"
)

// ResolveBindAddrs returns the list of addresses to bind for the given network
// and port. It tries the wildcard address first; if another process already
// occupies it (EADDRINUSE), it falls back to per-interface binding, skipping
// any addresses that are already in use.
func ResolveBindAddrs(network, port string) ([]string, error) {
	wildcard := ":" + port
	if err := tryBind(network, wildcard); err == nil {
		return []string{wildcard}, nil
	} else if !errors.Is(err, syscall.EADDRINUSE) {
		return nil, fmt.Errorf("%s listen on %s: %w", network, wildcard, err)
	}

	log.Warnf("SERVER: wildcard %s is occupied, falling back to per-interface binding", wildcard)

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
			if !ok || ipNet.IP.IsLoopback() {
				continue
			}
			addr := net.JoinHostPort(ipNet.IP.String(), port)
			if err := tryBind(network, addr); err != nil {
				if errors.Is(err, syscall.EADDRINUSE) {
					log.Warnf("SERVER: skipping occupied %s address %s", network, addr)
					continue
				}
				return nil, fmt.Errorf("%s listen on %s: %w", network, addr, err)
			}
			addrs = append(addrs, addr)
		}
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("no available %s addresses for port %s", network, port)
	}
	return addrs, nil
}

// tryBind attempts to bind a listener of the given network to addr and
// immediately closes it. Returns nil on success, the bind error otherwise.
func tryBind(network, addr string) error {
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
