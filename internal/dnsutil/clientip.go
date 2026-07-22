package dnsutil

import "net"

// ClientIPFromAddr extracts the client IP address from a net.Addr, handling
// TCP, UDP, and other address types. Returns nil for unknown or nil addresses.
func ClientIPFromAddr(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return nil
		}
		return net.ParseIP(host)
	}
}
