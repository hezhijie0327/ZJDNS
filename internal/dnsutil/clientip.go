package dnsutil

import "net"

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
