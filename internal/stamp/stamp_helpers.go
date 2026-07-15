// Package stamp implements DNS Stamp (sdns://) parsing for all major DNS
// protocols as defined by the DNSCrypt project's DNS Stamp specification.
//
// Supported protocol IDs:
//
//	0x00 — Plain DNS (Do53)
//	0x01 — DNSCrypt v2
//	0x02 — DNS-over-HTTPS (DoH)
//	0x03 — DNS-over-TLS (DoT)
//	0x04 — DNS-over-QUIC (DoQ)
//	0x05 — Oblivious DoH Target
//	0x81 — DNSCrypt Relay
//	0x85 — Oblivious DoH Relay
//
// The package is foundation-level: zero zjdns imports, standard library only.
package stamp

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

func stripDefaultPort(s string, defaultPort int) string {
	return strings.TrimSuffix(s, ":"+strconv.Itoa(defaultPort))
}

func encodeAddrAndHostname(addr, hostname string, defaultPort int) (encodedAddr, encodedHost string) {
	if host, port := splitOptionalPort(addr); port != "" {
		addr = host
		if hostname != "" {
			if _, hostPort := splitOptionalPort(hostname); hostPort == "" {
				hostname = hostname + ":" + port
			}
		}
	}
	return addr, stripDefaultPort(hostname, defaultPort)
}

func appendHashes(bin []uint8, hashes [][]uint8) []uint8 {
	if len(hashes) == 0 {
		return append(bin, 0x00)
	}
	last := len(hashes) - 1
	for i, hash := range hashes {
		vlen := len(hash)
		if i < last {
			vlen |= 0x80
		}
		bin = append(bin, uint8(vlen)) //nolint:gosec // G115: VLP length ≤ 127
		bin = append(bin, hash...)
	}
	return bin
}

func appendBootstrapIPs(bin []uint8, bootstrapIPs []string) []uint8 {
	last := len(bootstrapIPs) - 1
	for i, bootstrapIP := range bootstrapIPs {
		vlen := len(bootstrapIP)
		if i < last {
			vlen |= 0x80
		}
		bin = append(bin, uint8(vlen)) //nolint:gosec // G115: VLP length ≤ 127
		bin = append(bin, []uint8(bootstrapIP)...)
	}
	return bin
}

// readVLP reads a Variable Length Prefixed sequence from bin at pos.
// The high bit (0x80) of each length byte indicates another element follows.
// Returns the decoded byte slices, the new position, and any error.
func readVLP(bin []byte, pos, binLen int) (elements [][]byte, newPos int, err error) {
	for {
		if pos >= binLen {
			return nil, pos, ErrTruncatedLength
		}
		vlen := int(bin[pos])
		length := vlen & ^0x80 // clear continuation bit
		if 1+length > binLen-pos {
			return nil, pos, ErrTruncatedPayload
		}
		pos++
		if length > 0 {
			elem := make([]byte, length)
			copy(elem, bin[pos:pos+length])
			elements = append(elements, elem)
		}
		pos += length
		if vlen&0x80 != 0x80 {
			break
		}
	}
	return elements, pos, nil
}

func validatePort(port string) error {
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return ErrInvalidPort
	}
	return nil
}

func validateAddrAndHostname(addr, hostname string) error {
	if addr != "" {
		ip := addr
		if strings.HasPrefix(ip, "[") && strings.HasSuffix(ip, "]") {
			ip = ip[1 : len(ip)-1]
		} else if strings.ContainsRune(ip, ':') {
			return errors.New("stamp: invalid IP address")
		}
		if net.ParseIP(ip) == nil {
			return ErrInvalidIP
		}
	}
	if _, err := stripAndValidatePort(hostname); err != nil {
		return err
	}
	return nil
}

func stripAndValidatePort(s string) (string, error) {
	host, port := splitOptionalPort(s)
	if port == "" {
		if strings.HasSuffix(s, ":") {
			return "", errors.New("stamp: empty port")
		}
		return s, nil
	}
	if err := validatePort(port); err != nil {
		return "", errors.New("stamp: port range")
	}
	return host, nil
}

func splitOptionalPort(s string) (host, port string) {
	colIndex := strings.LastIndex(s, ":")
	bracketIndex := strings.LastIndex(s, "]")
	if colIndex < bracketIndex || colIndex < 0 {
		return s, ""
	}
	return s[:colIndex], s[colIndex+1:]
}
