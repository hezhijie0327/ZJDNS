package stamp

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// MarshalStamp encodes the stamp back to an sdns:// URI, reporting an error
// instead of emitting a sentinel string.  Use this in error-capable paths
// (CLI); String() keeps the sentinel for the fmt.Stringer constraint.
func (s *DNSStamp) MarshalStamp() (string, error) {
	// Length guards: wire fields are single-byte length-prefixed and VLP
	// elements cap at 127 bytes — the previous byte(len(x)) truncation
	// silently produced stamps that decode to garbage. Fail instead of
	// emitting corrupted output.
	if len(s.Address) > 255 || len(s.ProviderName) > 255 || len(s.Path) > 255 || len(s.PublicKey) > 255 {
		return "", errors.New("stamp field exceeds 255-byte single-byte length prefix")
	}
	for _, h := range s.Hashes {
		if len(h) > 127 {
			return "", errors.New("stamp hash exceeds 127-byte VLP limit")
		}
	}
	for _, b := range s.BootstrapIPs {
		if len(b) > 127 {
			return "", errors.New("stamp bootstrap IP exceeds 127-byte VLP limit")
		}
	}
	switch s.Proto {
	case ProtoPlain:
		return s.plainString(), nil
	case ProtoDNSCrypt:
		return s.dnsCryptString(), nil
	case ProtoDOH:
		return s.encodeSecure(ProtoDOH, DefaultHTTPSPort, false), nil
	case ProtoDOT:
		return s.encodeSecure(ProtoDOT, DefaultTLSPort, true), nil
	case ProtoDOQ:
		return s.encodeSecure(ProtoDOQ, DefaultTLSPort, true), nil
	case ProtoODoHTarget:
		return s.oDohTargetString(), nil
	case ProtoDNSCryptRelay:
		return s.dnsCryptRelayString(), nil
	case ProtoODoHRelay:
		return s.encodeSecure(ProtoODoHRelay, DefaultHTTPSPort, false), nil
	default:
		return "", fmt.Errorf("stamp: unknown protocol %d", s.Proto)
	}
}

// String encodes the stamp back to an sdns:// URI.  As a fmt.Stringer it
// cannot return an error — encoding failures surface as "sdns://error:..."
// sentinels; use MarshalStamp for error-capable paths.
func (s *DNSStamp) String() string {
	uri, err := s.MarshalStamp()
	if err != nil {
		return "sdns://error:" + err.Error()
	}
	return uri
}

func newStampHeader(proto uint8, props uint64) []byte {
	bin := make([]byte, 0, 128)
	bin = append(bin, proto)
	var propsBytes [8]uint8
	binary.LittleEndian.PutUint64(propsBytes[:], props)
	bin = append(bin, propsBytes[:]...)
	return bin
}

func (s *DNSStamp) plainString() string {
	bin := newStampHeader(byte(ProtoPlain), uint64(s.Props))
	addr := stripDefaultPort(s.Address, DefaultDNSPort)
	bin = append(bin, byte(len(addr))) //nolint:gosec // G115: address length bounded to 255
	bin = append(bin, []byte(addr)...)
	return stampPrefix + base64.RawURLEncoding.EncodeToString(bin)
}

func (s *DNSStamp) dnsCryptString() string {
	bin := newStampHeader(byte(ProtoDNSCrypt), uint64(s.Props))
	addr := stripDefaultPort(s.Address, DefaultHTTPSPort)
	bin = append(bin, byte(len(addr))) //nolint:gosec // G115: address length bounded to 255
	bin = append(bin, []byte(addr)...)
	bin = append(bin, byte(len(s.PublicKey))) //nolint:gosec // G115: key size is 32
	bin = append(bin, s.PublicKey...)
	bin = append(bin, byte(len(s.ProviderName))) //nolint:gosec // G115: name length bounded to 255
	bin = append(bin, []byte(s.ProviderName)...)
	return stampPrefix + base64.RawURLEncoding.EncodeToString(bin)
}

func (s *DNSStamp) oDohTargetString() string {
	bin := newStampHeader(byte(ProtoODoHTarget), uint64(s.Props))
	providerName := stripDefaultPort(s.ProviderName, DefaultHTTPSPort)
	bin = append(bin, byte(len(providerName))) //nolint:gosec // G115: name length bounded to 255
	bin = append(bin, []byte(providerName)...)
	bin = append(bin, byte(len(s.Path))) //nolint:gosec // G115: path length bounded to 255
	bin = append(bin, []byte(s.Path)...)
	return stampPrefix + base64.RawURLEncoding.EncodeToString(bin)
}

func (s *DNSStamp) dnsCryptRelayString() string {
	bin := make([]byte, 0, 32)
	bin = append(bin, byte(ProtoDNSCryptRelay)) //nolint:gosec // G115: proto byte
	addr := stripDefaultPort(s.Address, DefaultHTTPSPort)
	bin = append(bin, byte(len(addr))) //nolint:gosec // G115: address length bounded to 255
	bin = append(bin, []byte(addr)...)
	return stampPrefix + base64.RawURLEncoding.EncodeToString(bin)
}

// encodeSecure encodes a secure-transport stamp with protocol proto and default
// port.  skipPath omits the /dns-query path (used by DoT and DoQ).
func (s *DNSStamp) encodeSecure(proto ProtoType, port int, skipPath bool) string {
	bin := newStampHeader(byte(proto), uint64(s.Props))
	addr, providerName := encodeAddrAndHostname(s.Address, s.ProviderName, port)
	bin = append(bin, byte(len(addr))) //nolint:gosec // G115: address length bounded to 255
	bin = append(bin, []byte(addr)...)
	bin = appendHashes(bin, s.Hashes)
	bin = append(bin, byte(len(providerName))) //nolint:gosec // G115: name length bounded to 255
	bin = append(bin, []byte(providerName)...)
	if !skipPath {
		bin = append(bin, byte(len(s.Path))) //nolint:gosec // G115: path length bounded to 255
		bin = append(bin, []byte(s.Path)...)
	}
	bin = appendBootstrapIPs(bin, s.BootstrapIPs)
	return stampPrefix + base64.RawURLEncoding.EncodeToString(bin)
}

func stripDefaultPort(s string, defaultPort int) string {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return s // no port present
	}
	if p, err := strconv.Atoi(port); err == nil && p == defaultPort {
		return host
	}
	return s
}

// bracketIPv6 wraps a bare IPv6 literal in square brackets (RFC 3986 §3.2.2).
// The decoder's splitOptionalPort requires brackets to disambiguate the port —
// previously the encoder emitted bare IPv6 that its own parser rejected (R3-M16).
func bracketIPv6(host string) string {
	if strings.HasPrefix(host, "[") {
		return host // already bracketed
	}
	if strings.Count(host, ":") > 1 {
		return "[" + host + "]"
	}
	return host
}

func encodeAddrAndHostname(addr, hostname string, defaultPort int) (encodedAddr, encodedHost string) {
	if host, port := splitOptionalPort(addr); port != "" {
		addr = bracketIPv6(host)
		if hostname != "" {
			if _, hostPort := splitOptionalPort(hostname); hostPort == "" {
				hostname = hostname + ":" + port
			}
		} else {
			// Move the port onto the hostname instead of discarding it:
			// an empty hostname with a non-default port would otherwise
			// encode the stamp with the protocol's default port.
			hostname = bracketIPv6(host) + ":" + port
		}
	}
	// Bracket bare IPv6 in the no-port case too (a plain IPv6 address
	// without a port still needs brackets for the decoder).
	return bracketIPv6(addr), stripDefaultPort(hostname, defaultPort)
}

func appendHashes(bin []byte, hashes [][]byte) []byte {
	if len(hashes) == 0 {
		return append(bin, 0x00)
	}
	last := len(hashes) - 1
	for i, hash := range hashes {
		vlen := len(hash)
		if i < last {
			vlen |= 0x80
		}
		bin = append(bin, byte(vlen)) //nolint:gosec // G115: VLP length ≤ 127
		bin = append(bin, hash...)
	}
	return bin
}

func appendBootstrapIPs(bin []byte, bootstrapIPs []string) []byte {
	if len(bootstrapIPs) == 0 {
		// Per the stamp spec the VLP field is always present: an empty list
		// is encoded as a single 0x00 terminator (mirroring appendHashes).
		// Conforming decoders error on end-of-data without it.
		return append(bin, 0x00)
	}
	last := len(bootstrapIPs) - 1
	for i, bootstrapIP := range bootstrapIPs {
		vlen := len(bootstrapIP)
		if i < last {
			vlen |= 0x80
		}
		bin = append(bin, byte(vlen)) //nolint:gosec // G115: VLP length ≤ 127
		bin = append(bin, []byte(bootstrapIP)...)
	}
	return bin
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
		// Strip optional port suffix before bracket/IP validation.
		ip, port := splitOptionalPort(addr)
		if port != "" {
			if err := validatePort(port); err != nil {
				return err
			}
		}
		if ip != "" {
			if strings.HasPrefix(ip, "[") && strings.HasSuffix(ip, "]") {
				ip = ip[1 : len(ip)-1]
			} else if strings.ContainsRune(ip, ':') {
				return errors.New("stamp: invalid IP address")
			}
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
	// A bare IPv6 address has multiple colons and no brackets: do not treat
	// the last colon as a host:port separator (::1 would parse as host ":").
	if bracketIndex < 0 && strings.Count(s, ":") > 1 {
		return s, ""
	}
	host = s[:colIndex]
	// Restore trailing bracket stripped by the colon split for IPv6 addresses.
	if bracketIndex >= 0 && host != "" && host[0] == '[' && host[len(host)-1] != ']' {
		host += "]"
	}
	return host, s[colIndex+1:]
}
