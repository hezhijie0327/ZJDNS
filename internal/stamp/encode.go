package stamp

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
)

func (s *DNSStamp) String() string {
	switch s.Proto {
	case ProtoPlain:
		return s.plainString()
	case ProtoDNSCrypt:
		return s.dnsCryptString()
	case ProtoDOH:
		return s.dohString()
	case ProtoDOT:
		return s.dotString()
	case ProtoDOQ:
		return s.doqString()
	case ProtoODoHTarget:
		return s.oDohTargetString()
	case ProtoDNSCryptRelay:
		return s.dnsCryptRelayString()
	case ProtoODoHRelay:
		return s.oDohRelayString()
	default:
		panic("unsupported protocol")
	}
}

func newStampHeader(proto uint8, props uint64) []uint8 {
	bin := make([]uint8, 0, 128)
	bin = append(bin, proto)
	var propsBytes [8]uint8
	binary.LittleEndian.PutUint64(propsBytes[:], props)
	bin = append(bin, propsBytes[:]...)
	return bin
}

func (s *DNSStamp) plainString() string {
	bin := newStampHeader(uint8(ProtoPlain), uint64(s.Props))
	addr := stripDefaultPort(s.Address, DefaultDNSPort)
	bin = append(bin, uint8(len(addr))) //nolint:gosec // G115: address length bounded to 255
	bin = append(bin, []uint8(addr)...)
	return stampPrefix + base64.RawURLEncoding.EncodeToString(bin)
}

func (s *DNSStamp) dnsCryptString() string {
	bin := newStampHeader(uint8(ProtoDNSCrypt), uint64(s.Props))
	addr := stripDefaultPort(s.Address, DefaultPort)
	bin = append(bin, uint8(len(addr))) //nolint:gosec // G115: address length bounded to 255
	bin = append(bin, []uint8(addr)...)
	bin = append(bin, uint8(len(s.PublicKey))) //nolint:gosec // G115: key size is 32
	bin = append(bin, s.PublicKey...)
	bin = append(bin, uint8(len(s.ProviderName))) //nolint:gosec // G115: name length bounded to 255
	bin = append(bin, []uint8(s.ProviderName)...)
	return stampPrefix + base64.RawURLEncoding.EncodeToString(bin)
}

func (s *DNSStamp) dohString() string {
	bin := newStampHeader(uint8(ProtoDOH), uint64(s.Props))
	addr, providerName := encodeAddrAndHostname(s.Address, s.ProviderName, DefaultPort)
	bin = append(bin, uint8(len(addr))) //nolint:gosec // G115: address length bounded to 255
	bin = append(bin, []uint8(addr)...)
	bin = appendHashes(bin, s.Hashes)
	bin = append(bin, uint8(len(providerName))) //nolint:gosec // G115: name length bounded to 255
	bin = append(bin, []uint8(providerName)...)
	bin = append(bin, uint8(len(s.Path))) //nolint:gosec // G115: path length bounded to 255
	bin = append(bin, []uint8(s.Path)...)
	bin = appendBootstrapIPs(bin, s.BootstrapIPs)
	return stampPrefix + base64.RawURLEncoding.EncodeToString(bin)
}

func (s *DNSStamp) dotString() string {
	bin := newStampHeader(uint8(ProtoDOT), uint64(s.Props))
	addr, providerName := encodeAddrAndHostname(s.Address, s.ProviderName, DefaultDoTPort)
	bin = append(bin, uint8(len(addr))) //nolint:gosec // G115: address length bounded to 255
	bin = append(bin, []uint8(addr)...)
	bin = appendHashes(bin, s.Hashes)
	bin = append(bin, uint8(len(providerName))) //nolint:gosec // G115: name length bounded to 255
	bin = append(bin, []uint8(providerName)...)
	bin = appendBootstrapIPs(bin, s.BootstrapIPs)
	return stampPrefix + base64.RawURLEncoding.EncodeToString(bin)
}

func (s *DNSStamp) doqString() string {
	bin := newStampHeader(uint8(ProtoDOQ), uint64(s.Props))
	addr, providerName := encodeAddrAndHostname(s.Address, s.ProviderName, DefaultDoTPort)
	bin = append(bin, uint8(len(addr))) //nolint:gosec // G115: address length bounded to 255
	bin = append(bin, []uint8(addr)...)
	bin = appendHashes(bin, s.Hashes)
	bin = append(bin, uint8(len(providerName))) //nolint:gosec // G115: name length bounded to 255
	bin = append(bin, []uint8(providerName)...)
	bin = appendBootstrapIPs(bin, s.BootstrapIPs)
	return stampPrefix + base64.RawURLEncoding.EncodeToString(bin)
}

func (s *DNSStamp) oDohTargetString() string {
	bin := newStampHeader(uint8(ProtoODoHTarget), uint64(s.Props))
	providerName := stripDefaultPort(s.ProviderName, DefaultPort)
	bin = append(bin, uint8(len(providerName))) //nolint:gosec // G115: name length bounded to 255
	bin = append(bin, []uint8(providerName)...)
	bin = append(bin, uint8(len(s.Path))) //nolint:gosec // G115: path length bounded to 255
	bin = append(bin, []uint8(s.Path)...)
	return stampPrefix + base64.RawURLEncoding.EncodeToString(bin)
}

func (s *DNSStamp) dnsCryptRelayString() string {
	bin := make([]uint8, 0, 32)
	bin = append(bin, uint8(ProtoDNSCryptRelay)) //nolint:gosec // G115: proto byte
	addr := stripDefaultPort(s.Address, DefaultPort)
	bin = append(bin, uint8(len(addr))) //nolint:gosec // G115: address length bounded to 255
	bin = append(bin, []uint8(addr)...)
	return stampPrefix + base64.RawURLEncoding.EncodeToString(bin)
}

func (s *DNSStamp) oDohRelayString() string {
	bin := newStampHeader(uint8(ProtoODoHRelay), uint64(s.Props))
	addr, providerName := encodeAddrAndHostname(s.Address, s.ProviderName, DefaultPort)
	bin = append(bin, uint8(len(addr))) //nolint:gosec // G115: address length bounded to 255
	bin = append(bin, []uint8(addr)...)
	bin = appendHashes(bin, s.Hashes)
	bin = append(bin, uint8(len(providerName))) //nolint:gosec // G115: name length bounded to 255
	bin = append(bin, []uint8(providerName)...)
	bin = append(bin, uint8(len(s.Path))) //nolint:gosec // G115: path length bounded to 255
	bin = append(bin, []uint8(s.Path)...)
	bin = appendBootstrapIPs(bin, s.BootstrapIPs)
	return stampPrefix + base64.RawURLEncoding.EncodeToString(bin)
}

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
