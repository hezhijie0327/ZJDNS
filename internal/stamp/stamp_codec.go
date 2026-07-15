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
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func (s *Stamp) parsePlainDNS(bin []byte) error {
	binLen := len(bin)
	pos := 9 // skip proto(1) + props(8)

	length := int(bin[pos])
	if 1+length > binLen-pos {
		return errors.New("stamp: invalid plain DNS stamp")
	}
	pos++
	s.Address = string(bin[pos : pos+length])
	pos += length

	// Auto-append default DNS port if missing.
	colIndex := strings.LastIndex(s.Address, ":")
	if bracketIndex := strings.LastIndex(s.Address, "]"); colIndex < bracketIndex {
		colIndex = -1
	}
	if colIndex < 0 {
		colIndex = len(s.Address)
		s.Address = fmt.Sprintf("%s:%d", s.Address, DefaultDNSPort)
	}
	if colIndex >= len(s.Address)-1 {
		return errors.New("stamp: empty port")
	}
	ipOnly := s.Address[:colIndex]
	if err := validatePort(s.Address[colIndex+1:]); err != nil {
		return err
	}
	if net.ParseIP(strings.TrimRight(strings.TrimLeft(ipOnly, "["), "]")) == nil {
		return errors.New("stamp: plain DNS address must be an IP address")
	}
	if pos != binLen {
		return ErrTrailingGarbage
	}
	return nil
}

// parseDNSCrypt parses a DNSCrypt stamp payload (protocol 0x01).
// Format: [addr_len:1][addr][pk_len:1][pk][prov_len:1][prov]
func (s *Stamp) parseDNSCrypt(bin []byte) error {
	binLen := len(bin)
	pos := 9 // skip proto(1) + props(8)

	// Address.
	length := int(bin[pos])
	if 1+length >= binLen-pos {
		return errors.New("stamp: invalid DNSCrypt stamp")
	}
	pos++
	s.Address = string(bin[pos : pos+length])
	pos += length

	// Auto-append default port if missing.
	colIndex := strings.LastIndex(s.Address, ":")
	if bracketIndex := strings.LastIndex(s.Address, "]"); colIndex < bracketIndex {
		colIndex = -1
	}
	if colIndex < 0 {
		colIndex = len(s.Address)
		s.Address = fmt.Sprintf("%s:%d", s.Address, DefaultPort)
	}
	if colIndex >= len(s.Address)-1 {
		return errors.New("stamp: empty port")
	}
	ipOnly := s.Address[:colIndex]
	if err := validatePort(s.Address[colIndex+1:]); err != nil {
		return err
	}
	if net.ParseIP(strings.TrimRight(strings.TrimLeft(ipOnly, "["), "]")) == nil {
		return errors.New("stamp: DNSCrypt address must be an IP address")
	}

	// Public key — MUST be exactly 32 bytes per §4.2.3.
	length = int(bin[pos])
	if length != 32 {
		return errors.New("stamp: DNSCrypt public key must be exactly 32 bytes")
	}
	if 1+length >= binLen-pos {
		return errors.New("stamp: invalid DNSCrypt stamp")
	}
	pos++
	s.PublicKey = make([]byte, length)
	copy(s.PublicKey, bin[pos:pos+length])
	pos += length

	// Provider name.
	length = int(bin[pos])
	if length >= binLen-pos {
		return errors.New("stamp: invalid DNSCrypt stamp")
	}
	pos++
	s.ProviderName = string(bin[pos : pos+length])
	pos += length

	if pos != binLen {
		return ErrTrailingGarbage
	}
	return nil
}

// parseDoH parses a DNS-over-HTTPS stamp payload (protocol 0x02).
// Format: [addr_len:1][addr][hashes:VLP][host_len:1][host][path_len:1][path][bootstrap:VLP]
func (s *Stamp) parseDoH(bin []byte) error {
	binLen := len(bin)
	pos := 9

	// Address.
	length := int(bin[pos])
	if 1+length >= binLen-pos {
		return errors.New("stamp: invalid DoH stamp")
	}
	pos++
	s.Address = string(bin[pos : pos+length])
	pos += length

	// Hashes (VLP-encoded).
	hashes, newPos, err := readVLP(bin, pos, binLen)
	if err != nil {
		return fmt.Errorf("stamp: DoH cert hashes: %w", err)
	}
	for _, h := range hashes {
		if len(h) != 32 {
			return errors.New("stamp: DoH certificate hash must be 32 bytes")
		}
	}
	s.Hashes = hashes
	pos = newPos

	// Provider name (SNI).
	length = int(bin[pos])
	if 1+length >= binLen-pos {
		return errors.New("stamp: invalid DoH stamp")
	}
	pos++
	s.ProviderName = string(bin[pos : pos+length])
	pos += length

	// Path.
	length = int(bin[pos])
	if length >= binLen-pos {
		return errors.New("stamp: invalid DoH stamp")
	}
	pos++
	s.Path = string(bin[pos : pos+length])
	pos += length

	// Optional bootstrap IPs (VLP-encoded).
	if pos < binLen {
		bootstrapIPs, bpPos, bpErr := readVLP(bin, pos, binLen)
		if bpErr != nil {
			return fmt.Errorf("stamp: DoH bootstrap IPs: %w", bpErr)
		}
		for _, ip := range bootstrapIPs {
			s.BootstrapIPs = append(s.BootstrapIPs, string(ip))
		}
		pos = bpPos
	}

	if pos != binLen {
		return ErrTrailingGarbage
	}

	if err := validateAddrAndHostname(s.Address, s.ProviderName); err != nil {
		return err
	}
	return nil
}

// parseDoT parses a DNS-over-TLS stamp payload (protocol 0x03).
// Format: [addr_len:1][addr][hashes:VLP][host_len:1][host][bootstrap:VLP]
func (s *Stamp) parseDoT(bin []byte) error {
	binLen := len(bin)
	pos := 9

	// Address.
	length := int(bin[pos])
	if 1+length >= binLen-pos {
		return errors.New("stamp: invalid DoT stamp")
	}
	pos++
	s.Address = string(bin[pos : pos+length])
	pos += length

	// Hashes (VLP-encoded).
	hashes, newPos, err := readVLP(bin, pos, binLen)
	if err != nil {
		return fmt.Errorf("stamp: DoT cert hashes: %w", err)
	}
	for _, h := range hashes {
		if len(h) != 32 {
			return errors.New("stamp: DoT certificate hash must be 32 bytes")
		}
	}
	s.Hashes = hashes
	pos = newPos

	// Provider name (SNI).
	length = int(bin[pos])
	if length >= binLen-pos {
		return errors.New("stamp: invalid DoT stamp")
	}
	pos++
	s.ProviderName = string(bin[pos : pos+length])
	pos += length

	// Optional bootstrap IPs (VLP-encoded).
	if pos < binLen {
		bootstrapIPs, bpPos, bpErr := readVLP(bin, pos, binLen)
		if bpErr != nil {
			return fmt.Errorf("stamp: DoT bootstrap IPs: %w", bpErr)
		}
		for _, ip := range bootstrapIPs {
			s.BootstrapIPs = append(s.BootstrapIPs, string(ip))
		}
		pos = bpPos
	}

	if pos != binLen {
		return ErrTrailingGarbage
	}

	if err := validateAddrAndHostname(s.Address, s.ProviderName); err != nil {
		return err
	}
	return nil
}

// parseDoQ parses a DNS-over-QUIC stamp payload (protocol 0x04).
// Format: [addr_len:1][addr][hashes:VLP][host_len:1][host][bootstrap:VLP]
func (s *Stamp) parseDoQ(bin []byte) error {
	// DoQ shares the same format as DoT.
	return s.parseDoT(bin)
}

// parseODoHTarget parses an Oblivious DoH Target stamp payload (protocol 0x05).
// Format: [host_len:1][host][path_len:1][path]
func (s *Stamp) parseODoHTarget(bin []byte) error {
	binLen := len(bin)
	pos := 9

	// Provider name (target hostname).
	length := int(bin[pos])
	if 1+length >= binLen-pos {
		return errors.New("stamp: invalid ODoH target stamp")
	}
	pos++
	s.ProviderName = string(bin[pos : pos+length])
	pos += length

	// Path.
	length = int(bin[pos])
	if length >= binLen-pos {
		return errors.New("stamp: invalid ODoH target stamp")
	}
	pos++
	s.Path = string(bin[pos : pos+length])
	pos += length

	if pos != binLen {
		return ErrTrailingGarbage
	}

	if _, err := stripAndValidatePort(s.ProviderName); err != nil {
		return err
	}
	return nil
}

// parseDNSCryptRelay parses a DNSCrypt Relay stamp payload (protocol 0x81).
// Format: [addr_len:1][addr]  (no properties field)
//
// Per §4.7.2, port specification is mandatory for relay stamps.
func (s *Stamp) parseDNSCryptRelay(bin []byte) error {
	binLen := len(bin)
	pos := 1 // relay stamps have no properties — skip only proto byte

	length := int(bin[pos])
	if 1+length > binLen-pos {
		return errors.New("stamp: invalid DNSCrypt relay stamp")
	}
	pos++
	s.Address = string(bin[pos : pos+length])
	pos += length

	colIndex := strings.LastIndex(s.Address, ":")
	if bracketIndex := strings.LastIndex(s.Address, "]"); colIndex < bracketIndex {
		colIndex = -1
	}
	if colIndex < 0 {
		return errors.New("stamp: DNSCrypt relay address must include a port")
	}
	if colIndex >= len(s.Address)-1 {
		return errors.New("stamp: empty port")
	}
	ipOnly := s.Address[:colIndex]
	if err := validatePort(s.Address[colIndex+1:]); err != nil {
		return err
	}
	if net.ParseIP(strings.TrimRight(strings.TrimLeft(ipOnly, "["), "]")) == nil {
		return errors.New("stamp: DNSCrypt relay address must be an IP address")
	}
	if pos != binLen {
		return ErrTrailingGarbage
	}
	return nil
}

// parseODoHRelay parses an Oblivious DoH Relay stamp payload (protocol 0x85).
// Format: [addr_len:1][addr][hashes:VLP][host_len:1][host][path_len:1][path][bootstrap:VLP]
func (s *Stamp) parseODoHRelay(bin []byte) error {
	binLen := len(bin)
	pos := 9

	// Address.
	length := int(bin[pos])
	if 1+length >= binLen-pos {
		return errors.New("stamp: invalid ODoH relay stamp")
	}
	pos++
	s.Address = string(bin[pos : pos+length])
	pos += length

	// Hashes (VLP-encoded).
	hashes, newPos, err := readVLP(bin, pos, binLen)
	if err != nil {
		return fmt.Errorf("stamp: ODoH relay cert hashes: %w", err)
	}
	for _, h := range hashes {
		if len(h) != 32 {
			return errors.New("stamp: ODoH relay certificate hash must be 32 bytes")
		}
	}
	s.Hashes = hashes
	pos = newPos

	// Provider name (SNI).
	length = int(bin[pos])
	if 1+length >= binLen-pos {
		return errors.New("stamp: invalid ODoH relay stamp")
	}
	pos++
	s.ProviderName = string(bin[pos : pos+length])
	pos += length

	// Path.
	length = int(bin[pos])
	if length >= binLen-pos {
		return errors.New("stamp: invalid ODoH relay stamp")
	}
	pos++
	s.Path = string(bin[pos : pos+length])
	pos += length

	// Optional bootstrap IPs (VLP-encoded).
	if pos < binLen {
		bootstrapIPs, bpPos, bpErr := readVLP(bin, pos, binLen)
		if bpErr != nil {
			return fmt.Errorf("stamp: ODoH relay bootstrap IPs: %w", bpErr)
		}
		for _, ip := range bootstrapIPs {
			s.BootstrapIPs = append(s.BootstrapIPs, string(ip))
		}
		pos = bpPos
	}

	if pos != binLen {
		return ErrTrailingGarbage
	}

	if err := validateAddrAndHostname(s.Address, s.ProviderName); err != nil {
		return err
	}
	return nil
}

func (s *Stamp) String() string {
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

func (s *Stamp) plainString() string {
	bin := newStampHeader(uint8(ProtoPlain), uint64(s.Props))
	addr := stripDefaultPort(s.Address, DefaultDNSPort)
	bin = append(bin, uint8(len(addr))) //nolint:gosec // G115: address length bounded to 255
	bin = append(bin, []uint8(addr)...)
	return stampPrefix + base64.RawURLEncoding.EncodeToString(bin)
}

func (s *Stamp) dnsCryptString() string {
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

func (s *Stamp) dohString() string {
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

func (s *Stamp) dotString() string {
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

func (s *Stamp) doqString() string {
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

func (s *Stamp) oDohTargetString() string {
	bin := newStampHeader(uint8(ProtoODoHTarget), uint64(s.Props))
	providerName := stripDefaultPort(s.ProviderName, DefaultPort)
	bin = append(bin, uint8(len(providerName))) //nolint:gosec // G115: name length bounded to 255
	bin = append(bin, []uint8(providerName)...)
	bin = append(bin, uint8(len(s.Path))) //nolint:gosec // G115: path length bounded to 255
	bin = append(bin, []uint8(s.Path)...)
	return stampPrefix + base64.RawURLEncoding.EncodeToString(bin)
}

func (s *Stamp) dnsCryptRelayString() string {
	bin := make([]uint8, 0, 32)
	bin = append(bin, uint8(ProtoDNSCryptRelay)) //nolint:gosec // G115: proto byte
	addr := stripDefaultPort(s.Address, DefaultPort)
	bin = append(bin, uint8(len(addr))) //nolint:gosec // G115: address length bounded to 255
	bin = append(bin, []uint8(addr)...)
	return stampPrefix + base64.RawURLEncoding.EncodeToString(bin)
}

func (s *Stamp) oDohRelayString() string {
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
