// Package stamp implements DNS DNSStamp (sdns://) parsing for all major DNS
// protocols as defined by the DNSCrypt project's DNS DNSStamp specification.
package stamp

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

func (s *DNSStamp) parsePlainDNS(bin []byte) error {
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
func (s *DNSStamp) parseDNSCrypt(bin []byte) error {
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
func (s *DNSStamp) parseDoH(bin []byte) error {
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
func (s *DNSStamp) parseDoT(bin []byte) error {
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
func (s *DNSStamp) parseDoQ(bin []byte) error {
	// DoQ shares the same format as DoT.
	return s.parseDoT(bin)
}

// parseODoHTarget parses an Oblivious DoH Target stamp payload (protocol 0x05).
// Format: [host_len:1][host][path_len:1][path]
func (s *DNSStamp) parseODoHTarget(bin []byte) error {
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
func (s *DNSStamp) parseDNSCryptRelay(bin []byte) error {
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
func (s *DNSStamp) parseODoHRelay(bin []byte) error {
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
