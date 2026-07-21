// Package stamp implements DNS DNSStamp (sdns://) parsing for all major DNS
// protocols as defined by the DNSCrypt project's DNS DNSStamp specification.
package stamp

import (
	"errors"
	"fmt"
	"net"
	"strconv"
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
	// colIndex tracks the position of the last colon for port detection.
	// When no colon is found, colIndex is set to len(Address); the
	// auto-append-default-port check (colIndex >= len-1) then correctly
	// passes, treating the address as a bare host with implied default port.
	colIndex := strings.LastIndex(s.Address, ":")
	if bracketIndex := strings.LastIndex(s.Address, "]"); colIndex < bracketIndex {
		colIndex = -1
	}
	if colIndex < 0 {
		colIndex = len(s.Address)
		s.Address = net.JoinHostPort(s.Address, strconv.Itoa(DefaultDNSPort))
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
		s.Address = net.JoinHostPort(s.Address, strconv.Itoa(DefaultHTTPSPort))
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

// parseSecure parses a secure-transport stamp payload.
// skipAddr omits address/hash parsing (ODoH Target has no address field).
func (s *DNSStamp) parseSecure(bin []byte, name string, hasPath, skipAddr bool) error {
	binLen := len(bin)
	pos := 9

	if !skipAddr {
		length := int(bin[pos])
		if 1+length >= binLen-pos {
			return fmt.Errorf("stamp: invalid %s stamp", name)
		}
		pos++
		s.Address = string(bin[pos : pos+length])
		pos += length

		hashes, newPos, err := readVLP(bin, pos, binLen)
		if err != nil {
			return fmt.Errorf("stamp: %s cert hashes: %w", name, err)
		}
		for _, h := range hashes {
			if len(h) != 32 {
				return fmt.Errorf("stamp: %s certificate hash must be 32 bytes", name)
			}
		}
		s.Hashes = hashes
		pos = newPos
	}

	length := int(bin[pos])
	if 1+length > binLen-pos {
		return fmt.Errorf("stamp: invalid %s stamp", name)
	}
	pos++
	s.ProviderName = string(bin[pos : pos+length])
	pos += length

	if hasPath {
		length = int(bin[pos])
		if length > binLen-pos {
			return fmt.Errorf("stamp: invalid %s stamp", name)
		}
		pos++
		s.Path = string(bin[pos : pos+length])
		pos += length
	}

	if !skipAddr && pos < binLen {
		bootstrapIPs, bpPos, bpErr := readVLP(bin, pos, binLen)
		if bpErr != nil {
			return fmt.Errorf("stamp: %s bootstrap IPs: %w", name, bpErr)
		}
		for _, ip := range bootstrapIPs {
			s.BootstrapIPs = append(s.BootstrapIPs, string(ip))
		}
		pos = bpPos
	}

	if pos != binLen {
		return ErrTrailingGarbage
	}

	if !skipAddr {
		if err := validateAddrAndHostname(s.Address, s.ProviderName); err != nil {
			return err
		}
	}
	return nil
}

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
