// Package stamp implements DNS DNSStamp (sdns://) parsing for all major DNS
// protocols as defined by the DNSCrypt project's DNS DNSStamp specification.
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
	"strings"
)

// ProtoType identifies the DNS protocol encoded in a stamp.
type ProtoType uint8

// ServerInformalProperties is a bitmask of informal server properties
// (DNSSEC, NoLog, NoFilter) encoded as a uint64 in the stamp.
type ServerInformalProperties uint64

// DNSStamp holds the decoded fields of an sdns:// stamp, following the
// go-dnsstamps reference implementation.
type DNSStamp struct {
	Proto        ProtoType                // Protocol identifier
	Address      string                   // Server address as host:port
	ProviderName string                   // TLS SNI (DoT/DoQ/DoH), DNSCrypt provider name, or ODoH target host
	Props        ServerInformalProperties // Bitmask of PropDNSSEC | PropNoLog | PropNoFilter
	PublicKey    []byte                   // DNSCrypt Ed25519 server public key (32 bytes)
	Hashes       [][]byte                 // TLS cert hashes for pinning (DoT/DoQ/DoH, VLP-encoded)
	Path         string                   // HTTP path for DoH and ODoH (e.g. "/dns-query")
	BootstrapIPs []string                 // Optional bootstrap IP addresses (VLP-encoded)
}

// Protocol identifiers from the DNS DNSStamp specification.
const (
	ProtoPlain         = ProtoType(0x00)
	ProtoDNSCrypt      = ProtoType(0x01)
	ProtoDOH           = ProtoType(0x02)
	ProtoDOT           = ProtoType(0x03)
	ProtoDOQ           = ProtoType(0x04)
	ProtoODoHTarget    = ProtoType(0x05)
	ProtoDNSCryptRelay = ProtoType(0x81)
	ProtoODoHRelay     = ProtoType(0x85)
)

// Property bitmask flags.
const (
	PropDNSSEC   = ServerInformalProperties(1) << 0
	PropNoLog    = ServerInformalProperties(1) << 1
	PropNoFilter = ServerInformalProperties(1) << 2
)

// DNSStamp prefix used in all sdns:// URIs.
const stampPrefix = "sdns://"

// Default ports for protocols that omit the port in stamps.
const (
	DefaultHTTPSPort = 443
	DefaultTLSPort   = 853
	DefaultDNSPort   = 53
)

// Common errors returned by Parse.
var (
	ErrNotAStamp        = errors.New("not a stamp: must start with sdns://")
	ErrBase64Decode     = errors.New("stamp base64 decode failed")
	ErrTooShort         = errors.New("stamp too short")
	ErrUnknownProtocol  = errors.New("unknown stamp protocol")
	ErrTruncatedAddress = errors.New("stamp: truncated address")
	ErrTruncatedLength  = errors.New("stamp: truncated length field")
	ErrTruncatedPayload = errors.New("stamp: truncated payload")
	ErrInvalidPort      = errors.New("stamp: invalid port")
	ErrInvalidIP        = errors.New("stamp: invalid IP address")
	ErrTrailingGarbage  = errors.New("stamp: garbage after end")
)

// parsePlainDNS parses a Plain DNS stamp payload (protocol 0x00).
// Format: [addr_len:1][addr]
func Parse(stampStr string) (*DNSStamp, error) {
	if !strings.HasPrefix(stampStr, stampPrefix) {
		return nil, ErrNotAStamp
	}

	bin, err := base64.RawURLEncoding.Strict().DecodeString(stampStr[len(stampPrefix):])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBase64Decode, err)
	}

	if len(bin) < 1 {
		return nil, ErrTooShort
	}

	proto := ProtoType(bin[0])
	var s *DNSStamp

	switch proto {
	case ProtoPlain:
		s = &DNSStamp{Proto: proto}
		if len(bin) < 1+8+1+1 { // proto + props + addrLen(1) + minAddr(1)
			return nil, ErrTooShort
		}
		s.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
		if err := s.parsePlainDNS(bin); err != nil {
			return nil, err
		}
	case ProtoDNSCrypt:
		s = &DNSStamp{Proto: proto}
		if len(bin) < 66 {
			return nil, ErrTooShort
		}
		s.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
		if err := s.parseDNSCrypt(bin); err != nil {
			return nil, err
		}
	case ProtoDOH:
		s = &DNSStamp{Proto: proto}
		if len(bin) < 15 {
			return nil, ErrTooShort
		}
		s.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
		if err := s.parseSecure(bin, "DoH", true, false); err != nil {
			return nil, err
		}
	case ProtoDOT:
		s = &DNSStamp{Proto: proto}
		if len(bin) < 13 {
			return nil, ErrTooShort
		}
		s.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
		if err := s.parseSecure(bin, "DoT", false, false); err != nil {
			return nil, err
		}
	case ProtoDOQ:
		s = &DNSStamp{Proto: proto}
		if len(bin) < 13 {
			return nil, ErrTooShort
		}
		s.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
		if err := s.parseSecure(bin, "DoQ", false, false); err != nil {
			return nil, err
		}
	case ProtoODoHTarget:
		s = &DNSStamp{Proto: proto}
		if len(bin) < 12 {
			return nil, ErrTooShort
		}
		s.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
		if err := s.parseSecure(bin, "ODoH target", true, true); err != nil {
			return nil, err
		}
	case ProtoDNSCryptRelay:
		s = &DNSStamp{Proto: proto}
		if len(bin) < 9 {
			return nil, ErrTooShort
		}
		if err := s.parseDNSCryptRelay(bin); err != nil {
			return nil, err
		}
	case ProtoODoHRelay:
		s = &DNSStamp{Proto: proto}
		if len(bin) < 13 {
			return nil, ErrTooShort
		}
		s.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
		if err := s.parseSecure(bin, "ODoH relay", true, false); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownProtocol, proto)
	}

	return s, nil
}

// ProtoToConfig maps a stamp protocol ID to the corresponding config protocol
// string. Returns "" for protocol types that have no direct config mapping
// (relays, ODoH target).
func ProtoToConfig(stampProto ProtoType) string {
	switch stampProto {
	case ProtoPlain:
		return "udp"
	case ProtoDNSCrypt:
		return "dnscrypt"
	case ProtoDOH:
		return "doh"
	case ProtoDOT:
		return "dot"
	case ProtoDOQ:
		return "doq"
	case ProtoODoHTarget:
		return "odoh"
	case ProtoDNSCryptRelay:
		return "dnscrypt-relay"
	case ProtoODoHRelay:
		return "odoh-relay"
	default:
		return ""
	}
}

// BuildDoHURL constructs the full https:// URL from the stamp's DoH fields.
// Address supplies host:port; ProviderName optionally overrides the host;
// Path provides the HTTP endpoint (defaults to /dns-query).
func (s *DNSStamp) BuildDoHURL() string {
	host, port, err := net.SplitHostPort(s.Address)
	if err != nil {
		return "https://" + s.Address + "/dns-query"
	}
	if s.ProviderName != "" {
		host = s.ProviderName
	}
	path := s.Path
	if path == "" {
		path = "/dns-query"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return "https://" + net.JoinHostPort(host, port) + path
}

// String encodes the stamp back to an sdns:// URI.
