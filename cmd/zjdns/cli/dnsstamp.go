package cli

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"zjdns/config"
	zstamp "zjdns/internal/stamp"
)

// RunDNSStampDecode parses an sdns:// stamp and prints the equivalent ZJDNS
// upstream server JSON configuration entry.
func RunDNSStampDecode(stampStr string) error {
	s, err := zstamp.Parse(stampStr)
	if err != nil {
		return err
	}

	entry := config.UpstreamServer{
		Protocol: zstamp.ProtoToConfig(s.Proto),
	}

	// Build the address and server_name from stamp fields, matching the
	// normalization logic in config.normalizeStamps.
	switch s.Proto {
	case zstamp.ProtoDOH:
		entry.Address = s.BuildDoHURL()
	case zstamp.ProtoODoHTarget:
		// ODoH target has no address — provider name + path only.
		entry.ServerName = s.ProviderName
	default:
		entry.Address = s.Address
	}

	// TLS SNI / DNSCrypt provider name.
	if s.ProviderName != "" && s.Proto != zstamp.ProtoODoHTarget {
		entry.ServerName = s.ProviderName
	}

	// DNSCrypt public key.
	if s.Proto == zstamp.ProtoDNSCrypt && len(s.PublicKey) > 0 {
		entry.PublicKey = hex.EncodeToString(s.PublicKey)
	}

	// Print as indented JSON (same format as config file upstream entries).
	output, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling upstream entry: %w", err)
	}
	fmt.Println(string(output))
	return nil
}

// RunDNSStampEncode builds a Stamp from the given fields and prints the
// encoded sdns:// URI.
func RunDNSStampEncode(protoStr, addr, providerName, publicKeyHex, path string, props uint64) error {
	proto, err := parseProto(protoStr)
	if err != nil {
		return err
	}

	if addr == "" && proto != zstamp.ProtoODoHTarget {
		return fmt.Errorf("--stamp-addr is required for protocol %q", protoStr)
	}

	s := &zstamp.Stamp{
		Proto:        proto,
		Address:      addr,
		ProviderName: providerName,
		Path:         path,
		Props:        zstamp.ServerInformalProperties(props),
	}

	if publicKeyHex != "" {
		pk, err := hex.DecodeString(publicKeyHex)
		if err != nil {
			return fmt.Errorf("invalid --public-key hex: %w", err)
		}
		if len(pk) != 32 {
			return fmt.Errorf("--public-key must be 32 bytes (64 hex chars), got %d", len(pk))
		}
		s.PublicKey = pk
	}

	if proto == zstamp.ProtoDNSCrypt && len(s.PublicKey) == 0 {
		return errors.New("--public-key is required for DNSCrypt stamps")
	}

	fmt.Println(s.String())
	return nil
}

func parseProto(s string) (zstamp.StampProtoType, error) {
	switch s {
	case "plain":
		return zstamp.ProtoPlain, nil
	case "dnscrypt":
		return zstamp.ProtoDNSCrypt, nil
	case "doh":
		return zstamp.ProtoDOH, nil
	case "dot":
		return zstamp.ProtoDOT, nil
	case "doq":
		return zstamp.ProtoDOQ, nil
	case "odoh-target":
		return zstamp.ProtoODoHTarget, nil
	case "dnscrypt-relay":
		return zstamp.ProtoDNSCryptRelay, nil
	case "odoh-relay":
		return zstamp.ProtoODoHRelay, nil
	default:
		return 0, fmt.Errorf("unknown protocol %q (use: plain, dnscrypt, doh, dot, doq, odoh-target, dnscrypt-relay, odoh-relay)", s)
	}
}
