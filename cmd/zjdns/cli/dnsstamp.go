package cli

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
		// The validator's protocol table spells DoH "https", not "doh" —
		// ProtoToConfig's raw mapping would emit an entry that fails
		// validation on reload.
		entry.Protocol = config.ProtoHTTPS
	case zstamp.ProtoODoHTarget, zstamp.ProtoDNSCryptRelay, zstamp.ProtoODoHRelay:
		// These stamps have no ZJDNS upstream representation (no valid
		// protocol in the validator's table), so the decoded entry could
		// never be loaded back — fail loudly instead of emitting an
		// unusable JSON entry.
		return fmt.Errorf("%s stamps cannot be represented as a %s upstream", protoLabel(s.Proto), config.DefaultProjectName)
	default:
		// Every other stamp type carries a plain host:port address.
		entry.Address = s.Address
	}

	// TLS SNI / DNSCrypt provider name. The ODoH-target guard is unnecessary:
	// those stamps already returned an error above.
	if s.ProviderName != "" {
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
	if addr != "" && proto == zstamp.ProtoODoHTarget {
		// An ODoH target stamp carries no address — silently accepting one
		// would drop it and print a stamp different from the request.
		return errors.New("--stamp-addr is not valid for odoh-target (it has no address)")
	}

	s := &zstamp.DNSStamp{
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

	// Ensure path starts with / for DoH/ODoH protocols (target and relay).
	if !strings.HasPrefix(path, "/") && (proto == zstamp.ProtoDOH || proto == zstamp.ProtoODoHTarget || proto == zstamp.ProtoODoHRelay) {
		path = "/" + path
		s.Path = path
	}

	if proto == zstamp.ProtoDNSCrypt && len(s.PublicKey) == 0 {
		return errors.New("--public-key is required for DNSCrypt stamps")
	}
	if proto == zstamp.ProtoODoHTarget && providerName == "" {
		return errors.New("--provider-name is required for odoh-target protocol")
	}

	uri, err := s.MarshalStamp()
	if err != nil {
		return fmt.Errorf("encoding stamp: %w", err)
	}
	fmt.Println(uri)
	return nil
}

// protoLabel returns a human-readable protocol name for error messages.
func protoLabel(p zstamp.ProtoType) string {
	switch p {
	case zstamp.ProtoPlain:
		return "plain"
	case zstamp.ProtoDNSCrypt:
		return "dnscrypt"
	case zstamp.ProtoDOH:
		return "doh"
	case zstamp.ProtoDOT:
		return "dot"
	case zstamp.ProtoDOQ:
		return "doq"
	case zstamp.ProtoODoHTarget:
		return "odoh-target"
	case zstamp.ProtoDNSCryptRelay:
		return "dnscrypt-relay"
	case zstamp.ProtoODoHRelay:
		return "odoh-relay"
	}
	return "stamp"
}

func parseProto(s string) (zstamp.ProtoType, error) {
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
