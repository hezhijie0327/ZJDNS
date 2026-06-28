package cli

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"zjdns/config"
)

// parseStamp decodes an sdns:// DNS stamp and outputs a JSON config snippet
// with the decoded server details ready for use as an upstream entry.
func ParseStamp(stampStr string) string {
	if !strings.HasPrefix(stampStr, "sdns://") {
		return `{"error": "stamp must start with sdns://"}`
	}

	data, err := base64.RawURLEncoding.DecodeString(stampStr[7:])
	if err != nil {
		return fmt.Sprintf(`{"error": "decode stamp: %v"}`, err)
	}
	if len(data) < 2 {
		return `{"error": "stamp too short"}`
	}

	proto := data[0]
	_ = data[1] // properties

	switch proto {
	case 0x01: // DNSCrypt
		return parseDNSCryptStamp(data)
	case 0x02: // DoH
		return fmt.Sprintf(`{"error": "DoH stamp parsing not yet implemented (proto=0x%02x)"}`, proto)
	case 0x00: // Plain DNS
		return fmt.Sprintf(`{"error": "plain DNS stamp parsing not yet implemented (proto=0x%02x)"}`, proto)
	default:
		return fmt.Sprintf(`{"error": "unsupported stamp protocol: 0x%02x"}`, proto)
	}
}

func parseDNSCryptStamp(data []byte) string {
	if len(data) < 10+12+32+1+1 {
		return `{"error": "DNSCrypt stamp too short"}`
	}

	// Skip proto(1) + props(1) + reserved(8) = 10 bytes.
	// Address is NOT length-prefixed; a space (0x20) separates it from the key.
	addrEnd := -1
	for i := 10; i < len(data); i++ {
		if data[i] == 0x20 {
			addrEnd = i
			break
		}
	}
	if addrEnd < 0 {
		return `{"error": "DNSCrypt stamp: address/pk separator not found"}`
	}
	addr := string(data[10:addrEnd])

	// Public key: 32 bytes after the space.
	pkStart := addrEnd + 1
	if pkStart+32 > len(data) {
		return `{"error": "DNSCrypt stamp: public key truncated"}`
	}
	pk := hex.EncodeToString(data[pkStart : pkStart+32])

	// Provider name: length-prefixed after the public key.
	nameStart := pkStart + 32
	if nameStart >= len(data) {
		return `{"error": "DNSCrypt stamp: provider name missing"}`
	}
	nameLen := int(data[nameStart])
	nameStart++
	if nameStart+nameLen > len(data) {
		return `{"error": "DNSCrypt stamp: provider name truncated"}`
	}
	providerName := string(data[nameStart : nameStart+nameLen])

	out := config.UpstreamServer{
		Address:           addr,
		Protocol:          config.ProtoDNSCrypt,
		ServerName:        providerName,
		DNSCryptPublicKey: pk,
	}

	b, _ := json.MarshalIndent(out, "", "  ")
	return string(b)
}
