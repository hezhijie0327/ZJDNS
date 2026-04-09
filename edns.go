// Package main implements ZJDNS - High Performance DNS Server
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
)

// =============================================================================
// EDNSManager Implementation
// =============================================================================

// NewEDNSManager creates a new EDNS manager with optional default ECS subnet
func NewEDNSManager(defaultSubnet string) (*EDNSManager, error) {
	manager := &EDNSManager{
		detector: &IPDetector{
			httpClient: &http.Client{Timeout: OperationTimeout},
		},
		cookieGenerator: NewCookieGenerator(),
	}

	if defaultSubnet != "" {
		ecs, err := manager.parseECSConfig(defaultSubnet)
		if err != nil {
			return nil, fmt.Errorf("parse ECS config: %w", err)
		}
		manager.defaultECS = ecs
		if ecs != nil {
			LogInfo("EDNS: Default ECS: %s/%d", ecs.Address, ecs.SourcePrefix)
		}
	}

	return manager, nil
}

// GetDefaultECS returns the default ECS option if configured
func (em *EDNSManager) GetDefaultECS() *ECSOption {
	if em == nil {
		return nil
	}
	return em.defaultECS
}

// ParseFromDNS extracts ECS option from a DNS message
func (em *EDNSManager) ParseFromDNS(msg *dns.Msg) *ECSOption {
	if em == nil || msg == nil || len(msg.Pseudo) == 0 {
		return nil
	}

	for _, option := range msg.Pseudo {
		switch subnet := option.(type) {
		case *dns.SUBNET:
			return &ECSOption{
				Family:       subnet.Family,
				SourcePrefix: subnet.Netmask,
				ScopePrefix:  subnet.Scope,
				Address:      net.IP(subnet.Address.AsSlice()),
			}
		}
	}
	return nil
}

// ParseCookie extracts DNS Cookie option from a DNS message
func (em *EDNSManager) ParseCookie(msg *dns.Msg) *CookieOption {
	if em == nil || msg == nil || len(msg.Pseudo) == 0 {
		return nil
	}

	for _, option := range msg.Pseudo {
		if cookie, ok := option.(*dns.COOKIE); ok {
			cookieHex := cookie.Cookie
			cookieBytes, _ := hex.DecodeString(cookieHex)

			// Client cookie is always 8 bytes (16 hex chars)
			if len(cookieBytes) >= DefaultCookieClientLen {
				clientCookie := cookieBytes[:DefaultCookieClientLen]
				var serverCookie []byte
				if len(cookieBytes) > DefaultCookieClientLen {
					serverCookie = cookieBytes[DefaultCookieClientLen:]
				}
				return &CookieOption{
					ClientCookie: clientCookie,
					ServerCookie: serverCookie,
				}
			}
		}
	}
	return nil
}

// ParseEDE extracts EDE (Extended DNS Error) option from a DNS message
func (em *EDNSManager) ParseEDE(msg *dns.Msg) *EDEOption {
	if em == nil || msg == nil || len(msg.Pseudo) == 0 {
		return nil
	}

	for _, option := range msg.Pseudo {
		if ede, ok := option.(*dns.EDE); ok {
			return &EDEOption{
				InfoCode:  ede.InfoCode,
				ExtraText: ede.ExtraText,
			}
		}
	}
	return nil
}

// AddToMessage adds EDNS options including ECS, cookies, EDE, and padding to a DNS message
func (em *EDNSManager) AddToMessage(msg *dns.Msg, ecs *ECSOption, clientRequestedDNSSEC bool, isSecureConnection bool, cookieStr string, ede *EDEOption) {
	if em == nil || msg == nil {
		return
	}

	if msg.Question == nil {
		msg.Question = []dns.RR{}
	}
	if msg.Answer == nil {
		msg.Answer = []dns.RR{}
	}
	if msg.Ns == nil {
		msg.Ns = []dns.RR{}
	}
	if msg.Extra == nil {
		msg.Extra = []dns.RR{}
	}

	msg.Pseudo = msg.Pseudo[:0]
	msg.UDPSize = UDPBufferSize
	msg.Security = clientRequestedDNSSEC

	if ecs != nil {
		if addr, ok := netip.AddrFromSlice(ecs.Address); ok {
			msg.Pseudo = append(msg.Pseudo, &dns.SUBNET{
				Family:  ecs.Family,
				Netmask: ecs.SourcePrefix,
				Scope:   DefaultECSScope,
				Address: addr,
			})
		}
	}

	if cookieStr != "" {
		msg.Pseudo = append(msg.Pseudo, &dns.COOKIE{Cookie: cookieStr})
	}

	if ede != nil {
		msg.Pseudo = append(msg.Pseudo, &dns.EDE{InfoCode: ede.InfoCode, ExtraText: ede.ExtraText})
	}

	if isSecureConnection {
		paddingDataSize := PaddingSize
		if err := msg.Pack(); err == nil {
			currentSize := len(msg.Data)
			if currentSize < PaddingSize {
				paddingDataSize = PaddingSize - currentSize - 4
			}
		}
		if paddingDataSize > 0 {
			paddingBytes := make([]byte, paddingDataSize)
			msg.Pseudo = append(msg.Pseudo, &dns.PADDING{Padding: hex.EncodeToString(paddingBytes)})
		}
	}
}

// parseECSConfig parses ECS configuration string (auto, auto_v4, auto_v6, or CIDR)
func (em *EDNSManager) parseECSConfig(subnet string) (*ECSOption, error) {
	switch strings.ToLower(subnet) {
	case "auto":
		return em.detectPublicIP(false, true)
	case "auto_v4":
		return em.detectPublicIP(false, false)
	case "auto_v6":
		return em.detectPublicIP(true, false)
	default:
		_, ipNet, err := net.ParseCIDR(subnet)
		if err != nil {
			return nil, fmt.Errorf("parse CIDR: %w", err)
		}
		prefix, _ := ipNet.Mask.Size()
		family := uint16(1)
		if ipNet.IP.To4() == nil {
			family = 2
		}
		return &ECSOption{
			Family:       family,
			SourcePrefix: uint8(prefix),
			ScopePrefix:  DefaultECSScope,
			Address:      ipNet.IP,
		}, nil
	}
}

// detectPublicIP detects the public IP address using external service
func (em *EDNSManager) detectPublicIP(forceIPv6, allowFallback bool) (*ECSOption, error) {
	var ecs *ECSOption
	if ip := em.detector.detectPublicIP(forceIPv6); ip != nil {
		family := uint16(1)
		prefix := uint8(DefaultECSv4Len)
		if forceIPv6 {
			family = 2
			prefix = DefaultECSv6Len
		}
		ecs = &ECSOption{
			Family:       family,
			SourcePrefix: prefix,
			ScopePrefix:  DefaultECSScope,
			Address:      ip,
		}
	}

	// Fallback to IPv6 if IPv4 detection failed
	if ecs == nil && allowFallback && !forceIPv6 {
		if ip := em.detector.detectPublicIP(true); ip != nil {
			ecs = &ECSOption{
				Family:       2,
				SourcePrefix: DefaultECSv6Len,
				ScopePrefix:  DefaultECSScope,
				Address:      ip,
			}
		}
	}

	return ecs, nil
}

// =============================================================================
// CookieGenerator Implementation (RFC 7873 + RFC 9018)
// =============================================================================

// CookieGenerator handles DNS cookie generation and validation
type CookieGenerator struct {
	secret []byte // Server secret for HMAC
}

// NewCookieGenerator creates a new cookie generator with a random secret
func NewCookieGenerator() *CookieGenerator {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		// Fallback: use timestamp-based secret if crypto/rand fails
		secret = []byte(fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Unix()))
	}
	return &CookieGenerator{secret: secret}
}

// GenerateServerCookie generates a server cookie per RFC 9018
// Algorithm: HMAC-SHA256(secret, clientIP || clientCookie || timestamp || nonce)
// Server cookie format: nonce (8 bytes) || HMAC truncated to 8 bytes = 16 bytes total
func (cg *CookieGenerator) GenerateServerCookie(clientIP net.IP, clientCookie []byte) []byte {
	if cg == nil || len(clientCookie) != DefaultCookieClientLen {
		return nil
	}

	// Generate random nonce (8 bytes)
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		// Fallback to timestamp-based nonce
		timestamp := uint64(time.Now().UnixNano())
		for i := 0; i < 8; i++ {
			nonce[i] = byte(timestamp >> (i * 8))
		}
	}

	// Build HMAC input: clientIP || clientCookie || nonce
	data := make([]byte, 0, len(clientIP)+len(clientCookie)+len(nonce))
	data = append(data, clientIP...)
	data = append(data, clientCookie...)
	data = append(data, nonce...)

	// Compute HMAC-SHA256
	h := hmac.New(sha256.New, cg.secret)
	h.Write(data)
	mac := h.Sum(nil)

	// Server cookie = nonce (8 bytes) || truncated MAC (8 bytes) = 16 bytes
	serverCookie := make([]byte, 0, DefaultCookieServerLen)
	serverCookie = append(serverCookie, nonce...)
	serverCookie = append(serverCookie, mac[:8]...)

	return serverCookie
}

// ValidateServerCookie verifies a server cookie
func (cg *CookieGenerator) ValidateServerCookie(clientIP net.IP, clientCookie, serverCookie []byte) bool {
	if cg == nil || len(clientCookie) != DefaultCookieClientLen || len(serverCookie) < 16 {
		return false
	}

	// Extract nonce (first 8 bytes)
	nonce := serverCookie[:8]
	receivedMAC := serverCookie[8:16]

	// Rebuild HMAC input
	data := make([]byte, 0, len(clientIP)+len(clientCookie)+len(nonce))
	data = append(data, clientIP...)
	data = append(data, clientCookie...)
	data = append(data, nonce...)

	// Compute expected HMAC
	h := hmac.New(sha256.New, cg.secret)
	h.Write(data)
	expectedMAC := h.Sum(nil)[:8]

	return hmac.Equal(receivedMAC, expectedMAC)
}

// GenerateClientCookie generates an 8-byte client cookie
// Per RFC 7873 Section 5.1: Client should use a stable source of entropy
func (cg *CookieGenerator) GenerateClientCookie(clientIP net.IP) []byte {
	clientCookie := make([]byte, DefaultCookieClientLen)

	// Use HMAC of clientIP with server secret
	h := hmac.New(sha256.New, cg.secret)
	h.Write(clientIP)
	h.Write([]byte("client"))
	copy(clientCookie, h.Sum(nil))

	return clientCookie
}

// BuildCookieResponse builds the full cookie string for response
// Format: hex(client_cookie || server_cookie)
func BuildCookieResponse(clientCookie, serverCookie []byte) string {
	if len(clientCookie) != DefaultCookieClientLen {
		return ""
	}

	cookie := make([]byte, 0, len(clientCookie)+len(serverCookie))
	cookie = append(cookie, clientCookie...)
	cookie = append(cookie, serverCookie...)

	return hex.EncodeToString(cookie)
}

// =============================================================================
// Extended DNS Error (EDE) Helpers (RFC 8914)
// =============================================================================

// ExtendedErrorCodeToString returns human-readable description for EDE code
func ExtendedErrorCodeToString(code uint16) string {
	switch code {
	case EDECodeOther:
		return "Other"
	case EDECodeUnsupportedDNSKEY:
		return "Unsupported DNSKEY Algorithm"
	case EDECodeUnsupportedDS:
		return "Unsupported DS Digest Type"
	case EDECodeStaleAnswer:
		return "Stale Answer"
	case EDECodeForgedAnswer:
		return "Forged Answer"
	case EDECodeDNSSECIndeterminate:
		return "DNSSEC Indeterminate"
	case EDECodeDNSSECBogus:
		return "DNSSEC Bogus"
	case EDECodeSignatureExpired:
		return "Signature Expired"
	case EDECodeSignatureNotYetValid:
		return "Signature Not Yet Valid"
	case EDECodeDNSKEYMissing:
		return "DNSKEY Missing"
	case EDECodeRRSIGsMissing:
		return "RRSIGs Missing"
	case EDECodeNoZoneKeyBitSet:
		return "No Zone Key Bit Set"
	case EDECodeNSECMissing:
		return "NSEC Missing"
	case EDECodeCachedError:
		return "Cached Error"
	case EDECodeNotReady:
		return "Not Ready"
	case EDECodeBlocked:
		return "Blocked"
	case EDECodeCensored:
		return "Censored"
	case EDECodeFiltered:
		return "Filtered"
	case EDECodeProhibited:
		return "Prohibited"
	case EDECodeStaleNSAnswer:
		return "Stale NS Answer"
	case EDECodeUnknownRCODE:
		return "Unknown RCODE"
	case EDECodeNotAuth:
		return "Not Authoritative"
	case EDECodeNotSupported:
		return "Not Supported"
	case EDECodeNoReachableAuthority:
		return "No Reachable Authority"
	case EDECodeNetworkError:
		return "Network Error"
	case EDECodeInvalidData:
		return "Invalid Data"
	default:
		return fmt.Sprintf("Unknown Error (%d)", code)
	}
}

// NewEDEOption creates a new EDE option
func NewEDEOption(infoCode uint16, extraText string) *EDEOption {
	return &EDEOption{
		InfoCode:  infoCode,
		ExtraText: extraText,
	}
}

// NewEDEWithError creates EDE option from an error
func NewEDEWithError(infoCode uint16, err error) *EDEOption {
	if err == nil {
		return nil
	}
	return &EDEOption{
		InfoCode:  infoCode,
		ExtraText: err.Error(),
	}
}
