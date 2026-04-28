// Package main implements ZJDNS - High Performance DNS Server
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	DefaultECSv4Len = 24 // Default ECS prefix length for IPv4 (RFC 7871 recommends /24 for IPv4)
	DefaultECSv6Len = 64 // Default ECS prefix length for IPv6 (RFC 7871 recommends /64 for IPv6)
	DefaultECSScope = 0  // Default ECS scope prefix length (0 means no scope)

	PaddingSize = 468 // Target size for padded DNS messages (RFC 7830 recommends at least 256 bytes, 468 is a common choice for better security)

	DefaultCookieClientLen = 8  // 8 bytes client cookie
	DefaultCookieServerLen = 16 // 16 bytes server cookie (recommended)
	MaxCookieServerLen     = 32 // 32 bytes max server cookie
)

// Extended DNS Error codes (RFC 8914)
/*
	0 - 24 - Defined
	25-49151 - Unassigned
	49152-65535 - Reserved for Private Use
*/
const (
	EDECodeOtherError                 uint16 = 0
	EDECodeUnsupportedDNSKEYAlgorithm uint16 = 1
	EDECodeUnsupportedDSDigestType    uint16 = 2
	EDECodeStaleAnswer                uint16 = 3
	EDECodeForgedAnswer               uint16 = 4
	EDECodeDNSSECIndeterminate        uint16 = 5
	EDECodeDNSSECBogus                uint16 = 6
	EDECodeSignatureExpired           uint16 = 7
	EDECodeSignatureNotYetValid       uint16 = 8
	EDECodeDNSKEYMissing              uint16 = 9
	EDECodeRRSIGsMissing              uint16 = 10
	EDECodeNoZoneKeyBitSet            uint16 = 11
	EDECodeNSECMissing                uint16 = 12
	EDECodeCachedError                uint16 = 13
	EDECodeNotReady                   uint16 = 14
	EDECodeBlocked                    uint16 = 15
	EDECodeCensored                   uint16 = 16
	EDECodeFiltered                   uint16 = 17
	EDECodeProhibited                 uint16 = 18
	EDECodeStaleNXDomainAnswer        uint16 = 19
	EDECodeNotAuthoritative           uint16 = 20
	EDECodeNotSupported               uint16 = 21
	EDECodeNoReachableAuthority       uint16 = 22
	EDECodeNetworkError               uint16 = 23
	EDECodeInvalidData                uint16 = 24
)

// CookieGenerator handles DNS cookie generation and validation
type CookieGenerator struct {
	secret         []byte // Current HMAC secret
	previousSecret []byte // Previous secret for seamless rotation
}

// CookieOption represents the DNS Cookie option with client and server cookies
type CookieOption struct {
	ClientCookie []byte
	ServerCookie []byte
}

// EDEOption represents the Extended DNS Error option with an info code and extra text
type EDEOption struct {
	InfoCode  uint16
	ExtraText string
}

// ECSOption represents the EDNS Client Subnet option with address, family, and prefix lengths
type ECSOption struct {
	Address      net.IP
	Family       uint16
	SourcePrefix uint8
	ScopePrefix  uint8
}

// EDNSManager handles EDNS option parsing and construction for DNS messages
type EDNSManager struct {
	defaultECS      *ECSOption
	detector        *IPDetector
	cookieGenerator *CookieGenerator
}

// IPDetector is responsible for detecting the server's public IP address for ECS auto-configuration
type IPDetector struct {
	httpClient *http.Client
}

// detectPublicIP detects the public IP address using Cloudflare's trace service.
func (d *IPDetector) detectPublicIP(forceIPv6 bool) net.IP {
	if d == nil {
		return nil
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: DefaultTimeout}
			if forceIPv6 {
				return dialer.DialContext(ctx, "tcp6", addr)
			}
			return dialer.DialContext(ctx, "tcp4", addr)
		},
	}

	client := &http.Client{Timeout: OperationTimeout, Transport: transport}
	defer transport.CloseIdleConnections()

	resp, err := client.Get("https://api.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	re := regexp.MustCompile(`ip=([^\s\n]+)`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) < 2 {
		return nil
	}

	ip := net.ParseIP(matches[1])
	if ip == nil {
		return nil
	}

	if forceIPv6 && ip.To4() != nil {
		return nil
	}
	if !forceIPv6 && ip.To4() == nil {
		return nil
	}

	return ip
}

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
	if em == nil || msg == nil || msg.Extra == nil {
		return nil
	}

	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}

	for _, option := range opt.Option {
		if subnet, ok := option.(*dns.EDNS0_SUBNET); ok {
			LogDebug("EDNS: extracted ECS subnet %s/%d scope=%d", subnet.Address, subnet.SourceNetmask, subnet.SourceScope)
			return &ECSOption{
				Family:       subnet.Family,
				SourcePrefix: subnet.SourceNetmask,
				ScopePrefix:  subnet.SourceScope,
				Address:      subnet.Address,
			}
		}
	}
	return nil
}

// ParseCookie extracts DNS Cookie option from a DNS message
func (em *EDNSManager) ParseCookie(msg *dns.Msg) *CookieOption {
	if em == nil || msg == nil || msg.Extra == nil {
		return nil
	}

	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}

	for _, option := range opt.Option {
		if cookie, ok := option.(*dns.EDNS0_COOKIE); ok {
			cookieHex := cookie.Cookie
			cookieBytes, _ := hex.DecodeString(cookieHex)

			if len(cookieBytes) < DefaultCookieClientLen {
				LogDebug("EDNS: invalid COOKIE option, too short=%d bytes", len(cookieBytes))
				return nil
			}

			clientCookie := cookieBytes[:DefaultCookieClientLen]
			var serverCookie []byte
			if len(cookieBytes) > DefaultCookieClientLen {
				serverCookie = cookieBytes[DefaultCookieClientLen:]
			}
			LogDebug("EDNS: extracted COOKIE client=%x server=%x", clientCookie, serverCookie)
			return &CookieOption{
				ClientCookie: clientCookie,
				ServerCookie: serverCookie,
			}
		}
	}
	return nil
}

// ParseEDE extracts EDE (Extended DNS Error) option from a DNS message
func (em *EDNSManager) ParseEDE(msg *dns.Msg) *EDEOption {
	if em == nil || msg == nil || msg.Extra == nil {
		return nil
	}

	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}

	for _, option := range opt.Option {
		if ede, ok := option.(*dns.EDNS0_EDE); ok {
			LogDebug("EDNS: extracted EDE code=%d (%s) extra=%q", ede.InfoCode, ExtendedErrorCodeToString(ede.InfoCode), ede.ExtraText)
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

	// Ensure message sections are initialized
	if msg.Question == nil {
		msg.Question = []dns.Question{}
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

	// Remove existing OPT records
	cleanExtra := make([]dns.RR, 0, len(msg.Extra))
	for _, rr := range msg.Extra {
		if rr != nil && rr.Header().Rrtype != dns.TypeOPT {
			cleanExtra = append(cleanExtra, rr)
		}
	}
	msg.Extra = cleanExtra

	// Create new OPT record
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  UDPBufferSize,
		},
	}

	opt.SetDo()

	var options []dns.EDNS0

	// Add ECS option if provided
	if ecs != nil {
		options = append(options, &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        ecs.Family,
			SourceNetmask: ecs.SourcePrefix,
			SourceScope:   DefaultECSScope,
			Address:       ecs.Address,
		})
	}

	// Add DNS Cookie option if provided
	if cookieStr != "" {
		options = append(options, &dns.EDNS0_COOKIE{
			Code:   dns.EDNS0COOKIE,
			Cookie: cookieStr,
		})
	}

	// Add EDE option if provided
	if ede != nil {
		options = append(options, &dns.EDNS0_EDE{
			InfoCode:  ede.InfoCode,
			ExtraText: ede.ExtraText,
		})
	}

	// Add padding for secure connections (RFC 7830)
	paddingBytes := 0
	if isSecureConnection {
		opt.Option = options
		msg.Extra = append(msg.Extra, opt)
		if wireData, err := msg.Pack(); err == nil {
			currentSize := len(wireData)
			if currentSize < PaddingSize {
				paddingDataSize := PaddingSize - currentSize - 4
				if paddingDataSize > 0 {
					paddingBytes = paddingDataSize
					options = append(options, &dns.EDNS0_PADDING{
						Padding: make([]byte, paddingDataSize),
					})
				}
			}
		}
		msg.Extra = msg.Extra[:len(msg.Extra)-1]
	}

	opt.Option = options
	msg.Extra = append(msg.Extra, opt)
	LogDebug("EDNS: built OPT secure=%t ecs=%t cookie=%t ede=%t padding=%d bytes totalOptions=%d",
		isSecureConnection,
		ecs != nil,
		cookieStr != "",
		ede != nil,
		paddingBytes,
		len(opt.Option))
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

// NewCookieGenerator creates a new cookie generator with a random secret
func NewCookieGenerator() *CookieGenerator {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		// Fallback: use timestamp-based secret if crypto/rand fails
		secret = []byte(fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Unix()))
	}
	return &CookieGenerator{secret: secret}
}

// RotateSecret replaces the current secret and retains the previous secret
// so already-issued cookies remain valid across one rotation window.
func (cg *CookieGenerator) RotateSecret() {
	if cg == nil {
		return
	}

	newSecret := make([]byte, 32)
	if _, err := rand.Read(newSecret); err != nil {
		newSecret = []byte(fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Unix()))
	}
	cg.previousSecret = cg.secret
	cg.secret = newSecret
}

// GenerateServerCookie generates a server cookie.
// The server cookie is an HMAC of clientIP and clientCookie, truncated to 16 bytes.
func (cg *CookieGenerator) GenerateServerCookie(clientIP net.IP, clientCookie []byte) []byte {
	if cg == nil || len(clientCookie) != DefaultCookieClientLen {
		return nil
	}

	if clientIP == nil {
		clientIP = net.ParseIP("0.0.0.0")
	}
	clientIP = clientIP.To16()

	data := make([]byte, 0, len(clientIP)+len(clientCookie))
	data = append(data, clientIP...)
	data = append(data, clientCookie...)

	h := hmac.New(sha256.New, cg.secret)
	h.Write(data)
	mac := h.Sum(nil)

	serverCookie := make([]byte, DefaultCookieServerLen)
	copy(serverCookie, mac[:DefaultCookieServerLen])

	return serverCookie
}

// ValidateServerCookie verifies a server cookie using the current secret
// or the previous secret when the server secret has rotated.
func (cg *CookieGenerator) ValidateServerCookie(clientIP net.IP, clientCookie, serverCookie []byte) bool {
	if cg == nil || len(clientCookie) != DefaultCookieClientLen || len(serverCookie) != DefaultCookieServerLen {
		return false
	}

	if clientIP == nil {
		clientIP = net.ParseIP("0.0.0.0")
	}
	clientIP = clientIP.To16()

	data := make([]byte, 0, len(clientIP)+len(clientCookie))
	data = append(data, clientIP...)
	data = append(data, clientCookie...)

	h := hmac.New(sha256.New, cg.secret)
	h.Write(data)
	if hmac.Equal(serverCookie, h.Sum(nil)[:DefaultCookieServerLen]) {
		return true
	}

	if len(cg.previousSecret) > 0 {
		hPrev := hmac.New(sha256.New, cg.previousSecret)
		hPrev.Write(data)
		return hmac.Equal(serverCookie, hPrev.Sum(nil)[:DefaultCookieServerLen])
	}

	return false
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

// Extended DNS Error (EDE) Helpers (RFC 8914)

// ExtendedErrorCodeToString returns human-readable description for EDE code
func ExtendedErrorCodeToString(code uint16) string {
	switch code {
	case EDECodeOtherError:
		return "Other Error"
	case EDECodeUnsupportedDNSKEYAlgorithm:
		return "Unsupported DNSKEY Algorithm"
	case EDECodeUnsupportedDSDigestType:
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
	case EDECodeStaleNXDomainAnswer:
		return "Stale NXDOMAIN Answer"
	case EDECodeNotAuthoritative:
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
