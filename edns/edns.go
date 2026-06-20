// Package edns provides EDNS(0) extension handling: ECS (Client Subnet),
// DNS Cookies (RFC 7873/9018), Extended DNS Errors (RFC 8914), and DNS
// Padding (RFC 7830).
package edns

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"zjdns/internal/ipdetect"
	"zjdns/internal/log"

	"github.com/miekg/dns"
)

// ──────────────────────────────────────────
// ECS / Cookie / EDE option types
// ──────────────────────────────────────────

// ECSOption represents an EDNS Client Subnet option.
type ECSOption struct {
	Address      net.IP
	Family       uint16
	SourcePrefix uint8
	ScopePrefix  uint8
}

// CookieOption represents the DNS Cookie option with client and server cookies.
type CookieOption struct {
	ClientCookie []byte
	ServerCookie []byte
}

// EDEOption represents an Extended DNS Error option.
type EDEOption struct {
	InfoCode  uint16
	ExtraText string
}

// ──────────────────────────────────────────
// Constants
// ──────────────────────────────────────────

const (
	DefaultECSv4Len = 24 // RFC 7871 recommended /24 for IPv4.
	DefaultECSv6Len = 64 // RFC 7871 recommended /64 for IPv6.
	DefaultECSScope = 0

	PaddingSize = 468 // RFC 7830 recommended minimum padding size.

	DefaultCookieClientLen = 8
	DefaultCookieServerLen = 16
	MaxCookieServerLen     = 32
)

// Extended DNS Error codes (RFC 8914).
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

// ──────────────────────────────────────────
// EDNS Manager
// ──────────────────────────────────────────

// Manager handles EDNS option parsing and construction for DNS messages.
type Manager struct {
	defaultECSIPv4   atomic.Pointer[ECSOption]
	defaultECSIPv6   atomic.Pointer[ECSOption]
	defaultECSConfig DefaultECSConfig
	detector         *ipdetect.Detector
	CookieGenerator  *CookieGenerator
}

// DefaultECSConfig mirrors config.DefaultECSConfig to avoid a dependency cycle.
type DefaultECSConfig struct {
	IPv4       string
	IPv6       string
	PreferIPv4 bool
}

// IsEmpty reports whether no ECS configuration is set.
func (c DefaultECSConfig) IsEmpty() bool {
	return c.IPv4 == "" && c.IPv6 == ""
}

// HasAuto reports whether either address family is set to auto-detect.
func (c DefaultECSConfig) HasAuto() bool {
	return isAutoECSValue(c.IPv4) || isAutoECSValue(c.IPv6)
}

// ValueForQType returns the ECS value appropriate for the given query type.
func (c DefaultECSConfig) ValueForQType(qtype uint16) string {
	if qtype == dns.TypeA {
		if c.IPv4 != "" {
			return c.IPv4
		}
		return c.IPv6
	}
	if qtype == dns.TypeAAAA {
		if c.IPv6 != "" {
			return c.IPv6
		}
		return c.IPv4
	}
	if c.PreferIPv4 {
		if c.IPv4 != "" {
			return c.IPv4
		}
		return c.IPv6
	}
	if c.IPv6 != "" {
		return c.IPv6
	}
	return c.IPv4
}

// Validate checks that the ECS config values are valid ("auto" or a CIDR).
func (c DefaultECSConfig) Validate() error {
	if c.IPv4 == "" && c.IPv6 == "" {
		return errors.New("default_ecs_subnet must specify ipv4 and/or ipv6")
	}
	if c.IPv4 != "" {
		if err := validateECSConfigValue(c.IPv4); err != nil {
			return fmt.Errorf("invalid default_ecs_subnet.ipv4: %w", err)
		}
	}
	if c.IPv6 != "" {
		if err := validateECSConfigValue(c.IPv6); err != nil {
			return fmt.Errorf("invalid default_ecs_subnet.ipv6: %w", err)
		}
	}
	return nil
}

// UnmarshalJSON handles empty/null values and trims whitespace from ECS strings.
func (c *DefaultECSConfig) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] != '{' {
		return fmt.Errorf("default_ecs_subnet must be an object")
	}
	var aux struct {
		IPv4       string `json:"ipv4"`
		IPv6       string `json:"ipv6"`
		PreferIPv4 bool   `json:"prefer_ipv4"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	c.IPv4 = strings.TrimSpace(aux.IPv4)
	c.IPv6 = strings.TrimSpace(aux.IPv6)
	// Default PreferIPv4 to true when the JSON omits the field,
	// matching getDefaultConfig(). Without this, Go's bool zero-value
	// (false) would silently override the default.
	if !strings.Contains(string(data), `"prefer_ipv4"`) {
		c.PreferIPv4 = true
	} else {
		c.PreferIPv4 = aux.PreferIPv4
	}
	return nil
}

// MarshalJSON omits empty ECS fields from JSON output.
func (c DefaultECSConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		IPv4       string `json:"ipv4,omitempty"`
		IPv6       string `json:"ipv6,omitempty"`
		PreferIPv4 bool   `json:"prefer_ipv4,omitempty"`
	}{
		IPv4:       c.IPv4,
		IPv6:       c.IPv6,
		PreferIPv4: c.PreferIPv4,
	})
}

func validateECSConfigValue(value string) error {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "auto" {
		return nil
	}
	if _, _, err := net.ParseCIDR(value); err == nil {
		return nil
	}
	if net.ParseIP(value) != nil {
		return nil
	}
	return fmt.Errorf("invalid ECS subnet value: %s", value)
}

// NewManager creates a new EDNS Manager.
func NewManager(defaultECS DefaultECSConfig) (*Manager, error) {
	mgr := &Manager{
		defaultECSConfig: defaultECS,
		detector:         &ipdetect.Detector{},
		CookieGenerator:  NewCookieGenerator(),
	}

	if !defaultECS.IsEmpty() {
		if defaultECS.IPv4 != "" {
			if isAutoECSValue(defaultECS.IPv4) {
				log.Infof("EDNS: Default ECS IPv4 set to auto; refresh will run in background")
			} else {
				ecs, err := mgr.parseECSConfig(defaultECS.IPv4, false)
				if err != nil {
					return nil, fmt.Errorf("parse default_ecs_subnet.ipv4: %w", err)
				}
				if ecs != nil {
					mgr.defaultECSIPv4.Store(ecs)
					log.Infof("EDNS: Default ECS IPv4: %s/%d", ecs.Address, ecs.SourcePrefix)
				}
			}
		}
		if defaultECS.IPv6 != "" {
			if isAutoECSValue(defaultECS.IPv6) {
				log.Infof("EDNS: Default ECS IPv6 set to auto; refresh will run in background")
			} else {
				ecs, err := mgr.parseECSConfig(defaultECS.IPv6, true)
				if err != nil {
					return nil, fmt.Errorf("parse default_ecs_subnet.ipv6: %w", err)
				}
				if ecs != nil {
					mgr.defaultECSIPv6.Store(ecs)
					log.Infof("EDNS: Default ECS IPv6: %s/%d", ecs.Address, ecs.SourcePrefix)
				}
			}
		}
	}

	return mgr, nil
}

// DefaultECS returns the first available default ECS option.
func (m *Manager) DefaultECS() *ECSOption {
	if m == nil {
		return nil
	}
	if ecs := m.defaultECSIPv4.Load(); ecs != nil {
		return ecs
	}
	return m.defaultECSIPv6.Load()
}

// DefaultECSForQType returns the default ECS for a specific question type.
func (m *Manager) DefaultECSForQType(qtype uint16) *ECSOption {
	if m == nil || m.defaultECSConfig.IsEmpty() {
		return nil
	}
	if qtype == dns.TypeA {
		if ecs := m.defaultECSIPv4.Load(); ecs != nil {
			return ecs
		}
		return m.defaultECSIPv6.Load()
	}
	if qtype == dns.TypeAAAA {
		if ecs := m.defaultECSIPv6.Load(); ecs != nil {
			return ecs
		}
		return m.defaultECSIPv4.Load()
	}
	if m.defaultECSConfig.PreferIPv4 {
		if ecs := m.defaultECSIPv4.Load(); ecs != nil {
			return ecs
		}
		return m.defaultECSIPv6.Load()
	}
	if ecs := m.defaultECSIPv6.Load(); ecs != nil {
		return ecs
	}
	return m.defaultECSIPv4.Load()
}

// ShouldRefreshDefaultECS reports whether auto ECS refresh is needed.
func (m *Manager) ShouldRefreshDefaultECS() bool {
	if m == nil {
		return false
	}
	return m.defaultECSConfig.HasAuto()
}

// RefreshDefaultECS re-detects public IPs for auto ECS modes.
func (m *Manager) RefreshDefaultECS() ([]*ECSOption, bool, error) {
	if m == nil {
		return nil, false, errors.New("EDNS manager is not initialized")
	}
	if m.defaultECSConfig.IsEmpty() {
		return nil, false, nil
	}

	var changed bool
	var changedECS []*ECSOption
	var firstErr error

	if m.defaultECSConfig.IPv4 != "" {
		ecs, err := m.parseECSConfig(m.defaultECSConfig.IPv4, false)
		if err != nil {
			firstErr = fmt.Errorf("refresh IPv4 ECS: %w", err)
		} else if ecs != nil {
			old := m.defaultECSIPv4.Load()
			if !ecsOptionEqual(old, ecs) {
				m.defaultECSIPv4.Store(ecs)
				changed = true
				changedECS = append(changedECS, ecs)
			}
		}
	}
	if m.defaultECSConfig.IPv6 != "" {
		ecs, err := m.parseECSConfig(m.defaultECSConfig.IPv6, true)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("refresh IPv6 ECS: %w", err)
			} else {
				firstErr = fmt.Errorf("%v; refresh IPv6 ECS: %w", firstErr, err)
			}
		} else if ecs != nil {
			old := m.defaultECSIPv6.Load()
			if !ecsOptionEqual(old, ecs) {
				m.defaultECSIPv6.Store(ecs)
				changed = true
				changedECS = append(changedECS, ecs)
			}
		}
	}

	return changedECS, changed, firstErr
}

// ParseFromDNS extracts the ECS option from a DNS message.
func (m *Manager) ParseFromDNS(msg *dns.Msg) *ECSOption {
	if m == nil || msg == nil || msg.Extra == nil {
		return nil
	}
	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, option := range opt.Option {
		if subnet, ok := option.(*dns.EDNS0_SUBNET); ok {
			log.Debugf("EDNS: extracted ECS subnet %s/%d scope=%d", subnet.Address, subnet.SourceNetmask, subnet.SourceScope)
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

// ParseCookie extracts the DNS Cookie option from a DNS message.
func (m *Manager) ParseCookie(msg *dns.Msg) *CookieOption {
	if m == nil || msg == nil || msg.Extra == nil {
		return nil
	}
	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, option := range opt.Option {
		if cookie, ok := option.(*dns.EDNS0_COOKIE); ok {
			cookieBytes, _ := hex.DecodeString(cookie.Cookie)
			if len(cookieBytes) < DefaultCookieClientLen {
				return nil
			}
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
	return nil
}

// ParseEDE extracts the EDE option from a DNS message.
func (m *Manager) ParseEDE(msg *dns.Msg) *EDEOption {
	if m == nil || msg == nil || msg.Extra == nil {
		return nil
	}
	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, option := range opt.Option {
		if ede, ok := option.(*dns.EDNS0_EDE); ok {
			return &EDEOption{
				InfoCode:  ede.InfoCode,
				ExtraText: ede.ExtraText,
			}
		}
	}
	return nil
}

// ApplyToMessage adds EDNS options (ECS, Cookie, EDE, Padding) to a DNS message.
func (m *Manager) ApplyToMessage(msg *dns.Msg, ecs *ECSOption, clientRequestedDNSSEC bool, isSecureConnection bool, cookieStr string, ede *EDEOption) {
	if m == nil || msg == nil {
		return
	}

	// Ensure message sections are initialized.
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

	// Remove existing OPT records.
	cleanExtra := make([]dns.RR, 0, len(msg.Extra))
	for _, rr := range msg.Extra {
		if rr != nil && rr.Header().Rrtype != dns.TypeOPT {
			cleanExtra = append(cleanExtra, rr)
		}
	}
	msg.Extra = cleanExtra

	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  1232, // EDNS0 UDP payload size.
		},
	}
	opt.SetDo()

	var options []dns.EDNS0

	if ecs != nil {
		options = append(options, &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        ecs.Family,
			SourceNetmask: ecs.SourcePrefix,
			SourceScope:   DefaultECSScope, // 0 = scope not set (RFC 7871: authoritative servers SHOULD set this)
			Address:       ecs.Address,
		})
	}

	if cookieStr != "" {
		options = append(options, &dns.EDNS0_COOKIE{
			Code:   dns.EDNS0COOKIE,
			Cookie: cookieStr,
		})
	}

	if ede != nil {
		options = append(options, &dns.EDNS0_EDE{
			InfoCode:  ede.InfoCode,
			ExtraText: ede.ExtraText,
		})
	}

	// Padding for secure connections (RFC 7830 §4).
	// Temporarily append the OPT (without padding) to get the exact wire
	// size via msg.Pack(), then calculate correct padding to reach the
	// next PaddingSize block boundary. Avoids msg.Copy() by mutating and
	// restoring msg.Extra.
	paddingBytes := 0
	if isSecureConnection {
		tmpOpt := &dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeOPT,
				Class:  1232,
			},
		}
		tmpOpt.Option = options
		savedExtra := msg.Extra
		msg.Extra = append(msg.Extra, tmpOpt)
		if packed, err := msg.Pack(); err == nil {
			currentSize := len(packed)
			targetSize := ((currentSize + PaddingSize - 1) / PaddingSize) * PaddingSize
			// Subtract 4 for the PADDING option header (2-byte code + 2-byte length).
			paddingDataSize := targetSize - currentSize - 4
			if paddingDataSize > 0 {
				paddingBytes = paddingDataSize
				options = append(options, &dns.EDNS0_PADDING{
					Padding: make([]byte, paddingDataSize),
				})
			}
		}
		msg.Extra = savedExtra
	}

	opt.Option = options
	msg.Extra = append(msg.Extra, opt)

	log.Debugf("EDNS: built OPT secure=%t ecs=%t cookie=%t ede=%t padding=%d bytes",
		isSecureConnection, ecs != nil, cookieStr != "", ede != nil, paddingBytes)
}

// ──────────────────────────────────────────
// Cookie Generator
// ──────────────────────────────────────────

// CookieGenerator handles DNS cookie generation and validation.
type CookieGenerator struct {
	mu             sync.RWMutex
	secret         []byte
	previousSecret []byte
}

// NewCookieGenerator creates a new cookie generator with a random 32-byte secret.
func NewCookieGenerator() *CookieGenerator {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic(fmt.Sprintf("EDNS: failed to generate cookie secret: %v (system CSPRNG unavailable)", err))
	}
	return &CookieGenerator{secret: secret}
}

// RotateSecret replaces the current secret and retains the previous one.
func (cg *CookieGenerator) RotateSecret() {
	if cg == nil {
		return
	}
	newSecret := make([]byte, 32)
	if _, err := rand.Read(newSecret); err != nil {
		panic(fmt.Sprintf("EDNS: failed to rotate cookie secret: %v (system CSPRNG unavailable)", err))
	}
	cg.mu.Lock()
	cg.previousSecret = cg.secret
	cg.secret = newSecret
	cg.mu.Unlock()
}

// GenerateServerCookie creates an HMAC-SHA256 server cookie.
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

	cg.mu.RLock()
	h := hmac.New(sha256.New, cg.secret)
	cg.mu.RUnlock()
	h.Write(data)
	mac := h.Sum(nil)

	serverCookie := make([]byte, DefaultCookieServerLen)
	copy(serverCookie, mac[:DefaultCookieServerLen])
	return serverCookie
}

// ValidateServerCookie verifies a server cookie (current or previous secret).
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

	cg.mu.RLock()
	h := hmac.New(sha256.New, cg.secret)
	prevLen := len(cg.previousSecret)
	var prevSecret []byte
	if prevLen > 0 {
		prevSecret = make([]byte, prevLen)
		copy(prevSecret, cg.previousSecret)
	}
	cg.mu.RUnlock()

	h.Write(data)
	if hmac.Equal(serverCookie, h.Sum(nil)[:DefaultCookieServerLen]) {
		return true
	}
	if prevLen > 0 {
		hPrev := hmac.New(sha256.New, prevSecret)
		hPrev.Write(data)
		return hmac.Equal(serverCookie, hPrev.Sum(nil)[:DefaultCookieServerLen])
	}
	return false
}

// GenerateClientCookie generates an 8-byte client cookie.
func (cg *CookieGenerator) GenerateClientCookie(clientIP net.IP) []byte {
	clientCookie := make([]byte, DefaultCookieClientLen)
	h := hmac.New(sha256.New, cg.secret)
	h.Write(clientIP)
	h.Write([]byte("client"))
	copy(clientCookie, h.Sum(nil))
	return clientCookie
}

// BuildCookieResponse builds the cookie string for DNS responses: hex(client||server).
func BuildCookieResponse(clientCookie, serverCookie []byte) string {
	if len(clientCookie) != DefaultCookieClientLen {
		return ""
	}
	cookie := make([]byte, 0, len(clientCookie)+len(serverCookie))
	cookie = append(cookie, clientCookie...)
	cookie = append(cookie, serverCookie...)
	return hex.EncodeToString(cookie)
}

// ──────────────────────────────────────────
// EDE helpers
// ──────────────────────────────────────────

// NewEDEOption creates a new EDE option.
func NewEDEOption(infoCode uint16, extraText string) *EDEOption {
	return &EDEOption{InfoCode: infoCode, ExtraText: extraText}
}

// NewEDEWithError creates an EDE option from an error.
func NewEDEWithError(infoCode uint16, err error) *EDEOption {
	if err == nil {
		return nil
	}
	return &EDEOption{InfoCode: infoCode, ExtraText: err.Error()}
}

// EDECodeString returns a human-readable description for an EDE code.
func EDECodeString(code uint16) string {
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

// ──────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────

func isAutoECSValue(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "auto")
}

func ecsOptionEqual(a, b *ECSOption) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Address.Equal(b.Address) && a.Family == b.Family &&
		a.SourcePrefix == b.SourcePrefix && a.ScopePrefix == b.ScopePrefix
}

func (m *Manager) parseECSConfig(subnet string, forceIPv6 bool) (*ECSOption, error) {
	subnet = strings.ToLower(strings.TrimSpace(subnet))
	if subnet == "auto" {
		return m.detectVia(forceIPv6, false)
	}
	if _, ipNet, err := net.ParseCIDR(subnet); err == nil {
		prefix, _ := ipNet.Mask.Size()
		family := uint16(1)
		if ipNet.IP.To4() == nil {
			family = 2
		}
		if forceIPv6 && family == 1 {
			return nil, fmt.Errorf("expected IPv6 ECS value, got IPv4: %s", subnet)
		}
		if !forceIPv6 && family == 2 {
			return nil, fmt.Errorf("expected IPv4 ECS value, got IPv6: %s", subnet)
		}
		return &ECSOption{Family: family, SourcePrefix: uint8(prefix), ScopePrefix: DefaultECSScope, Address: ipNet.IP}, nil
	}
	ip := net.ParseIP(subnet)
	if ip == nil {
		return nil, fmt.Errorf("parse IP or CIDR: %s", subnet)
	}
	if forceIPv6 && ip.To4() != nil {
		return nil, fmt.Errorf("expected IPv6 ECS value, got IPv4: %s", subnet)
	}
	if !forceIPv6 && ip.To4() == nil {
		return nil, fmt.Errorf("expected IPv4 ECS value, got IPv6: %s", subnet)
	}
	family := uint16(1)
	prefix := uint8(DefaultECSv4Len)
	if ip.To4() == nil {
		family = 2
		prefix = DefaultECSv6Len
	}
	return &ECSOption{Family: family, SourcePrefix: prefix, ScopePrefix: DefaultECSScope, Address: ip}, nil
}

// detectVia delegates to ipdetect for public IP detection.
func (m *Manager) detectVia(forceIPv6, allowFallback bool) (*ECSOption, error) {
	var ip net.IP
	if forceIPv6 {
		ip = m.detector.IPv6()
	} else {
		ip = m.detector.IPv4()
	}
	if ip == nil && allowFallback && !forceIPv6 {
		ip = m.detector.IPv6()
	}
	if ip == nil {
		return nil, nil
	}
	family := uint16(1)
	prefix := uint8(DefaultECSv4Len)
	if ip.To4() == nil {
		family = 2
		prefix = DefaultECSv6Len
	}
	return &ECSOption{Family: family, SourcePrefix: prefix, ScopePrefix: DefaultECSScope, Address: ip}, nil
}
