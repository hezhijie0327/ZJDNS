package edns

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// ECS prefix length constants.
const (
	DefaultECSv4Len = 24
	DefaultECSv6Len = 64
	DefaultECSScope = 0
)

// ECSOption represents an EDNS Client Subnet option with address and prefix
// information.
type ECSOption struct {
	Address      net.IP
	Family       uint16
	SourcePrefix uint8
	ScopePrefix  uint8
}

// DefaultECSConfig holds the default ECS subnet configuration for IPv4 and
// IPv6.
type DefaultECSConfig struct {
	IPv4       string
	IPv6       string
	PreferIPv4 bool
}

// IsEmpty returns true if neither IPv4 nor IPv6 is configured.
func (c DefaultECSConfig) IsEmpty() bool {
	return c.IPv4 == "" && c.IPv6 == ""
}

// HasAuto returns true if either IPv4 or IPv6 is set to the auto-detection
// value.
func (c DefaultECSConfig) HasAuto() bool {
	return isAutoECSValue(c.IPv4) || isAutoECSValue(c.IPv6)
}

// ValueForQType returns the ECS subnet string appropriate for the given query
// type.
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

// Validate checks that the ECS configuration contains valid subnet values.
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

// UnmarshalJSON implements json.Unmarshaler for DefaultECSConfig.
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
	if !strings.Contains(string(data), `"prefer_ipv4"`) {
		c.PreferIPv4 = true
	} else {
		c.PreferIPv4 = aux.PreferIPv4
	}
	return nil
}

// MarshalJSON implements json.Marshaler for DefaultECSConfig.
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

func isAutoECSValue(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "auto")
}

// ParseFromDNS extracts the ECS option from a DNS message's OPT record.
func (m *Handler) ParseFromDNS(msg *dns.Msg) *ECSOption {
	if m == nil || msg == nil || msg.Extra == nil {
		return nil
	}
	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, option := range opt.Option {
		if subnet, ok := option.(*dns.EDNS0_SUBNET); ok {
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

// DefaultECS returns the default ECS option, preferring IPv4 over IPv6.
func (m *Handler) DefaultECS() *ECSOption {
	if m == nil {
		return nil
	}
	if ecs := m.defaultECSIPv4.Load(); ecs != nil {
		return ecs
	}
	return m.defaultECSIPv6.Load()
}

// DefaultECSForQType returns the default ECS option appropriate for the given
// query type.
func (m *Handler) DefaultECSForQType(qtype uint16) *ECSOption {
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

// ShouldRefreshDefaultECS reports whether any ECS value uses auto-detection
// and should be refreshed.
func (m *Handler) ShouldRefreshDefaultECS() bool {
	if m == nil {
		return false
	}
	return m.defaultECSConfig.HasAuto()
}

// RefreshDefaultECS re-evaluates auto-detected ECS values and updates them if
// they changed.
func (m *Handler) RefreshDefaultECS() ([]*ECSOption, bool, error) {
	if m == nil {
		return nil, false, errors.New("EDNS handler is not initialized")
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

func ecsOptionEqual(a, b *ECSOption) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Address.Equal(b.Address) && a.Family == b.Family &&
		a.SourcePrefix == b.SourcePrefix && a.ScopePrefix == b.ScopePrefix
}

func (m *Handler) parseECSConfig(subnet string, forceIPv6 bool) (*ECSOption, error) {
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

func (m *Handler) detectVia(forceIPv6, allowFallback bool) (*ECSOption, error) {
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
