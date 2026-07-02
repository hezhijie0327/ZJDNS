package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// ECSModeAuto is the sentinel value for auto-detection of ECS subnets.
const ECSModeAuto = "auto"

// ECSConfig holds the default ECS subnet configuration for IPv4 and
// IPv6.
type ECSConfig struct {
	IPv4          string
	IPv6          string
	PreferIPv4    bool
	AutoDetectURL string `json:"auto_detect_url,omitempty"` // optional custom URL for auto-detection
}

// IsEmpty returns true if neither IPv4 nor IPv6 is configured.
func (c ECSConfig) IsEmpty() bool {
	return c.IPv4 == "" && c.IPv6 == ""
}

// HasAuto returns true if either IPv4 or IPv6 is set to the auto-detection
// value.
func (c ECSConfig) HasAuto() bool {
	return IsAutoECSValue(c.IPv4) || IsAutoECSValue(c.IPv6)
}

// ValueForQType returns the ECS subnet string appropriate for the given query
// type.
func (c ECSConfig) ValueForQType(qtype uint16) string {
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
func (c ECSConfig) Validate() error {
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

// UnmarshalJSON implements json.Unmarshaler for ECSConfig.
func (c *ECSConfig) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] != '{' {
		return fmt.Errorf("default_ecs_subnet must be an object")
	}
	var aux struct {
		IPv4          string `json:"ipv4"`
		IPv6          string `json:"ipv6"`
		PreferIPv4    bool   `json:"prefer_ipv4"`
		AutoDetectURL string `json:"auto_detect_url"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	c.IPv4 = strings.TrimSpace(aux.IPv4)
	c.IPv6 = strings.TrimSpace(aux.IPv6)
	c.AutoDetectURL = strings.TrimSpace(aux.AutoDetectURL)
	if !strings.Contains(string(data), `"prefer_ipv4"`) {
		c.PreferIPv4 = true
	} else {
		c.PreferIPv4 = aux.PreferIPv4
	}
	return nil
}

// MarshalJSON implements json.Marshaler for ECSConfig.
func (c ECSConfig) MarshalJSON() ([]byte, error) {
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

// IsAutoECSValue reports whether an ECS value is the auto-detection sentinel.
func IsAutoECSValue(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), ECSModeAuto)
}

func validateECSConfigValue(value string) error {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == ECSModeAuto {
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
