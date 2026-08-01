package edns

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"zjdns/config"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// ECSOption is an alias for config.ECSOption, kept here for compatibility
// with packages that already depend on the edns package.
type ECSOption = config.ECSOption

// ECS prefix length constants.
const (
	DefaultECSv4Len = 24
	DefaultECSv6Len = 56 // RFC 7871 §11.1: 56 bits recommended for IPv6
	DefaultECSScope = 0
)

// ParseFromDNS extracts the ECS option from a DNS message's OPT record.
func (h *Handler) ParseFromDNS(msg *dns.Msg) *ECSOption {
	if h == nil || msg == nil {
		return nil
	}
	for _, rr := range msg.Pseudo {
		if subnet, ok := rr.(*dns.SUBNET); ok {
			ecs := &ECSOption{
				Family:       subnet.Family,
				SourcePrefix: subnet.Netmask,
				ScopePrefix:  subnet.Scope,
				Address:      netipToIP(subnet.Address),
			}
			ecs.Normalize()
			return ecs
		}
	}
	return nil
}

// ECSForQType returns the default ECS option appropriate for the given
// query type.
func (h *Handler) ECSForQType(qtype uint16) *ECSOption {
	if h == nil || h.defaultECSConfig.IsEmpty() {
		return nil
	}
	if qtype == dns.TypeA {
		if ecs := h.defaultECSIPv4.Load(); ecs != nil {
			return ecs
		}
		return h.defaultECSIPv6.Load()
	}
	if qtype == dns.TypeAAAA {
		if ecs := h.defaultECSIPv6.Load(); ecs != nil {
			return ecs
		}
		return h.defaultECSIPv4.Load()
	}
	if h.defaultECSConfig.PreferIPv4 {
		if ecs := h.defaultECSIPv4.Load(); ecs != nil {
			return ecs
		}
		return h.defaultECSIPv6.Load()
	}
	if ecs := h.defaultECSIPv6.Load(); ecs != nil {
		return ecs
	}
	return h.defaultECSIPv4.Load()
}

// ShouldRefreshDefaultECS reports whether any ECS value uses auto-detection
// and should be refreshed.
func (h *Handler) ShouldRefreshDefaultECS() bool {
	if h == nil {
		return false
	}
	return h.defaultECSConfig.HasAuto()
}

// RefreshDefaultECS re-evaluates auto-detected ECS values and updates them if
// they changed.
func (h *Handler) RefreshDefaultECS() (options []*ECSOption, updated bool, err error) {
	if h == nil {
		return nil, false, errors.New("EDNS handler is not initialized")
	}
	if h.defaultECSConfig.IsEmpty() {
		return nil, false, nil
	}

	var changed bool
	var changedECS []*ECSOption
	var firstErr error

	if h.defaultECSConfig.IPv4 != "" {
		ecs, err := h.parseECSConfig(h.defaultECSConfig.IPv4, false)
		if err != nil {
			firstErr = fmt.Errorf("refresh IPv4 ECS: %w", err)
		} else if ecs != nil {
			old := h.defaultECSIPv4.Load()
			if !isECSOptionEqual(old, ecs) {
				h.defaultECSIPv4.Store(ecs)
				changed = true
				changedECS = append(changedECS, ecs)
			}
		}
	}
	if h.defaultECSConfig.IPv6 != "" {
		ecs, err := h.parseECSConfig(h.defaultECSConfig.IPv6, true)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("refresh IPv6 ECS: %w", err)
			} else {
				firstErr = fmt.Errorf("%w; refresh IPv6 ECS: %w", firstErr, err)
			}
		} else if ecs != nil {
			old := h.defaultECSIPv6.Load()
			if !isECSOptionEqual(old, ecs) {
				h.defaultECSIPv6.Store(ecs)
				changed = true
				changedECS = append(changedECS, ecs)
			}
		}
	}

	return changedECS, changed, firstErr
}

func isECSOptionEqual(a, b *ECSOption) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Address.Equal(b.Address) && a.Family == b.Family &&
		a.SourcePrefix == b.SourcePrefix && a.ScopePrefix == b.ScopePrefix
}

func (h *Handler) parseECSConfig(subnet string, forceIPv6 bool) (*ECSOption, error) {
	subnet = strings.ToLower(strings.TrimSpace(subnet))
	if subnet == config.ECSModeAuto {
		ecs := h.detectVia(forceIPv6, false)
		if ecs == nil {
			// A broken/unreachable AutoDetectURL would otherwise leave the
			// default ECS unset forever with no diagnostic.
			return nil, errors.New("ECS auto-detection returned no address")
		}
		return ecs, nil
	}
	if _, ipNet, err := net.ParseCIDR(subnet); err == nil {
		// Mask.Size() always succeeds for a successfully parsed CIDR.
		prefix, _ := ipNet.Mask.Size()
		family := uint16(dnsutil.IPv4Family)
		if ipNet.IP.To4() == nil {
			family = uint16(dnsutil.IPv6Family)
		}
		if forceIPv6 && family == dnsutil.IPv4Family {
			return nil, fmt.Errorf("expected IPv6 ECS value, got IPv4: %s", subnet)
		}
		if !forceIPv6 && family == dnsutil.IPv6Family {
			return nil, fmt.Errorf("expected IPv4 ECS value, got IPv6: %s", subnet)
		}
		ecs := &ECSOption{Family: family, SourcePrefix: uint8(prefix), ScopePrefix: DefaultECSScope, Address: ipNet.IP} //nolint:gosec // G115: CIDR prefix — 0-128 fits uint8
		ecs.Normalize()
		return ecs, nil
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
	family := uint16(dnsutil.IPv4Family)
	prefix := uint8(DefaultECSv4Len)
	if ip.To4() == nil {
		family = uint16(dnsutil.IPv6Family)
		prefix = DefaultECSv6Len
	}
	ecs := &ECSOption{Family: family, SourcePrefix: prefix, ScopePrefix: DefaultECSScope, Address: ip}
	ecs.Normalize()
	return ecs, nil
}

// detectVia resolves ECS options via IP detection. allowFallback is reserved
// for future IPv4→IPv6 fallback support and is currently always false.
func (h *Handler) detectVia(forceIPv6, allowFallback bool) *ECSOption {
	var ip net.IP
	if forceIPv6 {
		ip = h.detector.IPv6()
	} else {
		ip = h.detector.IPv4()
	}
	if ip == nil && allowFallback && !forceIPv6 {
		ip = h.detector.IPv6()
	}
	if ip == nil {
		return nil
	}
	family := uint16(dnsutil.IPv4Family)
	prefix := uint8(DefaultECSv4Len)
	if ip.To4() == nil {
		family = uint16(dnsutil.IPv6Family)
		prefix = DefaultECSv6Len
	}
	ecs := &ECSOption{Family: family, SourcePrefix: prefix, ScopePrefix: DefaultECSScope, Address: ip}
	ecs.Normalize()
	return ecs
}

// VerifyECSResponse checks that the response ECS matches the query ECS per
// RFC 7871 §7.3. Returns false if FAMILY, SOURCE PREFIX-LENGTH, or ADDRESS
// bits differ — the response MUST be dropped (§11.2).
func VerifyECSResponse(query, response *ECSOption) bool {
	if query == nil || response == nil {
		return true // nothing to verify
	}
	if query.Family != response.Family {
		return false
	}
	if query.SourcePrefix != response.SourcePrefix {
		return false
	}
	if query.SourcePrefix == 0 {
		return true // /0 prefix — no address bits to compare
	}
	// Compare only the significant bits of the address
	addrLen := len(query.Address)
	if addrLen != len(response.Address) {
		return false
	}
	// A wire-supplied SourcePrefix larger than the address width would index
	// past the slice end below; degrade to 'mismatch' instead of panicking.
	if int(query.SourcePrefix) > len(query.Address)*8 || int(response.SourcePrefix) > len(response.Address)*8 {
		return false
	}
	fullBytes := int(query.SourcePrefix) / 8
	if fullBytes > 0 {
		for i := range fullBytes {
			if query.Address[i] != response.Address[i] {
				return false
			}
		}
	}
	remainBits := int(query.SourcePrefix) % 8
	if remainBits > 0 && fullBytes < addrLen {
		mask := byte(0xFF << (8 - remainBits))
		if query.Address[fullBytes]&mask != response.Address[fullBytes]&mask {
			return false
		}
	}
	return true
}
