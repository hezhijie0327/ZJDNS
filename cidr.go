// Package main implements ZJDNS - High Performance DNS Server
package main

import (
	"bufio"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"slices"
	"strings"
)

// =============================================================================
// CIDRManager Implementation
// =============================================================================

// NewCIDRManager creates a new CIDR manager from the provided configurations
func NewCIDRManager(configs []CIDRConfig) (*CIDRManager, error) {
	cm := &CIDRManager{}
	rules := make(map[string]*CIDRRule)
	matchCache := make(map[string]*CIDRMatchInfo)
	cm.rules.Store(rules)
	cm.matchCache.Store(matchCache)

	for _, config := range configs {
		if config.Tag == "" {
			return nil, errors.New("CIDR tag cannot be empty")
		}
		if _, exists := rules[config.Tag]; exists {
			return nil, fmt.Errorf("duplicate CIDR tag: %s", config.Tag)
		}

		rule, err := cm.loadCIDRConfig(config)
		if err != nil {
			return nil, fmt.Errorf("load CIDR config for tag '%s': %w", config.Tag, err)
		}
		rules[config.Tag] = rule

		sourceInfo := ""
		if config.File != "" && len(config.Rules) > 0 {
			sourceInfo = fmt.Sprintf("%s + %d inline rules", config.File, len(config.Rules))
		} else if config.File != "" {
			sourceInfo = config.File
		} else {
			sourceInfo = fmt.Sprintf("%d inline rules", len(config.Rules))
		}
		LogInfo("CIDR: Loaded tag=%s, source=%s, total=%d", config.Tag, sourceInfo, len(rule.nets))
	}

	cm.rules.Store(rules)
	return cm, nil
}

// loadCIDRConfig loads CIDR rules from file and inline configuration
func (cm *CIDRManager) loadCIDRConfig(config CIDRConfig) (*CIDRRule, error) {
	rule := &CIDRRule{tag: config.Tag, nets: make([]*net.IPNet, 0)}
	validCount := 0

	// Process inline rules
	for i, cidr := range config.Rules {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" || strings.HasPrefix(cidr, "#") {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			LogWarn("CIDR: Invalid CIDR in rules[%d] for tag '%s': %s - %v", i, config.Tag, cidr, err)
			continue
		}
		rule.nets = append(rule.nets, ipNet)
		validCount++
	}

	// Process file if specified
	if config.File != "" {
		if !IsValidFilePath(config.File) {
			return nil, fmt.Errorf("invalid file path: %s", config.File)
		}
		f, err := os.Open(config.File)
		if err != nil {
			return nil, fmt.Errorf("open CIDR file: %w", err)
		}
		defer func() { _ = f.Close() }()

		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			_, ipNet, err := net.ParseCIDR(line)
			if err != nil {
				LogWarn("CIDR: Invalid CIDR at %s:%d: %s - %v", config.File, lineNum, line, err)
				continue
			}
			rule.nets = append(rule.nets, ipNet)
			validCount++
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("scan CIDR file: %w", err)
		}
	}

	if validCount == 0 {
		return nil, fmt.Errorf("no valid CIDR entries for tag '%s'", config.Tag)
	}

	rule.preprocessNetworks()
	return rule, nil
}

// MatchIP checks if an IP address matches the specified CIDR tag
// Returns: matched (bool), exists (bool)
func (cm *CIDRManager) MatchIP(ip net.IP, matchTag string) (matched bool, exists bool) {
	if cm == nil || matchTag == "" {
		return true, true
	}

	matchInfo := cm.getMatchInfo(matchTag)
	if matchInfo == nil {
		return false, false
	}

	rules := cm.rules.Load().(map[string]*CIDRRule)
	rule, exists := rules[matchInfo.Tag]

	if !exists {
		return false, false
	}

	inList := rule.contains(ip)
	if matchInfo.Negate {
		return !inList, true
	}
	return inList, true
}

// getMatchInfo retrieves or creates match info for a tag, caching the result
func (cm *CIDRManager) getMatchInfo(matchTag string) *CIDRMatchInfo {
	matchCache := cm.matchCache.Load().(map[string]*CIDRMatchInfo)

	if info, exists := matchCache[matchTag]; exists {
		return info
	}

	negate := strings.HasPrefix(matchTag, "!")
	tag := strings.TrimPrefix(matchTag, "!")

	info := &CIDRMatchInfo{
		Tag:      tag,
		Negate:   negate,
		Original: matchTag,
	}

	newCache := make(map[string]*CIDRMatchInfo, len(matchCache)+1)
	maps.Copy(newCache, matchCache)
	newCache[matchTag] = info
	cm.matchCache.Store(newCache)

	return info
}

// =============================================================================
// CIDRRule Implementation
// =============================================================================

// preprocessNetworks optimizes network storage for fast IP matching
func (r *CIDRRule) preprocessNetworks() {
	if r == nil {
		return
	}

	r.totalNets = len(r.nets)
	r.ipv4Nets = make([]ipv4Net, 0, r.totalNets)
	r.ipv6Nets = make([]*net.IPNet, 0, r.totalNets)

	for _, ipNet := range r.nets {
		if ipNet == nil {
			continue
		}

		if ipNet.IP.To4() != nil {
			if ipv4Net := toIPv4Net(ipNet); ipv4Net != nil {
				r.ipv4Nets = append(r.ipv4Nets, *ipv4Net)
			}
		} else {
			r.ipv6Nets = append(r.ipv6Nets, ipNet)
		}
	}

	// Sort IPv4 networks by prefix length (longest first for more specific matches)
	slices.SortFunc(r.ipv4Nets, func(a, b ipv4Net) int {
		if a.prefix != b.prefix {
			return int(b.prefix) - int(a.prefix)
		}
		return 0
	})
}

// toIPv4Net converts a net.IPNet to an optimized ipv4Net structure
func toIPv4Net(ipNet *net.IPNet) *ipv4Net {
	if ipNet == nil || ipNet.IP.To4() == nil {
		return nil
	}

	ipv4 := ipNet.IP.To4()
	if ipv4 == nil {
		return nil
	}

	ipUint := uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])

	maskSize, _ := ipNet.Mask.Size()
	var maskUint uint32
	if maskSize <= 32 {
		maskUint = ^uint32(0) << (32 - maskSize)
	}

	return &ipv4Net{
		ip:     ipUint & maskUint,
		mask:   maskUint,
		prefix: uint8(maskSize),
	}
}

// contains checks if an IP address is within any of the rule's networks
func (r *CIDRRule) contains(ip net.IP) bool {
	if r == nil || ip == nil {
		return false
	}

	if ipv4 := ip.To4(); ipv4 != nil {
		return r.containsIPv4(ipv4)
	}

	return r.containsIPv6(ip)
}

// containsIPv4 checks if an IPv4 address is within any of the rule's IPv4 networks
func (r *CIDRRule) containsIPv4(ipv4 net.IP) bool {
	if len(r.ipv4Nets) == 0 {
		return false
	}

	ipUint := uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])

	for _, net := range r.ipv4Nets {
		if (ipUint & net.mask) == net.ip {
			return true
		}
	}

	return false
}

// containsIPv6 checks if an IPv6 address is within any of the rule's IPv6 networks
func (r *CIDRRule) containsIPv6(ip net.IP) bool {
	for _, ipNet := range r.ipv6Nets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}
