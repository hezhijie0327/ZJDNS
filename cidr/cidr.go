// Package cidr provides IP filtering using CIDR rules with tag matching.
package cidr

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"

	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
)

// ErrEmptyTag is returned when a CIDR tag is empty.
var ErrEmptyTag = errors.New("CIDR tag cannot be empty")

// CIDRRule holds a set of parsed CIDR networks for a single tag.
type CIDRRule struct {
	tag       string
	nets      []*net.IPNet
	ipv4Nets  []ipv4Net
	ipv6Nets  []*net.IPNet
	totalNets int
}

// Filter manages CIDR rules for IP address matching.
type Filter struct {
	rules      map[string]*CIDRRule
	matchCache map[string]*CIDRMatchInfo
	mu         sync.RWMutex
}

// CIDRMatchInfo contains the parsed match tag with negation support.
type CIDRMatchInfo struct {
	Tag      string
	Negate   bool
	Original string
}

type ipv4Net struct {
	ip     uint32
	mask   uint32
	prefix uint8
}

// New creates a new Filter from the given CIDR configuration slice.
func New(configs []config.CIDRConfig) (*Filter, error) {
	cm := &Filter{
		rules:      make(map[string]*CIDRRule),
		matchCache: make(map[string]*CIDRMatchInfo),
	}

	for _, cfg := range configs {
		if cfg.Tag == "" {
			return nil, ErrEmptyTag
		}
		if _, exists := cm.rules[cfg.Tag]; exists {
			return nil, fmt.Errorf("duplicate CIDR tag: %s", cfg.Tag)
		}

		rule, err := cm.loadConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("load CIDR config for tag '%s': %w", cfg.Tag, err)
		}
		cm.rules[cfg.Tag] = rule

		sourceInfo := ""
		if cfg.File != "" && len(cfg.Rules) > 0 {
			sourceInfo = fmt.Sprintf("%s + %d inline rules", cfg.File, len(cfg.Rules))
		} else if cfg.File != "" {
			sourceInfo = cfg.File
		} else {
			sourceInfo = fmt.Sprintf("%d inline rules", len(cfg.Rules))
		}
		log.Infof("CIDR: Loaded tag=%s, source=%s, total=%d", cfg.Tag, sourceInfo, len(rule.nets))
	}

	return cm, nil
}

func (cm *Filter) loadConfig(cfg config.CIDRConfig) (*CIDRRule, error) {
	rule := &CIDRRule{tag: cfg.Tag, nets: make([]*net.IPNet, 0)}
	validCount := 0

	for i, cidr := range cfg.Rules {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" || strings.HasPrefix(cidr, "#") {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Warnf("CIDR: Invalid CIDR in rules[%d] for tag '%s': %s - %v", i, cfg.Tag, cidr, err)
			continue
		}
		rule.nets = append(rule.nets, ipNet)
		validCount++
	}

	if cfg.File != "" {
		if !dnsutil.IsValidFilePath(cfg.File) {
			return nil, fmt.Errorf("invalid file path: %s", cfg.File)
		}
		f, err := os.Open(cfg.File)
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
				log.Warnf("CIDR: Invalid CIDR at %s:%d: %s - %v", cfg.File, lineNum, line, err)
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
		return nil, fmt.Errorf("no valid CIDR entries for tag '%s'", cfg.Tag)
	}

	rule.preprocessNetworks()
	return rule, nil
}

// MatchIP checks if an IP matches the CIDR rule identified by matchTag.
func (cm *Filter) MatchIP(ip net.IP, matchTag string) (matched bool, exists bool) {
	if cm == nil || matchTag == "" {
		return true, true
	}

	matchInfo := cm.getMatchInfo(matchTag)
	if matchInfo == nil {
		return false, false
	}

	rule, exists := cm.rules[matchInfo.Tag]
	if !exists {
		return false, false
	}

	inList := rule.contains(ip)
	if matchInfo.Negate {
		return !inList, true
	}
	return inList, true
}

func (cm *Filter) getMatchInfo(matchTag string) *CIDRMatchInfo {
	cm.mu.RLock()
	if info, exists := cm.matchCache[matchTag]; exists {
		cm.mu.RUnlock()
		return info
	}
	cm.mu.RUnlock()

	cm.mu.Lock()
	defer cm.mu.Unlock()

	if info, exists := cm.matchCache[matchTag]; exists {
		return info
	}

	negate := strings.HasPrefix(matchTag, "!")
	tag := strings.TrimPrefix(matchTag, "!")

	info := &CIDRMatchInfo{
		Tag:      tag,
		Negate:   negate,
		Original: matchTag,
	}

	cm.matchCache[matchTag] = info
	return info
}

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

	slices.SortFunc(r.ipv4Nets, func(a, b ipv4Net) int {
		if a.prefix != b.prefix {
			return int(b.prefix) - int(a.prefix)
		}
		return 0
	})

	r.nets = nil
}

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

func (r *CIDRRule) contains(ip net.IP) bool {
	if r == nil || ip == nil {
		return false
	}

	if ipv4 := ip.To4(); ipv4 != nil {
		return r.containsIPv4(ipv4)
	}

	return r.containsIPv6(ip)
}

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

func (r *CIDRRule) containsIPv6(ip net.IP) bool {
	for _, ipNet := range r.ipv6Nets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}
