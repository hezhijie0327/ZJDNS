// Package cidr provides IP filtering using CIDR rules with tag matching
// and path-compressed binary tries for O(prefix-length) IP lookup.
package cidr

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
)

const (
	cidrCommentPrefix  = "#"
	cidrNegationPrefix = "!"
)

// errEmptyTag is returned when a CIDR tag is empty.
var errEmptyTag = errors.New("CIDR tag cannot be empty")

// rule holds a set of parsed CIDR networks for a single tag.
type rule struct {
	tag       string
	nets      []*net.IPNet // raw nets before trie preprocessing
	totalNets int
	v4        bitTrie
	v6        bitTrie
}

// Filter manages CIDR rules for IP address matching.
type Filter struct {
	rules      map[string]*rule
	matchCache map[string]*MatchInfo
	mu         sync.RWMutex
}

// MatchInfo contains the parsed match tag with negation support.
type MatchInfo struct {
	Tag      string
	Negate   bool
	Original string
}

// bitTrie is a binary trie for CIDR prefix matching.
// Insert stores a prefix at the terminal node; lookup walks the IP's bit
// path and returns true if any terminal node is found along the way
// (longest-prefix match is implicit — shorter prefixes are ancestors).
type bitTrie struct {
	root *bitNode
}

type bitNode struct {
	leaf bool
	ch   [2]*bitNode
}

func (t *bitTrie) insert(key []uint32, bits int) {
	if t.root == nil {
		t.root = &bitNode{}
	}
	n := t.root
	for b := 0; b < bits; b++ {
		bit := getBit(key, b)
		if n.ch[bit] == nil {
			n.ch[bit] = &bitNode{}
		}
		n = n.ch[bit]
	}
	n.leaf = true
}

func (t *bitTrie) contains(key []uint32) bool {
	if t.root == nil {
		return false
	}
	n := t.root
	for b := 0; b < len(key)*32; b++ {
		if n.leaf {
			return true
		}
		bit := getBit(key, b)
		if n.ch[bit] == nil {
			return false
		}
		n = n.ch[bit]
	}
	return n.leaf
}

// getBit returns the b-th bit of key (0 = MSB of key[0]).
func getBit(key []uint32, b int) uint32 {
	return (key[b/32] >> (31 - b%32)) & 1
}

// ipToKey converts a 4-byte IPv4 to a single-uint32 key.
func ipToKey(ip net.IP) []uint32 {
	return []uint32{uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])}
}

// ipToKey6 converts a 16-byte IPv6 to 4 uint32s.
func ipToKey6(ip net.IP) []uint32 {
	return []uint32{
		uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3]),
		uint32(ip[4])<<24 | uint32(ip[5])<<16 | uint32(ip[6])<<8 | uint32(ip[7]),
		uint32(ip[8])<<24 | uint32(ip[9])<<16 | uint32(ip[10])<<8 | uint32(ip[11]),
		uint32(ip[12])<<24 | uint32(ip[13])<<16 | uint32(ip[14])<<8 | uint32(ip[15]),
	}
}

// New creates a new Filter from the given CIDR configuration slice.
func New(configs []config.CIDRConfig) (*Filter, error) {
	f := &Filter{
		rules:      make(map[string]*rule),
		matchCache: make(map[string]*MatchInfo),
	}

	for _, cfg := range configs {
		if cfg.Tag == "" {
			return nil, errEmptyTag
		}
		if _, exists := f.rules[cfg.Tag]; exists {
			return nil, fmt.Errorf("duplicate CIDR tag: %s", cfg.Tag)
		}

		rule, err := f.loadConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("load CIDR config for tag '%s': %w", cfg.Tag, err)
		}
		f.rules[cfg.Tag] = rule

		var sourceInfo string
		switch {
		case cfg.File != "" && len(cfg.IPs) > 0:
			sourceInfo = fmt.Sprintf("%s + %d inline rules", cfg.File, len(cfg.IPs))
		case cfg.File != "":
			sourceInfo = cfg.File
		default:
			sourceInfo = fmt.Sprintf("%d inline rules", len(cfg.IPs))
		}
		log.Infof("CIDR: Loaded tag=%s, source=%s, total=%d", cfg.Tag, sourceInfo, rule.totalNets)
	}

	return f, nil
}

func (f *Filter) loadConfig(cfg config.CIDRConfig) (*rule, error) {
	rule := &rule{tag: cfg.Tag, nets: make([]*net.IPNet, 0)}
	validCount := 0

	for i, cidr := range cfg.IPs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" || strings.HasPrefix(cidr, cidrCommentPrefix) {
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
		if !zdnsutil.IsValidFilePath(cfg.File) {
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
			if line == "" || strings.HasPrefix(line, cidrCommentPrefix) {
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

// MatchTags returns all tags whose CIDR ranges contain the given IP.
func (f *Filter) MatchTags(ip net.IP) map[string]bool {
	if f == nil {
		return nil
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	tags := make(map[string]bool, len(f.rules))
	for tag, rule := range f.rules {
		if rule.contains(ip) {
			tags[tag] = true
		}
	}
	return tags
}

// MatchIP checks if an IP matches the CIDR rule identified by matchTag.
func (f *Filter) MatchIP(ip net.IP, matchTag string) (matched, exists bool) {
	if f == nil || matchTag == "" {
		return true, true
	}

	matchInfo := f.getMatchInfo(matchTag)
	if matchInfo == nil {
		return false, false
	}

	rule, exists := f.rules[matchInfo.Tag]
	if !exists {
		return false, false
	}

	inList := rule.contains(ip)
	if matchInfo.Negate {
		return !inList, true
	}
	return inList, true
}

func (f *Filter) getMatchInfo(matchTag string) *MatchInfo {
	f.mu.RLock()
	if info, exists := f.matchCache[matchTag]; exists {
		f.mu.RUnlock()
		return info
	}
	f.mu.RUnlock()

	f.mu.Lock()
	defer f.mu.Unlock()

	if info, exists := f.matchCache[matchTag]; exists {
		return info
	}

	negate := strings.HasPrefix(matchTag, cidrNegationPrefix)
	tag := strings.TrimPrefix(matchTag, cidrNegationPrefix)

	info := &MatchInfo{
		Tag:      tag,
		Negate:   negate,
		Original: matchTag,
	}

	f.matchCache[matchTag] = info
	return info
}

func (r *rule) preprocessNetworks() {
	if r == nil {
		return
	}

	r.totalNets = len(r.nets)

	for _, ipNet := range r.nets {
		if ipNet == nil {
			continue
		}
		prefix, _ := ipNet.Mask.Size()

		if ip4 := ipNet.IP.To4(); ip4 != nil {
			r.v4.insert(ipToKey(ip4), prefix)
		} else {
			r.v6.insert(ipToKey6(ipNet.IP), prefix)
		}
	}

	r.nets = nil
}

func (r *rule) contains(ip net.IP) bool {
	if r == nil || ip == nil {
		return false
	}

	if ip4 := ip.To4(); ip4 != nil {
		return r.v4.contains(ipToKey(ip4))
	}
	return r.v6.contains(ipToKey6(ip))
}
