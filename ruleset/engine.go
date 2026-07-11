// Package ruleset provides tag-based matching for client IP (CIDR) and query
// domain (suffix). A ruleset combines both match types under a single tag.
// Match(qname, ip) returns all matching tags for use in upstream selection,
// zone rules, and CIDR filtering.
package ruleset

import (
	"zjdns/config"
)

// Engine matches queries against rule sets to produce tags.
type Engine struct {
	ip     *ipMatcher
	domain *domainMatcher
	tags   map[string]bool // all known tags from config
}

// New builds an Engine from RuleSet configurations.
func New(rulesets []config.RuleSet) (*Engine, error) {
	e := &Engine{}
	var ipConfigs []ipRule
	var domainConfigs []domainRule

	for _, rs := range rulesets {
		switch rs.Type {
		case "ip":
			ipConfigs = append(ipConfigs, ipRule{tag: rs.Tag, cidrs: rs.Rule, file: rs.File})
		case "domain":
			domainConfigs = append(domainConfigs, domainRule{tag: rs.Tag, pattern: "", file: "", rules: rs.Rule, filePath: rs.File})
		}
	}

	var err error
	if len(ipConfigs) > 0 {
		e.ip, err = newIPMatcher(ipConfigs)
		if err != nil {
			return nil, err
		}
	}
	if len(domainConfigs) > 0 {
		e.domain = newDomainMatcher(domainConfigs)
	}
	e.tags = make(map[string]bool)
	for _, rs := range rulesets {
		e.tags[rs.Tag] = true
	}
	return e, nil
}

// Match returns all tags that match the given query name and client IP.
func (e *Engine) Match(qname, ip string) map[string]bool {
	tags := make(map[string]bool)
	if e.ip != nil {
		for _, t := range e.ip.match(ip) {
			tags[t] = true
		}
	}
	if e.domain != nil {
		if t := e.domain.match(qname); t != "" {
			tags[t] = true
		}
	}
	return tags
}

// MatchIP checks whether an IP matches a specific tag. Used for response
// record filtering. Tags prefixed with ! are negated.
// HasIPTag reports whether a tag has CIDR rules for IP-based filtering.
func (e *Engine) HasIPTag(tag string) bool {
	if e == nil || e.ip == nil {
		return false
	}
	_, ok := e.ip.tags[tag]
	return ok
}

func (e *Engine) MatchIP(ip, tag string) (matched, exists bool) {
	if e == nil {
		return false, false
	}
	negate := false
	if tag != "" && tag[0] == '!' {
		negate = true
		tag = tag[1:]
	}
	// Tag must exist in config — if not, refuse the response (config error).
	if !e.tags[tag] {
		return false, false
	}
	if e.ip == nil {
		return false, true // tag exists but no IP rules: skip (domain-only)
	}
	m, ok := e.ip.matchTag(ip, tag)
	if !ok {
		return false, true // tag exists but no IP rules for it
	}
	if negate {
		return !m, true
	}
	return m, true
}
