package ruleset

import (
	"strings"
)

type domainRule struct {
	tag      string
	pattern  string
	file     string
	rules    []string
	filePath string
}

// domainMatcher does O(1) domain→tag matching via TLD+1 suffix map.
// "google.com" and "*.google.com" both key to "google.com".
type domainMatcher struct {
	suffix map[string]string // tld+1 → tag
}

func newDomainMatcher(rules []domainRule) *domainMatcher {
	dm := &domainMatcher{suffix: make(map[string]string)}
	for _, r := range rules {
		for _, p := range r.rules {
			key := domainKey(p)
			if key != "" {
				dm.suffix[key] = r.tag
			}
		}
		if r.filePath != "" {
			lines, err := readDomainFile(r.filePath)
			if err != nil {
				continue
			}
			for _, line := range lines {
				key := domainKey(line)
				if key != "" {
					dm.suffix[key] = r.tag
				}
			}
		}
	}
	return dm
}

func readDomainFile(path string) ([]string, error) {
	data, err := readFile(path) //nolint:gosec // G304: path from config
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		result = append(result, line)
	}
	return result, nil
}

// domainKey normalizes a domain pattern to its TLD+1 key.
// "google.com" → "google.com"
// "*.google.com" → "google.com"
func domainKey(p string) string {
	p = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p)), ".")
	p = strings.TrimPrefix(p, "*.")
	return p
}

// match returns the tag for a qname, or "".
// O(1): extracts TLD+1 from qname, one map lookup.
func (dm *domainMatcher) match(qname string) string {
	if dm == nil {
		return ""
	}
	key := tldPlusOne(qname)
	return dm.suffix[key]
}

// tldPlusOne extracts the effective suffix for domain matching.
// "www.google.com."  → "google.com"
// "google.com."      → "google.com"
func tldPlusOne(name string) string {
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	last := strings.LastIndexByte(n, '.')
	if last < 0 {
		return n
	}
	prev := strings.LastIndexByte(n[:last], '.')
	if prev < 0 {
		return n
	}
	return n[prev+1:]
}
