package ruleset

import (
	"net"
	"slices"
)

// ipTrie is a binary radix trie for O(bit-length) CIDR matching.
// Each node represents one bit position in the IP address.  IPv4
// addresses are mapped to their IPv4-in-IPv6 representation (::ffff:0:0/96)
// so both address families share the same trie structure.
type ipTrie struct {
	root   ipTrieNode
	tagSet map[string]bool // O(1) lookup for hasTag
}

type ipTrieNode struct {
	child0 *ipTrieNode // bit = 0
	child1 *ipTrieNode // bit = 1
	tags   []string    // tags whose CIDR prefix ends at this node
}

// insert adds a CIDR rule to the trie.
func (t *ipTrie) insert(n *net.IPNet, tag string) {
	if n == nil {
		return
	}
	bits := ipToBits(n.IP)
	ones, total := n.Mask.Size()

	node := &t.root

	// For IPv4 addresses, build the shared ::ffff:0:0/96 prefix if
	// it doesn't already exist.  This ensures match() — which always
	// walks from bit 0 — hits the same nodes.
	if total == 32 {
		for i := range 96 {
			bit := (bits[i/8] >> (7 - i%8)) & 1
			if bit == 0 {
				if node.child0 == nil {
					node.child0 = &ipTrieNode{}
				}
				node = node.child0
			} else {
				if node.child1 == nil {
					node.child1 = &ipTrieNode{}
				}
				node = node.child1
			}
		}
	}

	for i := range ones {
		idx := i
		if total == 32 {
			idx = 96 + i
		}
		bit := (bits[idx/8] >> (7 - idx%8)) & 1
		if bit == 0 {
			if node.child0 == nil {
				node.child0 = &ipTrieNode{}
			}
			node = node.child0
		} else {
			if node.child1 == nil {
				node.child1 = &ipTrieNode{}
			}
			node = node.child1
		}
	}
	// Dedup: the same (CIDR, tag) pair may appear in multiple rule files.
	if !slices.Contains(node.tags, tag) {
		node.tags = append(node.tags, tag)
	}
	if t.tagSet == nil {
		t.tagSet = make(map[string]bool)
	}
	t.tagSet[tag] = true
}

// match returns all tags whose CIDR prefixes contain ip.
// Returns nil for an invalid IP.
func (t *ipTrie) match(ip net.IP) []string {
	if ip = ip.To16(); ip == nil {
		return nil
	}
	// IPv4 queries walk the shared ::ffff:0:0/96 mapping — tags attached
	// above depth 96 are IPv6 rules (e.g. ::/0) that must NOT match IPv4.
	isV4 := ip.To4() != nil
	bits := [16]byte(ip)
	node := &t.root
	var tags []string
	for i := range 128 {
		if len(node.tags) > 0 && (!isV4 || i >= 96) {
			tags = append(tags, node.tags...)
		}
		bit := (bits[i/8] >> (7 - i%8)) & 1
		var next *ipTrieNode
		if bit == 0 {
			next = node.child0
		} else {
			next = node.child1
		}
		if next == nil {
			return tags
		}
		node = next
	}
	// Depth 128 is always inside the IPv4 mapping zone.
	if len(node.tags) > 0 {
		tags = append(tags, node.tags...)
	}
	return tags
}

// matchTag reports whether ip matches a specific tag in the trie.
func (t *ipTrie) matchTag(ip net.IP, tag string) bool {
	if ip = ip.To16(); ip == nil {
		return false
	}
	// See match: IPv6 rules above depth 96 must not match IPv4 addresses.
	isV4 := ip.To4() != nil
	bits := [16]byte(ip)
	node := &t.root
	if !isV4 && slices.Contains(node.tags, tag) {
		return true
	}
	for i := range 128 {
		bit := (bits[i/8] >> (7 - i%8)) & 1
		var next *ipTrieNode
		if bit == 0 {
			next = node.child0
		} else {
			next = node.child1
		}
		if next == nil {
			return false
		}
		node = next
		if (!isV4 || i+1 >= 96) && slices.Contains(node.tags, tag) {
			return true
		}
	}
	return false
}

// hasTag reports whether any rule in the trie uses the given tag.
func (t *ipTrie) hasTag(tag string) bool {
	return t.tagSet[tag]
}

// reset clears the trie for rebuilding.
func (t *ipTrie) reset() {
	t.root = ipTrieNode{}
	t.tagSet = nil
}

// ipToBits converts a net.IP to a fixed 16-byte representation.
// IPv4 addresses use the IPv4-in-IPv6 mapping (::ffff:0:0/96).
func ipToBits(ip net.IP) [16]byte {
	if ip = ip.To16(); ip == nil {
		return [16]byte{}
	}
	return [16]byte(ip)
}
