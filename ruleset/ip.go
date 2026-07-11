package ruleset

import (
	"net"
)

type bitTrie struct{ root *bitNode }

type bitNode struct {
	leaf bool
	ch   [2]*bitNode
}

type ipRule struct {
	tag   string
	cidrs []string
}

type ipMatcher struct {
	tags map[string]*bitTrie
}

func newIPMatcher(rules []ipRule) (*ipMatcher, error) {
	m := &ipMatcher{tags: make(map[string]*bitTrie)}
	for _, r := range rules {
		trie := &bitTrie{}
		added := false
		for _, cidr := range r.cidrs {
			if _, n, err := net.ParseCIDR(cidr); err == nil {
				trie.insertCIDR(n)
				added = true
			}
		}
		if added {
			m.tags[r.tag] = trie
		}
	}
	return m, nil
}

func (m *ipMatcher) match(ipStr string) []string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	var tags []string
	for tag, trie := range m.tags {
		if trie.contains(ip) {
			tags = append(tags, tag)
		}
	}
	return tags
}

func (m *ipMatcher) matchTag(ipStr, tag string) (matched, exists bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, false
	}
	trie, ok := m.tags[tag]
	if !ok {
		return false, false
	}
	return trie.contains(ip), true
}

func (t *bitTrie) insertCIDR(n *net.IPNet) {
	ones, bits := n.Mask.Size()
	if ones == 0 {
		t.root = &bitNode{leaf: true}
		return
	}
	var key []uint32
	if bits == 32 {
		ip4 := n.IP.To4()
		key = []uint32{uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])}
	} else {
		key = ipToUint32(n.IP)
	}
	if t.root == nil {
		t.root = &bitNode{}
	}
	nd := t.root
	for b := 0; b < ones; b++ {
		bit := (key[b/32] >> (31 - b%32)) & 1
		if nd.ch[bit] == nil {
			nd.ch[bit] = &bitNode{}
		}
		nd = nd.ch[bit]
	}
	nd.leaf = true
}

func (t *bitTrie) contains(ip net.IP) bool {
	if t.root == nil {
		return false
	}
	if t.root.leaf {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		key := []uint32{uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])}
		return walkTrie(t.root, key, 32)
	}
	return walkTrie(t.root, ipToUint32(ip), 128)
}

func walkTrie(n *bitNode, key []uint32, bits int) bool {
	for b := 0; b < bits; b++ {
		if n.leaf {
			return true
		}
		bit := (key[b/32] >> (31 - b%32)) & 1
		if n.ch[bit] == nil {
			return false
		}
		n = n.ch[bit]
	}
	return n.leaf
}

func ipToUint32(ip net.IP) []uint32 {
	ip = ip.To16()
	if ip == nil {
		ip = net.IPv4zero.To16()
	}
	return []uint32{
		uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3]),
		uint32(ip[4])<<24 | uint32(ip[5])<<16 | uint32(ip[6])<<8 | uint32(ip[7]),
		uint32(ip[8])<<24 | uint32(ip[9])<<16 | uint32(ip[10])<<8 | uint32(ip[11]),
		uint32(ip[12])<<24 | uint32(ip[13])<<16 | uint32(ip[14])<<8 | uint32(ip[15]),
	}
}
