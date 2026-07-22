package ruleset

import (
	"net"
	"testing"
)

func parseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func parseIP(s string) net.IP {
	return net.ParseIP(s)
}

func TestIPTrie_SingleRule(t *testing.T) {
	trie := &ipTrie{}
	trie.insert(parseCIDR("10.0.0.0/8"), "private")

	tags := trie.match(parseIP("10.1.2.3"))
	if len(tags) != 1 || tags[0] != "private" {
		t.Fatalf("expected [private], got %v", tags)
	}

	tags = trie.match(parseIP("11.0.0.1"))
	if len(tags) != 0 {
		t.Fatalf("expected no match, got %v", tags)
	}
}

func TestIPTrie_MultipleTags(t *testing.T) {
	trie := &ipTrie{}
	trie.insert(parseCIDR("10.0.0.0/8"), "a")
	trie.insert(parseCIDR("10.1.0.0/16"), "b")
	trie.insert(parseCIDR("10.1.2.0/24"), "c")

	// 10.1.2.3 matches all three
	tags := trie.match(parseIP("10.1.2.3"))
	if len(tags) != 3 {
		t.Fatalf("expected 3 tags, got %v", tags)
	}

	// 10.2.0.1 matches only "a"
	tags = trie.match(parseIP("10.2.0.1"))
	if len(tags) != 1 || tags[0] != "a" {
		t.Fatalf("expected [a], got %v", tags)
	}
}

func TestIPTrie_IPv6(t *testing.T) {
	trie := &ipTrie{}
	trie.insert(parseCIDR("2001:db8::/32"), "doc")

	tags := trie.match(parseIP("2001:db8::1"))
	if len(tags) != 1 || tags[0] != "doc" {
		t.Fatalf("expected [doc], got %v", tags)
	}

	tags = trie.match(parseIP("2001:db9::1"))
	if len(tags) != 0 {
		t.Fatalf("expected no match, got %v", tags)
	}
}

func TestIPTrie_IPv4InIPv6(t *testing.T) {
	trie := &ipTrie{}
	trie.insert(parseCIDR("192.168.0.0/16"), "lan")

	// IPv4-mapped IPv6 should also match
	ip := net.ParseIP("::ffff:192.168.1.1")
	tags := trie.match(ip)
	if len(tags) != 1 || tags[0] != "lan" {
		t.Fatalf("expected [lan] for mapped IPv6, got %v", tags)
	}
}

func TestIPTrie_MatchTag(t *testing.T) {
	trie := &ipTrie{}
	trie.insert(parseCIDR("10.0.0.0/8"), "a")
	trie.insert(parseCIDR("10.1.0.0/16"), "b")
	trie.insert(parseCIDR("172.16.0.0/12"), "c")

	if !trie.matchTag(parseIP("10.1.2.3"), "a") {
		t.Error("10.1.2.3 should match tag a")
	}
	if !trie.matchTag(parseIP("10.1.2.3"), "b") {
		t.Error("10.1.2.3 should match tag b")
	}
	if trie.matchTag(parseIP("10.1.2.3"), "c") {
		t.Error("10.1.2.3 should NOT match tag c")
	}
	if trie.matchTag(parseIP("1.1.1.1"), "a") {
		t.Error("1.1.1.1 should NOT match tag a")
	}
}

func TestIPTrie_HasTag(t *testing.T) {
	trie := &ipTrie{}
	trie.insert(parseCIDR("10.0.0.0/8"), "private")
	trie.insert(parseCIDR("172.16.0.0/12"), "private") // same tag, different CIDR
	trie.insert(parseCIDR("192.168.0.0/16"), "lan")

	if !trie.hasTag("private") {
		t.Error("should have tag private")
	}
	if !trie.hasTag("lan") {
		t.Error("should have tag lan")
	}
	if trie.hasTag("nonexistent") {
		t.Error("should NOT have tag nonexistent")
	}
}

func TestIPTrie_Reset(t *testing.T) {
	trie := &ipTrie{}
	trie.insert(parseCIDR("10.0.0.0/8"), "a")

	trie.reset()
	tags := trie.match(parseIP("10.1.2.3"))
	if len(tags) != 0 {
		t.Fatalf("expected empty after reset, got %v", tags)
	}
}

func TestIPTrie_ExactPrefix(t *testing.T) {
	trie := &ipTrie{}
	trie.insert(parseCIDR("1.2.3.4/32"), "host")

	tags := trie.match(parseIP("1.2.3.4"))
	if len(tags) != 1 || tags[0] != "host" {
		t.Fatalf("expected [host], got %v", tags)
	}

	tags = trie.match(parseIP("1.2.3.5"))
	if len(tags) != 0 {
		t.Fatalf("expected no match for neighbor, got %v", tags)
	}
}

func TestIPTrie_ZeroPrefix(t *testing.T) {
	trie := &ipTrie{}
	trie.insert(parseCIDR("0.0.0.0/0"), "all")

	// Everything matches /0
	tags := trie.match(parseIP("8.8.8.8"))
	if len(tags) != 1 || tags[0] != "all" {
		t.Fatalf("expected [all], got %v", tags)
	}
	tags = trie.match(parseIP("1.1.1.1"))
	if len(tags) != 1 || tags[0] != "all" {
		t.Fatalf("expected [all], got %v", tags)
	}
}

func TestIPTrie_NilIP(t *testing.T) {
	trie := &ipTrie{}
	trie.insert(parseCIDR("10.0.0.0/8"), "a")

	tags := trie.match(nil)
	if len(tags) != 0 {
		t.Fatalf("expected empty for nil IP, got %v", tags)
	}
}

func BenchmarkIPTrie_Match(b *testing.B) {
	trie := &ipTrie{}
	// Add 100 CIDR rules
	rules := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"100.64.0.0/10", "198.18.0.0/15", "169.254.0.0/16",
		"224.0.0.0/4", "240.0.0.0/4", "203.0.113.0/24",
		"198.51.100.0/24", "192.0.2.0/24", "127.0.0.0/8",
	}
	for i, r := range rules {
		trie.insert(parseCIDR(r), "tag"+string(rune('a'+i)))
	}
	ip := parseIP("10.1.2.3")

	b.ResetTimer()
	for b.Loop() {
		_ = trie.match(ip)
	}
}

func BenchmarkIPTrie_MatchTag(b *testing.B) {
	trie := &ipTrie{}
	rules := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"100.64.0.0/10", "198.18.0.0/15", "169.254.0.0/16",
	}
	for i, r := range rules {
		trie.insert(parseCIDR(r), "tag"+string(rune('a'+i)))
	}
	ip := parseIP("10.1.2.3")

	b.ResetTimer()
	for b.Loop() {
		_ = trie.matchTag(ip, "taga")
	}
}
