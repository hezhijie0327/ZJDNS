package ruleset

import (
	"testing"
	"zjdns/config"
	"zjdns/internal/log"
)

func BenchmarkEngine_Match(b *testing.B) {
	log.Default.SetLevel(log.Error)
	engine := New()
	_ = engine.LoadRules([]config.RuleSet{
		{Tag: "test", Type: "domain", Rule: []string{"example.com"}},
	})
	b.ResetTimer()
	for b.Loop() {
		_ = engine.Match("www.example.com", "192.0.2.1")
	}
}

func BenchmarkEngine_MatchIP(b *testing.B) {
	log.Default.SetLevel(log.Error)
	engine := New()
	_ = engine.LoadRules([]config.RuleSet{
		{Tag: "lan", Type: "ip", Rule: []string{"192.168.0.0/16", "10.0.0.0/8"}},
	})
	b.ResetTimer()
	for b.Loop() {
		_, _ = engine.MatchIP("192.168.1.1", "lan")
	}
}

func BenchmarkEngine_HasIPTag(b *testing.B) {
	log.Default.SetLevel(log.Error)
	engine := New()
	_ = engine.LoadRules([]config.RuleSet{
		{Tag: "lan", Type: "ip", Rule: []string{"192.168.0.0/16"}},
	})
	b.ResetTimer()
	for b.Loop() {
		_ = engine.HasIPTag("lan")
	}
}

func BenchmarkMatchSuffix(b *testing.B) {
	engine := New()
	_ = engine.LoadRules([]config.RuleSet{
		{Tag: "ads", Type: "domain", Rule: []string{"ads.example.com", "example.com"}},
	})
	qname := "tracker.sub.example.com."
	b.ResetTimer()
	for b.Loop() {
		_ = engine.Match(qname, "192.168.1.1")
	}
}

func BenchmarkDomainKey(b *testing.B) {
	p := "*.Example.Com."
	b.ResetTimer()
	for b.Loop() {
		_ = domainKey(p)
	}
}
