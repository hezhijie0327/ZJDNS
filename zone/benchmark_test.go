package zone

import (
	"testing"
	"zjdns/config"
	"zjdns/database"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

func BenchmarkEvaluator_EvaluateExact(b *testing.B) {
	log.Default.SetLevel(log.Error)
	db, _ := database.Open("", 0, database.Options{})
	eval := New(db, 0)
	defer func() { _ = eval.Close() }()

	_ = eval.LoadRules([]config.ZoneRule{
		{
			Name: "bench.local",
			Answer: []config.ZoneRecord{
				{Type: dns.TypeA, TTL: 10, Content: "192.0.2.1"},
			},
		},
	})

	b.ResetTimer()
	for b.Loop() {
		_ = eval.Evaluate("bench.local.", dns.TypeA, dns.ClassINET, nil)
	}
}

func BenchmarkEvaluator_EvaluateWildcard(b *testing.B) {
	log.Default.SetLevel(log.Error)
	db, _ := database.Open("", 0, database.Options{})
	eval := New(db, 0)
	defer func() { _ = eval.Close() }()

	_ = eval.LoadRules([]config.ZoneRule{
		{
			Name: "*.example.com",
			Answer: []config.ZoneRecord{
				{Type: dns.TypeA, TTL: 10, Content: "192.0.2.1"},
			},
		},
	})

	b.ResetTimer()
	for b.Loop() {
		_ = eval.Evaluate("sub.example.com.", dns.TypeA, dns.ClassINET, nil)
	}
}

func BenchmarkEvaluator_EvaluateMiss(b *testing.B) {
	log.Default.SetLevel(log.Error)
	db, _ := database.Open("", 0, database.Options{})
	eval := New(db, 0)
	defer func() { _ = eval.Close() }()

	_ = eval.LoadRules([]config.ZoneRule{
		{
			Name: "bench.local",
			Answer: []config.ZoneRecord{
				{Type: dns.TypeA, TTL: 10, Content: "192.0.2.1"},
			},
		},
	})

	b.ResetTimer()
	for b.Loop() {
		_ = eval.Evaluate("no-match.local.", dns.TypeA, dns.ClassINET, nil)
	}
}

func BenchmarkEvaluator_LoadRules(b *testing.B) {
	log.Default.SetLevel(log.Error)
	rules := []config.ZoneRule{
		{
			Name: "bench.local",
			Answer: []config.ZoneRecord{
				{Type: dns.TypeA, TTL: 10, Content: "192.0.2.1"},
			},
		},
	}

	b.ResetTimer()
	for b.Loop() {
		db, _ := database.Open("", 0, database.Options{})
		eval := New(db, 0)
		_ = eval.LoadRules(rules)
		_ = eval.Close()
	}
}

func BenchmarkParseRecordLine(b *testing.B) {
	line := "1 192.0.2.1 300 class=1"
	b.ResetTimer()
	for b.Loop() {
		_, _, _ = parseRecordLine(line)
	}
}

func BenchmarkTokenize(b *testing.B) {
	line := `1 "test content with spaces" 300 class=1 section=answer`
	b.ResetTimer()
	for b.Loop() {
		_ = tokenize(line)
	}
}
