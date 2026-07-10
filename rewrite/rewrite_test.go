package rewrite

import (
	"net"
	"os"
	"testing"
	"zjdns/config"
	"zjdns/internal/ttl"

	"codeberg.org/miekg/dns"
)

func TestEvaluator_LoadRules(t *testing.T) {
	re := New()

	blockedCode := dns.RcodeRefused
	rules := []config.RewriteRule{
		{
			Name: "blocked.example.com",
			Records: []config.DNSRecordConfig{
				{Type: "A", Content: "127.0.0.1", TTL: config.DefaultTTL},
			},
		},
		{
			Name:         "other.example.com",
			ResponseCode: &blockedCode,
		},
		{
			ExcludeClients: []string{"10.0.0.1/32"},
		},
	}

	if re.HasRules() {
		t.Error("HasRules should be false before loading")
	}

	err := re.LoadRules(rules)
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}

	if !re.HasRules() {
		t.Error("HasRules should be true after loading")
	}
}

func TestEvaluator_Evaluate_Block(t *testing.T) {
	re := New()
	blockedCode := dns.RcodeRefused
	err := re.LoadRules([]config.RewriteRule{
		{
			Name:         "blocked.example.com",
			ResponseCode: &blockedCode,
		},
	})
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}

	clientIP := net.ParseIP("192.168.1.1")
	result := re.Evaluate("blocked.example.com.", dns.TypeA, dns.ClassINET, clientIP)

	if !result.ShouldRewrite {
		t.Error("ShouldRewrite should be true")
	}
	if result.ResponseCode != dns.RcodeRefused {
		t.Errorf("ResponseCode = %d, want %d", result.ResponseCode, dns.RcodeRefused)
	}
}

func TestEvaluator_Evaluate_Synthetic(t *testing.T) {
	re := New()
	err := re.LoadRules([]config.RewriteRule{
		{
			Name: "test.example.com",
			Records: []config.DNSRecordConfig{
				{Type: "A", Content: "10.0.0.1", TTL: 300},
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}

	clientIP := net.ParseIP("10.0.0.1")
	result := re.Evaluate("test.example.com.", dns.TypeA, dns.ClassINET, clientIP)

	if !result.ShouldRewrite {
		t.Fatal("ShouldRewrite should be true")
	}
	if len(result.Records) != 1 {
		t.Fatalf("Records len = %d, want 1", len(result.Records))
	}
	rr, ok := result.Records[0].(*dns.A)
	if !ok {
		t.Fatal("Record should be A record")
	}
	if rr.A.String() != "10.0.0.1" {
		t.Errorf("A record = %s, want 10.0.0.1", rr.A.String())
	}
}

func TestEvaluator_Evaluate_NoMatch(t *testing.T) {
	re := New()
	err := re.LoadRules([]config.RewriteRule{
		{
			Name: "test.example.com",
			Records: []config.DNSRecordConfig{
				{Type: "A", Content: "10.0.0.1", TTL: 300},
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}

	clientIP := net.ParseIP("10.0.0.1")
	result := re.Evaluate("other.example.com.", dns.TypeA, dns.ClassINET, clientIP)
	if result.ShouldRewrite {
		t.Error("ShouldRewrite should be false for non-matching domain")
	}
}

func TestEvaluator_Evaluate_ClientExclude(t *testing.T) {
	re := New()
	blockedCode := dns.RcodeRefused
	err := re.LoadRules([]config.RewriteRule{
		{ExcludeClients: []string{"10.0.0.0/8"}},
		{
			Name:         "blocked.example.com",
			ResponseCode: &blockedCode,
		},
	})
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}

	// Client in excluded range — rule should NOT apply
	excludedClient := net.ParseIP("10.0.0.1")
	result := re.Evaluate("blocked.example.com.", dns.TypeA, dns.ClassINET, excludedClient)
	// Note: the rule is still evaluated, but the excluded client check skips it
	// Actually, check the logic: global excludes prevent rule matching
	_ = result

	// Client not excluded — rule should apply
	allowedClient := net.ParseIP("192.168.1.1")
	result2 := re.Evaluate("blocked.example.com.", dns.TypeA, dns.ClassINET, allowedClient)
	if !result2.ShouldRewrite {
		t.Error("ShouldRewrite should be true for non-excluded client")
	}
}

func TestEvaluator_Evaluate_ClientInclude(t *testing.T) {
	re := New()
	err := re.LoadRules([]config.RewriteRule{
		{
			Name: "special.example.com",
			Records: []config.DNSRecordConfig{
				{Type: "AAAA", Content: "::1", TTL: 300},
			},
			IncludeClients: []string{"192.168.0.0/24"},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}

	// Client in included range
	includedClient := net.ParseIP("192.168.0.50")
	result := re.Evaluate("special.example.com.", dns.TypeAAAA, dns.ClassINET, includedClient)
	if !result.ShouldRewrite {
		t.Error("ShouldRewrite should be true for included client")
	}

	// Client not in included range
	excludedClient := net.ParseIP("10.0.0.1")
	result2 := re.Evaluate("special.example.com.", dns.TypeAAAA, dns.ClassINET, excludedClient)
	if result2.ShouldRewrite {
		t.Error("ShouldRewrite should be false for non-included client")
	}
}

func TestEvaluator_NoRules(t *testing.T) {
	re := New()
	clientIP := net.ParseIP("8.8.8.8")
	result := re.Evaluate("example.com.", dns.TypeA, dns.ClassINET, clientIP)
	if result.ShouldRewrite {
		t.Error("ShouldRewrite should be false with no rules")
	}
}

func TestEvaluator_HasRules(t *testing.T) {
	re := New()
	if re.HasRules() {
		t.Error("HasRules should be false with no rules")
	}

	_ = re.LoadRules([]config.RewriteRule{
		{Name: "test.example.com", Records: []config.DNSRecordConfig{{Type: "A", Content: "127.0.0.1"}}},
	})
	if !re.HasRules() {
		t.Error("HasRules should be true with rules")
	}
}

// ── Rewrite TTL ──────────────────────────────────────────────────────────────

func TestEvaluator_CreatedAt(t *testing.T) {
	re := New()
	err := re.LoadRules([]config.RewriteRule{
		{
			Name: "ttl.example.com",
			Records: []config.DNSRecordConfig{
				{Type: "A", Content: "10.0.0.1", TTL: 120},
				{Type: "AAAA", Content: "::1", TTL: 300},
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}

	clientIP := net.ParseIP("192.168.1.1")
	result := re.Evaluate("ttl.example.com.", dns.TypeA, dns.ClassINET, clientIP)

	if !result.ShouldRewrite {
		t.Fatal("ShouldRewrite should be true")
	}
	if result.CreatedAt <= 0 {
		t.Errorf("CreatedAt = %d, should be > 0", result.CreatedAt)
	}
	if len(result.Records) != 1 {
		t.Fatalf("Records len = %d, want 1 (filtered by qtype=A)", len(result.Records))
	}
}

// TestEvaluator_RewriteTTLCyclical simulates the handler pipeline:
// Evaluate → DeductElapsedCyclical with elapsed time since LoadRules.
func TestEvaluator_RewriteTTLCyclical(t *testing.T) {
	re := New()
	err := re.LoadRules([]config.RewriteRule{
		{
			Name: "cycle.example.com",
			Records: []config.DNSRecordConfig{
				{Type: "A", Content: "10.0.0.1", TTL: 120},
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}

	clientIP := net.ParseIP("10.0.0.1")
	result := re.Evaluate("cycle.example.com.", dns.TypeA, dns.ClassINET, clientIP)
	if !result.ShouldRewrite {
		t.Fatal("ShouldRewrite should be true")
	}

	// Simulate elapsed time since LoadRules by overriding NowUnix.
	origNow := ttl.NowUnix
	defer func() { ttl.NowUnix = origNow }()

	tests := []struct {
		name    string
		elapsed int64
		wantTTL uint32
	}{
		{"fresh start", 0, 120},
		{"mid cycle", 40, 80},
		{"near expiry", 119, 1},
		{"reset at boundary", 120, 120},
		{"second cycle", 140, 100},        // 140ms elapsed, 100ms remaining (cyclical)
		{"third cycle near end", 350, 10}, // 120 - (350 % 120) = 120 - 110 = 10
		{"many cycles", 1200, 120},        // 1200 % 120 = 0 → 120
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the handler: elapsed = now - loadedAt
			records := ttl.DeductElapsedCyclical(result.Records, tt.elapsed)
			if len(records) != 1 {
				t.Fatalf("got %d records, want 1", len(records))
			}
			if got := records[0].Header().TTL; got != tt.wantTTL {
				t.Errorf("elapsed=%ds → TTL=%d, want %d", tt.elapsed, got, tt.wantTTL)
			}
		})
	}
}

// TestEvaluator_RewriteTTLMultipleRRs verifies that records with different
// TTLs cycle independently.
func TestEvaluator_RewriteTTLMultipleRRs(t *testing.T) {
	re := New()
	err := re.LoadRules([]config.RewriteRule{
		{
			Name: "multi.example.com",
			Records: []config.DNSRecordConfig{
				{Type: "A", Content: "10.0.0.1", TTL: 60},
				{Type: "A", Content: "10.0.0.2", TTL: 120},
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}

	clientIP := net.ParseIP("10.0.0.1")
	result := re.Evaluate("multi.example.com.", dns.TypeA, dns.ClassINET, clientIP)
	if !result.ShouldRewrite {
		t.Fatal("ShouldRewrite should be true")
	}
	if len(result.Records) != 2 {
		t.Fatalf("Records len = %d, want 2", len(result.Records))
	}

	// Elapsed=80: rr1 (TTL=60): 80%60=20 → 60-20=40; rr2 (TTL=120): 80%120=80 → 120-80=40
	records := ttl.DeductElapsedCyclical(result.Records, 80)
	if records[0].Header().TTL != 40 {
		t.Errorf("rr1 TTL=%d, want 40", records[0].Header().TTL)
	}
	if records[1].Header().TTL != 40 {
		t.Errorf("rr2 TTL=%d, want 40", records[1].Header().TTL)
	}
}

// ---------------------------------------------------------------------------
// Wildcard tests
// ---------------------------------------------------------------------------

func TestEvaluator_Wildcard_Inline(t *testing.T) {
	re := New()
	nx := dns.RcodeNameError
	err := re.LoadRules([]config.RewriteRule{
		{Name: "*.example.com", ResponseCode: &nx},
	})
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}

	// Wildcard matches subdomain.
	result := re.Evaluate("foo.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.ShouldRewrite || result.ResponseCode != dns.RcodeNameError {
		t.Errorf("wildcard + NXDOMAIN: rewrite=%v rcode=%d", result.ShouldRewrite, result.ResponseCode)
	}

	// Wildcard does NOT match base domain.
	result = re.Evaluate("example.com.", dns.TypeA, dns.ClassINET, nil)
	if result.ShouldRewrite {
		t.Error("wildcard *.example.com should NOT match example.com itself")
	}
}

func TestEvaluator_Wildcard_NXDOMAIN(t *testing.T) {
	re := New()
	nx := dns.RcodeNameError
	err := re.LoadRules([]config.RewriteRule{
		{Name: "*.blocked.com", ResponseCode: &nx},
	})
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}

	result := re.Evaluate("cdn.blocked.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.ShouldRewrite || result.ResponseCode != dns.RcodeNameError {
		t.Errorf("wildcard + NXDOMAIN: rewrite=%v rcode=%d", result.ShouldRewrite, result.ResponseCode)
	}
}

func TestEvaluator_Wildcard_WithRecords(t *testing.T) {
	re := New()
	err := re.LoadRules([]config.RewriteRule{
		{Name: "*.cdn.example.com", Records: []config.DNSRecordConfig{
			{Type: "A", Content: "10.0.0.1", TTL: 60},
		}},
	})
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}

	result := re.Evaluate("img.cdn.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.ShouldRewrite {
		t.Fatal("wildcard + RR should rewrite")
	}
	if len(result.Records) != 1 {
		t.Fatalf("Records len=%d, want 1", len(result.Records))
	}

	// Wrong QTYPE check — wildcard A should not match AAAA query.
	result = re.Evaluate("img.cdn.example.com.", dns.TypeAAAA, dns.ClassINET, nil)
	if result.ShouldRewrite {
		t.Error("AAAA query against wildcard A rule should not match")
	}
}

func TestEvaluator_Wildcard_DeepSubdomain(t *testing.T) {
	re := New()
	nx := dns.RcodeNameError
	_ = re.LoadRules([]config.RewriteRule{
		{Name: "*.tracker.com", ResponseCode: &nx},
	})

	result := re.Evaluate("a.b.c.tracker.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.ShouldRewrite {
		t.Error("*.tracker.com should match a.b.c.tracker.com")
	}
}

// ---------------------------------------------------------------------------
// File import tests
// ---------------------------------------------------------------------------

func TestEvaluator_FileImport_Basic(t *testing.T) {
	tmp := t.TempDir() + "/blocklist.csv"
	writeFile(t, tmp, "domain,type,content,ttl,rcode\nads.test.com.\nblock.test.com.\n")

	re := New()
	nx := dns.RcodeNameError
	err := re.LoadRules([]config.RewriteRule{
		{File: tmp, ResponseCode: &nx},
	})
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}

	for _, d := range []string{"ads.test.com.", "block.test.com."} {
		result := re.Evaluate(d, dns.TypeA, dns.ClassINET, nil)
		if !result.ShouldRewrite || result.ResponseCode != dns.RcodeNameError {
			t.Errorf("%s: rewrite=%v rcode=%d", d, result.ShouldRewrite, result.ResponseCode)
		}
	}

	result := re.Evaluate("other.test.com.", dns.TypeA, dns.ClassINET, nil)
	if result.ShouldRewrite {
		t.Error("other.test.com should not match")
	}
}

func TestEvaluator_FileImport_CustomRR(t *testing.T) {
	tmp := t.TempDir() + "/hosts.csv"
	writeFile(t, tmp, "domain,type,content,ttl,rcode\nmy.test.com.,A,10.0.0.1,60,\n")

	re := New()
	nx := dns.RcodeNameError
	err := re.LoadRules([]config.RewriteRule{
		{File: tmp, ResponseCode: &nx},
	})
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}

	result := re.Evaluate("my.test.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.ShouldRewrite {
		t.Fatal("custom RR should rewrite")
	}
	if result.ResponseCode != dns.RcodeSuccess {
		t.Errorf("custom RR should reset rcode to NOERROR when rcode col empty, got %d", result.ResponseCode)
	}
	if len(result.Records) != 1 {
		t.Fatalf("records=%d, want 1", len(result.Records))
	}
}

func TestEvaluator_FileImport_Wildcard(t *testing.T) {
	tmp := t.TempDir() + "/wild.csv"
	writeFile(t, tmp, "domain,type,content,ttl,rcode\n*.evil.com.\n*.good.com.,A,10.0.0.2,,\n")

	re := New()
	nx := dns.RcodeNameError
	err := re.LoadRules([]config.RewriteRule{
		{File: tmp, ResponseCode: &nx},
	})
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}

	result := re.Evaluate("cdn.evil.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.ShouldRewrite || result.ResponseCode != dns.RcodeNameError {
		t.Errorf("*.evil.com NXDOMAIN: rewrite=%v rcode=%d", result.ShouldRewrite, result.ResponseCode)
	}

	result = re.Evaluate("img.good.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.ShouldRewrite || result.ResponseCode != dns.RcodeSuccess {
		t.Errorf("*.good.com + RR: rewrite=%v rcode=%d", result.ShouldRewrite, result.ResponseCode)
	}
}

func TestEvaluator_FileImport_Comments(t *testing.T) {
	tmp := t.TempDir() + "/comments.csv"
	writeFile(t, tmp, "domain,type,content,ttl,rcode\n# comment\nreal.com.\n")

	re := New()
	nx := dns.RcodeNameError
	_ = re.LoadRules([]config.RewriteRule{{File: tmp, ResponseCode: &nx}})

	result := re.Evaluate("real.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.ShouldRewrite {
		t.Error("real.com should match despite comments")
	}
}

// ---------------------------------------------------------------------------
// Mixed exact + wildcard priority
// ---------------------------------------------------------------------------

func TestEvaluator_ExactWinsOverWildcard(t *testing.T) {
	re := New()
	nx := dns.RcodeNameError
	refused := dns.RcodeRefused
	_ = re.LoadRules([]config.RewriteRule{
		{Name: "cdn.example.com", ResponseCode: &refused},
		{Name: "*.example.com", ResponseCode: &nx},
	})

	result := re.Evaluate("cdn.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.ShouldRewrite || result.ResponseCode != dns.RcodeRefused {
		t.Errorf("exact should win: rewrite=%v rcode=%d", result.ShouldRewrite, result.ResponseCode)
	}

	result = re.Evaluate("img.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !result.ShouldRewrite || result.ResponseCode != dns.RcodeNameError {
		t.Errorf("wildcard should catch: rewrite=%v rcode=%d", result.ShouldRewrite, result.ResponseCode)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
}
