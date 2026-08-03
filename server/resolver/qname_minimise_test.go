package resolver

import (
	"testing"
	"zjdns/config"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// ── Labels ──────────────────────────────────────────────────────────────────

func TestLabels(t *testing.T) {
	tests := []struct {
		name string
		want int
	}{
		{".", 0},
		{"example.com.", 2},
		{"www.example.com.", 3},
		{"a.b.c.d.example.com.", 6},
		{"com.", 1},
	}
	for _, tt := range tests {
		got := dnsutil.Labels(tt.name)
		if got != tt.want {
			t.Errorf("Labels(%q) = %d, want %d", tt.name, got, tt.want)
		}
	}
}

// ── minimiseQNAME ───────────────────────────────────────────────────────────

func TestMinimiseQNAME_Root(t *testing.T) {
	// From root, add 1 label → top-level domain
	got := minimiseQNAME("www.example.com.", ".", 1)
	want := "com."
	if got != want {
		t.Errorf("minimiseQNAME(www.example.com., ., 1) = %q, want %q", got, want)
	}
}

func TestMinimiseQNAME_RootTwoLabels(t *testing.T) {
	got := minimiseQNAME("www.example.com.", ".", 2)
	want := "example.com."
	if got != want {
		t.Errorf("minimiseQNAME(www.example.com., ., 2) = %q, want %q", got, want)
	}
}

func TestMinimiseQNAME_FromCom(t *testing.T) {
	got := minimiseQNAME("www.example.com.", "com.", 1)
	want := "example.com."
	if got != want {
		t.Errorf("minimiseQNAME(www.example.com., com., 1) = %q, want %q", got, want)
	}
}

func TestMinimiseQNAME_FromExample(t *testing.T) {
	got := minimiseQNAME("www.example.com.", "example.com.", 1)
	want := "www.example.com."
	if got != want {
		t.Errorf("minimiseQNAME(www.example.com., example.com., 1) = %q, want %q", got, want)
	}
}

func TestMinimiseQNAME_AllLabels(t *testing.T) {
	// When labelsToAdd exceeds remaining labels, return original
	got := minimiseQNAME("www.example.com.", "example.com.", 10)
	want := "www.example.com."
	if got != want {
		t.Errorf("minimiseQNAME(www.example.com., example.com., 10) = %q, want %q", got, want)
	}
}

func TestMinimiseQNAME_DotEqualsZone(t *testing.T) {
	// QNAME equals zone → reached target
	got := minimiseQNAME("example.com.", "example.com.", 1)
	want := "example.com."
	if got != want {
		t.Errorf("minimiseQNAME(example.com., example.com., 1) = %q, want %q", got, want)
	}
}

func TestMinimiseQNAME_DeepDomain(t *testing.T) {
	got := minimiseQNAME("a.b.c.d.e.f.g.example.com.", ".", 1)
	want := "com."
	if got != want {
		t.Errorf("minimiseQNAME for deep domain from root: got %q, want %q", got, want)
	}
}

// ── labelsToAdd ─────────────────────────────────────────────────────────────

func TestLabelsToAdd_EarlySteps(t *testing.T) {
	// First MINIMISE_ONE_LAB steps return cumulative exposure: 1, 2, 3, 4, ...
	for s := range config.DefaultMinimiseOneLabel {
		got := labelsToAdd("a.b.c.example.com.", ".", s,
			config.DefaultQnameMinimiseCount, config.DefaultMinimiseOneLabel)
		want := s + 1 // cumulative: step 0 → 1 label, step 3 → 4 labels
		if got != want {
			t.Errorf("labelsToAdd step %d: got %d, want %d (cumulative)", s, got, want)
		}
	}
}

func TestLabelsToAdd_BeyondMax(t *testing.T) {
	// After minimisationCount steps, expose all remaining labels
	got := labelsToAdd("a.b.c.d.e.f.example.com.", ".", config.DefaultQnameMinimiseCount,
		config.DefaultQnameMinimiseCount, config.DefaultMinimiseOneLabel)
	want := dnsutil.Labels("a.b.c.d.e.f.example.com.")
	if got != want {
		t.Errorf("labelsToAdd beyond max: got %d, want %d", got, want)
	}
}

func TestLabelsToAdd_NoLabelsLeft(t *testing.T) {
	// Already at target zone
	got := labelsToAdd("example.com.", "example.com.", 0,
		config.DefaultQnameMinimiseCount, config.DefaultMinimiseOneLabel)
	if got != 0 {
		t.Errorf("labelsToAdd when at target: got %d, want 0", got)
	}
}

func TestLabelsToAdd_WithCurrentDomain(t *testing.T) {
	// Current domain is "com.", original QNAME has 3 labels: www.example.com.
	// 1 label remaining beyond "com." is "example."
	got := labelsToAdd("www.example.com.", "com.", 0,
		config.DefaultQnameMinimiseCount, config.DefaultMinimiseOneLabel)
	if got != 1 {
		t.Errorf("labelsToAdd from com: got %d, want 1", got)
	}
}

func TestLabelsToAdd_FromCnZone(t *testing.T) {
	// Regression: after the TLD step the zone has advanced to "cn.", so the
	// next minimised name must be exactly one label beyond it ("com.cn."),
	// not two ("apple.com.cn.").  Skipping "com.cn." broke DNSSEC for
	// apple.com.cn: the cn servers answer with com.cn-zone NSEC3 proofs
	// signed by com.cn's DNSKEY, which is never fetched when the
	// intermediate delegation is never walked.
	got := labelsToAdd("www.apple.com.cn.", "cn.", 1,
		config.DefaultQnameMinimiseCount, config.DefaultMinimiseOneLabel)
	if got != 1 {
		t.Errorf("labelsToAdd(www.apple.com.cn., cn., 1) = %d, want 1", got)
	}
	if name := minimiseQNAME("www.apple.com.cn.", "cn.", got); name != "com.cn." {
		t.Errorf("minimised name = %q, want %q", name, "com.cn.")
	}
}

func TestMinimiseQNAME_Sequence_Apple(t *testing.T) {
	// RFC 9156 §2.3 sequence for www.apple.com.cn: each step exposes
	// exactly one more label beyond the current zone.
	want := []string{"cn.", "com.cn.", "apple.com.cn.", "www.apple.com.cn."}
	zone := "."
	for s, w := range want {
		add := labelsToAdd("www.apple.com.cn.", zone, s,
			config.DefaultQnameMinimiseCount, config.DefaultMinimiseOneLabel)
		name := minimiseQNAME("www.apple.com.cn.", zone, add)
		if name != w {
			t.Fatalf("step %d: name = %q, want %q", s, name, w)
		}
		zone = name
	}
}

// ── minimisationQtype ───────────────────────────────────────────────────────

func TestMinimisationQtype_Normal(t *testing.T) {
	if got := minimisationQtype(dns.TypeA); got != dns.TypeA {
		t.Errorf("minimisationQtype(A) = %d, want A", got)
	}
	if got := minimisationQtype(dns.TypeAAAA); got != dns.TypeA {
		t.Errorf("minimisationQtype(AAAA) = %d, want A", got)
	}
	if got := minimisationQtype(dns.TypeMX); got != dns.TypeA {
		t.Errorf("minimisationQtype(MX) = %d, want A", got)
	}
}

func TestMinimisationQtype_ParentSide(t *testing.T) {
	// DS, NSEC, NSEC3 authority lies at parent side — use original QTYPE
	if got := minimisationQtype(dns.TypeDS); got != dns.TypeDS {
		t.Errorf("minimisationQtype(DS) = %d, want DS", got)
	}
	if got := minimisationQtype(dns.TypeNSEC); got != dns.TypeNSEC {
		t.Errorf("minimisationQtype(NSEC) = %d, want NSEC", got)
	}
	if got := minimisationQtype(dns.TypeNSEC3); got != dns.TypeNSEC3 {
		t.Errorf("minimisationQtype(NSEC3) = %d, want NSEC3", got)
	}
}

func TestMinimisationQtype_MetaTypes(t *testing.T) {
	if got := minimisationQtype(dns.TypeANY); got != dns.TypeANY {
		t.Errorf("minimisationQtype(ANY) = %d, want ANY", got)
	}
	if got := minimisationQtype(dns.TypeTSIG); got != dns.TypeTSIG {
		t.Errorf("minimisationQtype(TSIG) = %d, want TSIG", got)
	}
}
