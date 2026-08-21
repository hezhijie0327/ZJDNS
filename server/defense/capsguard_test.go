package defense

import (
	"strings"
	"testing"
)

// flipped reports whether b differs from c only by the 0x20 case bit.
func flipped(b, c byte) bool {
	return b^c == 0x20
}

// assertRandomizeInvariants checks the properties RandomizeCase must uphold
// for every input: same length, only ASCII letters may flip (and then only
// by the 0x20 bit), everything else byte-identical, result case-insensitively
// equal to the input.
func assertRandomizeInvariants(t *testing.T, in, out string) {
	t.Helper()
	if len(out) != len(in) {
		t.Fatalf("RandomizeCase(%q) length changed: %d → %d", in, len(in), len(out))
	}
	if !strings.EqualFold(in, out) {
		t.Fatalf("RandomizeCase(%q) = %q: not case-insensitively equal", in, out)
	}
	for i := 0; i < len(in); i++ {
		c, d := in[i], out[i]
		if isASCIILetter(c) {
			if d != c && !flipped(c, d) {
				t.Fatalf("RandomizeCase(%q)[%d]: ASCII letter %q → %q (not a 0x20 flip)", in, i, c, d)
			}
		} else if d != c {
			t.Fatalf("RandomizeCase(%q)[%d]: non-letter byte %q → %q", in, i, c, d)
		}
	}
}

func TestRandomizeCase_NoLetters(t *testing.T) {
	cases := []string{"", ".", "12345.", "9.9.9.9", "-_*", "\x00\x7f\x80\xff"}
	for _, name := range cases {
		if got := RandomizeCase(name); got != name {
			t.Errorf("RandomizeCase(%q) = %q, want unchanged", name, got)
		}
	}
}

func TestRandomizeCase_ASCIILettersOnly(t *testing.T) {
	const name = "wWw.BaiDu.CoM"
	differed := false
	for range 100 {
		got := RandomizeCase(name)
		assertRandomizeInvariants(t, name, got)
		if got != name {
			differed = true
		}
	}
	if !differed {
		t.Fatalf("RandomizeCase(%q): no iteration produced a flip in 100 tries", name)
	}
}

func TestRandomizeCase_NonLetterBytesUntouched(t *testing.T) {
	// Escaped octet (\065 = 'A' in miekg presentation format) must stay a
	// literal backslash+digits — the digits are not letters.  High-bit
	// UTF-8 bytes (é) are outside the ASCII letter ranges.
	cases := []string{
		`\065.example.`,
		`www.\065ample.com`,
		"caf\xc3\xa9.example.",
	}
	for _, name := range cases {
		got := RandomizeCase(name)
		assertRandomizeInvariants(t, name, got)
		// The escaped/digit/high-bit positions must be byte-identical.
		for i := 0; i < len(name); i++ {
			if !isASCIILetter(name[i]) && got[i] != name[i] {
				t.Fatalf("RandomizeCase(%q): non-letter byte %d changed: %q → %q", name, i, name[i], got[i])
			}
		}
	}
}

func TestRandomizeCase_SingleLetter(t *testing.T) {
	// A single ASCII letter still randomizes (1 bit of entropy).
	got := RandomizeCase("a")
	if got != "a" && got != "A" {
		t.Fatalf("RandomizeCase(\"a\") = %q, want \"a\" or \"A\"", got)
	}
}

func TestRandomizeCase_MaxLengthName(t *testing.T) {
	// 63-byte labels + 255-byte full name — must not panic or change length.
	name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." +
		strings.Repeat("c", 63) + "." + strings.Repeat("d", 62) + "."
	if len(name) != 255 {
		t.Fatalf("test name length %d, want 255", len(name))
	}
	got := RandomizeCase(name)
	assertRandomizeInvariants(t, name, got)
}

func FuzzRandomizeCase(f *testing.F) {
	for _, seed := range []string{"", ".", "www.example.com.", "wWw.BaiDu.CoM", "123.456.", `\065.example.`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		out := RandomizeCase(name)
		assertRandomizeInvariants(t, name, out)
	})
}

func BenchmarkRandomizeCase(b *testing.B) {
	const name = "www.example.com"
	b.ReportAllocs()
	for b.Loop() {
		_ = RandomizeCase(name)
	}
}

func BenchmarkRandomizeCase_NoLetters(b *testing.B) {
	const name = "192.0.2.1"
	b.ReportAllocs()
	for b.Loop() {
		_ = RandomizeCase(name)
	}
}
