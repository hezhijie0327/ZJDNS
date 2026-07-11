package edns

import (
	"strings"
	"testing"
)

func TestPerturbQnameCase_Basic(t *testing.T) {
	for range 100 {
		result := PerturbQnameCase("www.example.com.")
		if len(result) != len("www.example.com.") {
			t.Fatalf("length changed: got %d, want %d", len(result), len("www.example.com."))
		}
		if !strings.EqualFold(result, "www.example.com.") {
			t.Errorf("case-insensitive mismatch: got %q, want fold-equal to www.example.com.", result)
		}
	}
}

func TestPerturbQnameCase_PreservesNonAlpha(t *testing.T) {
	for range 50 {
		result := PerturbQnameCase("a-b.c0d.example.com.")
		// Dots and hyphens must be preserved (non-alphabetic ASCII).
		for i, ch := range "a-b.c0d.example.com." {
			switch ch {
			case '.', '-':
				if rune(result[i]) != ch {
					t.Errorf("non-alpha char at index %d changed: want %q, got %q", i, ch, rune(result[i]))
				}
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				if result[i] != byte(ch) {
					t.Errorf("digit at index %d changed: want %q, got %q", i, ch, rune(result[i]))
				}
			}
		}
		if !strings.EqualFold(result, "a-b.c0d.example.com.") {
			t.Errorf("fold mismatch: %q", result)
		}
	}
}

func TestPerturbQnameCase_PTRSkip(t *testing.T) {
	result := PerturbQnameCase("4.4.8.8.in-addr.arpa.")
	if result != "4.4.8.8.in-addr.arpa." {
		t.Errorf("in-addr.arpa should not be perturbed, got %q", result)
	}
	result = PerturbQnameCase("b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.")
	if result != "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa." {
		t.Errorf("ip6.arpa should not be perturbed, got %q", result)
	}
}

func TestPerturbQnameCase_Empty(t *testing.T) {
	if result := PerturbQnameCase(""); result != "" {
		t.Errorf("empty string should be empty, got %q", result)
	}
}

func TestIsCasePreserved_Match(t *testing.T) {
	if !IsCasePreserved("WwW.ExAmPlE.CoM.", "WwW.ExAmPlE.CoM.") {
		t.Error("identical case should match")
	}
}

func TestIsCasePreserved_Mismatch(t *testing.T) {
	if IsCasePreserved("WwW.ExAmPlE.CoM.", "www.example.com.") {
		t.Error("different case should not match")
	}
	if IsCasePreserved("www.example.com.", "WWW.EXAMPLE.COM.") {
		t.Error("uppercase vs lowercase should not match")
	}
}

func TestIsCasePreserved_EmptyString(t *testing.T) {
	if !IsCasePreserved("", "") {
		t.Error("empty strings should match")
	}
	if IsCasePreserved("www.example.com.", "") {
		t.Error("non-empty vs empty should not match")
	}
}
