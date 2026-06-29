package perip

import "testing"

func TestLimiterAllow(t *testing.T) {
	l := &Limiter{}
	max := int32(2)

	c1 := l.Allow("a", max)
	if c1 == nil {
		t.Fatal("first Allow should succeed")
	}
	c2 := l.Allow("a", max)
	if c2 == nil {
		t.Fatal("second Allow should succeed")
	}

	c3 := l.Allow("a", max)
	if c3 != nil {
		t.Fatal("third Allow should be rejected")
	}

	c1()
	c3 = l.Allow("a", max)
	if c3 == nil {
		t.Fatal("Allow after cleanup should succeed")
	}
	c2()
	c3()

	l.Sweep()
	l.entries.Range(func(key, value any) bool {
		t.Errorf("Sweep should have cleaned up, but found key=%v", key)
		return true
	})
}

func TestLimiterIndependentKeys(t *testing.T) {
	l := &Limiter{}
	max := int32(1)

	if c := l.Allow("a", max); c == nil {
		t.Fatal("key a should be allowed")
	}
	if c := l.Allow("b", max); c == nil {
		t.Fatal("key b should be allowed independently")
	}
}

func TestLimiterNil(t *testing.T) {
	var l *Limiter
	c := l.Allow("x", 10)
	if c == nil {
		t.Fatal("nil limiter should allow everything")
	}
	c()
	l.Sweep()
}
