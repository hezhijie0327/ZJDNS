package cache

import (
	"slices"
	"testing"
)

// parentWire strips the leftmost (original-first) label from a TLD-first
// wire-format name.
func parentWire(wire []byte) []byte {
	if len(wire) <= 1 {
		return wire
	}
	pos := 0
	labels := 0
	for pos < len(wire)-1 {
		labels++
		l := int(wire[pos])
		if l == 0 {
			break
		}
		pos += 1 + l
	}
	if labels <= 1 {
		return []byte{0}
	}
	pos = 0
	for i := 0; i < labels-1; i++ {
		l := int(wire[pos])
		pos += 1 + l
	}
	b := make([]byte, pos+1)
	copy(b, wire[:pos])
	b[pos] = 0
	return b
}

func bytesLT(a, b []byte) bool {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := range n {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return len(a) < len(b)
}

func bytesLE(a, b []byte) bool {
	return bytesLT(a, b) || slices.Equal(a, b)
}

func TestToWireName_Basic(t *testing.T) {
	w := toWireName("example.com")
	if len(w) == 0 || w[len(w)-1] != 0 {
		t.Fatal("wire name should be root-terminated")
	}
}

func TestToWireName_WireOrderCanonical(t *testing.T) {
	// Canonical DNS order: shorter names sort before longer ones,
	// labels compared right-to-left (TLD first).
	// "example.com" < "a.example.com" because com=com, example=example,
	// then "example.com" is shorter.
	a := toWireName("a.example.com")
	b := toWireName("example.com")
	if !bytesLE(b, a) {
		t.Errorf("example.com should sort BEFORE a.example.com: %x vs %x", b, a)
	}
	// b.example.com vs c.example.com: same TLD, same 2nd label, compare 3rd
	c := toWireName("b.example.com")
	d := toWireName("c.example.com")
	if !bytesLT(c, d) {
		t.Errorf("b.example.com should sort before c.example.com")
	}
	// com < yahoo.com (both share no labels, shorter wins)
	e := toWireName("com")
	f := toWireName("yahoo.com")
	if !bytesLT(e, f) {
		t.Errorf("com should sort before yahoo.com")
	}
}

func TestToWireName_Root(t *testing.T) {
	w := toWireName(".")
	if len(w) != 1 || w[0] != 0 {
		t.Errorf("root should be single zero byte, got %x", w)
	}
}

func TestParentWire(t *testing.T) {
	w := toWireName("www.example.com")
	p := parentWire(w)
	// "www.example.com" → parent should be "example.com"
	parentName := toWireName("example.com")
	if !slices.Equal(p, parentName) {
		t.Errorf("parent of www.example.com should be example.com: got %x, want %x", p, parentName)
	}

	// Parent of "com" should be root
	p2 := parentWire(toWireName("com"))
	root := toWireName(".")
	if !slices.Equal(p2, root) {
		t.Errorf("parent of com should be root")
	}
}

func TestMarshalTypeBitmap(t *testing.T) {
	types := []uint16{1, 28, 6}
	raw := marshalTypeBitmap(types)
	decoded := unmarshalTypeBitmap(raw)
	if len(decoded) != len(types) {
		t.Fatalf("round-trip length mismatch: %d vs %d", len(decoded), len(types))
	}
	for i, v := range types {
		if decoded[i] != v {
			t.Errorf("index %d: got %d, want %d", i, decoded[i], v)
		}
	}
}

func TestBytesLT(t *testing.T) {
	a := []byte{3, 'c', 'o', 'm', 0}
	b := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	if !bytesLT(a, b) {
		t.Errorf("com < example.com in wire order")
	}
	if bytesLT(a, a) {
		t.Error("a < a should be false")
	}
}
