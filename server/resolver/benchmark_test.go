package resolver

import (
	"fmt"
	"testing"
)

func BenchmarkShuffleSlice(b *testing.B) {
	s := make([]string, 13)
	for i := range s {
		s[i] = fmt.Sprintf("ns%d.example.com:53", i)
	}
	b.ResetTimer()
	for b.Loop() {
		ShuffleSlice(s)
	}
}
