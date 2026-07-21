package pending

import (
	"fmt"
	"testing"
)

func BenchmarkGroupStartDone(b *testing.B) {
	g := NewGroup[string]()
	b.ResetTimer()
	for b.Loop() {
		g.Start("key")
		g.Done("key")
	}
}

func BenchmarkGroupStartReject(b *testing.B) {
	g := NewGroup[string]()
	g.Start("key")
	b.ResetTimer()
	for b.Loop() {
		_ = g.Start("key") // should return false — already pending
	}
}

func BenchmarkGroupParallel(b *testing.B) {
	g := NewGroup[string]()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("key%d", i%100)
			if g.Start(key) {
				g.Done(key)
			}
			i++
		}
	})
}
