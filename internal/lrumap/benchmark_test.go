package lrumap

import (
	"fmt"
	"strconv"
	"testing"
)

func BenchmarkMapGet(b *testing.B) {
	m := New[string, int](1024)
	for i := range 1024 {
		m.Set(strconv.Itoa(i), i)
	}
	b.ResetTimer()
	for b.Loop() {
		_, _ = m.Get("512")
	}
}

func BenchmarkMapSet(b *testing.B) {
	m := New[string, int](2048)
	b.ResetTimer()
	for b.Loop() {
		m.Set("key", 42)
	}
}

func BenchmarkMapSetWithEviction(b *testing.B) {
	m := New[string, int](64)
	b.ResetTimer()
	i := 0
	for b.Loop() {
		m.Set(fmt.Sprintf("key%d", i), i)
		i++
	}
}

func BenchmarkMapDelete(b *testing.B) {
	m := New[string, int](1024)
	for i := range 1024 {
		m.Set(strconv.Itoa(i), i)
	}
	b.ResetTimer()
	for b.Loop() {
		m.Set("temp", 1)
		m.Delete("temp")
	}
}

func BenchmarkMapLen(b *testing.B) {
	m := New[string, int](1024)
	for i := range 512 {
		m.Set(strconv.Itoa(i), i)
	}
	b.ResetTimer()
	for b.Loop() {
		_ = m.Len()
	}
}

func BenchmarkMapParallel(b *testing.B) {
	m := New[string, int](4096)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("key%d", i%1000)
			m.Set(key, i)
			_, _ = m.Get(key)
			i++
		}
	})
}
