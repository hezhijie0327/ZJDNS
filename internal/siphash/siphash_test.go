package siphash

import (
	"encoding/binary"
	"math/bits"
	"testing"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// testRNG is a simple deterministic PRNG for repeatable random tests
// (SplitMix64).
type testRNG struct{ state uint64 }

// ---------------------------------------------------------------------------
// Test vectors
// ---------------------------------------------------------------------------

var (
	zeroKey = [16]byte{}
	refKey  = [16]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
)

// golden tests from dchest/siphash.
var golden = []struct {
	key  *[16]byte
	msg  []byte
	want uint64
}{
	{&zeroKey, []byte{}, 0x1e924b9d737700d7},
	{&zeroKey, []byte("Hello world"), 0xc9e8a3021f3822d9},
	{&zeroKey, []byte("12345678123"), 0xf95d77ccdb0649f},
	{&zeroKey, make([]byte, 8), 0xe849e8bb6ffe2567},
	{&zeroKey, make([]byte, 1535), 0xe74d1c0ab64b2afa},
	{
		&refKey,
		[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e},
		0xa129ca6149be45e5,
	},
}

// goldenRef is the SipHash reference implementation test vectors (LE byte order).
// Key = 00 01 02 ... 0f. Messages: empty, {00}, {00,01}, ..., {00..3e}.
// Each [8]byte is the LE encoding of the uint64 hash.
var goldenRef = [][]byte{
	{0x31, 0x0e, 0x0e, 0xdd, 0x47, 0xdb, 0x6f, 0x72}, // len=0
	{0xfd, 0x67, 0xdc, 0x93, 0xc5, 0x39, 0xf8, 0x74}, // len=1
	{0x5a, 0x4f, 0xa9, 0xd9, 0x09, 0x80, 0x6c, 0x0d}, // len=2
	{0x2d, 0x7e, 0xfb, 0xd7, 0x96, 0x66, 0x67, 0x85}, // len=3
	{0xb7, 0x87, 0x71, 0x27, 0xe0, 0x94, 0x27, 0xcf}, // len=4
	{0x8d, 0xa6, 0x99, 0xcd, 0x64, 0x55, 0x76, 0x18}, // len=5
	{0xce, 0xe3, 0xfe, 0x58, 0x6e, 0x46, 0xc9, 0xcb}, // len=6
	{0x37, 0xd1, 0x01, 0x8b, 0xf5, 0x00, 0x02, 0xab}, // len=7
	{0x62, 0x24, 0x93, 0x9a, 0x79, 0xf5, 0xf5, 0x93}, // len=8
}

// ---------------------------------------------------------------------------
// Reference implementation (test oracle)
// ---------------------------------------------------------------------------

// referenceSum64 is the previous implementation, kept as a test oracle.
func referenceSum64(key *[16]byte, msg []byte) uint64 {
	k0 := binary.LittleEndian.Uint64(key[0:8])
	k1 := binary.LittleEndian.Uint64(key[8:16])

	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573

	b := uint64(len(msg)) << 56

	for len(msg) >= 8 {
		m := binary.LittleEndian.Uint64(msg)
		v3 ^= m
		sipRoundRef(&v0, &v1, &v2, &v3)
		sipRoundRef(&v0, &v1, &v2, &v3)
		v0 ^= m
		msg = msg[8:]
	}

	var last uint64
	for i := len(msg) - 1; i >= 0; i-- {
		last |= uint64(msg[i]) << (i * 8)
	}
	last |= b

	v3 ^= last
	sipRoundRef(&v0, &v1, &v2, &v3)
	sipRoundRef(&v0, &v1, &v2, &v3)
	v0 ^= last

	v2 ^= 0xff
	sipRoundRef(&v0, &v1, &v2, &v3)
	sipRoundRef(&v0, &v1, &v2, &v3)
	sipRoundRef(&v0, &v1, &v2, &v3)
	sipRoundRef(&v0, &v1, &v2, &v3)

	return v0 ^ v1 ^ v2 ^ v3
}

func sipRoundRef(v0, v1, v2, v3 *uint64) {
	*v0 += *v1
	*v2 += *v3
	*v1 = bits.RotateLeft64(*v1, 13)
	*v3 = bits.RotateLeft64(*v3, 16)
	*v1 ^= *v0
	*v3 ^= *v2
	*v0 = bits.RotateLeft64(*v0, 32)
	*v2 += *v1
	*v0 += *v3
	*v1 = bits.RotateLeft64(*v1, 17)
	*v3 = bits.RotateLeft64(*v3, 21)
	*v1 ^= *v2
	*v3 ^= *v0
	*v2 = bits.RotateLeft64(*v2, 32)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// toUint64LE converts 8 bytes (little-endian) to uint64.
func toUint64LE(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

func newTestRNG(seed uint64) *testRNG { return &testRNG{state: seed} }

func (r *testRNG) Uint64() uint64 {
	r.state += 0x9e3779b97f4a7c15
	z := r.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestVectors_Golden(t *testing.T) {
	for i, g := range golden {
		got := Sum64(g.key, g.msg)
		if got != g.want {
			t.Errorf("golden[%d]: got %016x, want %016x", i, got, g.want)
		}
	}
}

func TestVectors_GoldenRef(t *testing.T) {
	msg := make([]byte, 0, 64)
	for i, wantBytes := range goldenRef {
		want := toUint64LE(wantBytes)
		got := Sum64(&refKey, msg)
		if got != want {
			t.Errorf("goldenRef len=%d: got %016x, want %016x", len(msg), got, want)
		}
		msg = append(msg, byte(i))
	}
}

func TestHash_MatchesSum64(t *testing.T) {
	for _, g := range golden {
		k0 := toUint64LE(g.key[0:8])
		k1 := toUint64LE(g.key[8:16])
		a := Sum64(g.key, g.msg)
		b := Hash(k0, k1, g.msg)
		if a != b || a != g.want {
			t.Errorf("Sum64=%016x Hash=%016x want=%016x", a, b, g.want)
		}
	}
}

func TestEquivalence_Random(t *testing.T) {
	rng := newTestRNG(0x9e3779b97f4a7c15)
	for i := range 1000 {
		var key [16]byte
		for j := range key {
			key[j] = byte(rng.Uint64()) //nolint:gosec // test-only: truncation to byte is intentional
		}
		msgLen := int(rng.Uint64() % 256)
		msg := make([]byte, msgLen)
		for j := range msg {
			msg[j] = byte(rng.Uint64()) //nolint:gosec // test-only: truncation to byte is intentional
		}

		got := Sum64(&key, msg)
		want := referenceSum64(&key, msg)
		if got != want {
			t.Fatalf("mismatch at iteration %d (len=%d): got %016x, want %016x", i, len(msg), got, want)
		}
	}
}

func TestCrossCheck_dchest(t *testing.T) {
	// Verify our Hash matches dchest/siphash.Hash for the reference vectors.
	// These are pre-computed via: go run -mod=mod ... dchest/siphash.Hash(k0,k1,msg)
	//
	// Cross-check: our Hash(k0=LE(key), k1=LE(key+8), msg) must match dchest.
	// We verify via the golden table which is copied from dchest/siphash.
	for _, g := range golden {
		k0 := toUint64LE(g.key[0:8])
		k1 := toUint64LE(g.key[8:16])

		got := Hash(k0, k1, g.msg)
		if got != g.want {
			t.Errorf("Hash mismatch for len=%d: got %016x, want %016x",
				len(g.msg), got, g.want)
		}
	}
}

func TestHexDecode(t *testing.T) {
	// Sanity: verify toUint64LE is consistent with encoding/binary.
	for i := range 10 {
		key := make([]byte, 16)
		for j := range key {
			key[j] = byte(i + j)
		}
		a := binary.LittleEndian.Uint64(key[0:8])
		b := toUint64LE(key[0:8])
		if a != b {
			t.Errorf("toUint64LE mismatch at %d: %016x != %016x", i, a, b)
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkSum64_8(b *testing.B)    { benchSum64(b, 8) }
func BenchmarkSum64_64(b *testing.B)   { benchSum64(b, 64) }
func BenchmarkSum64_256(b *testing.B)  { benchSum64(b, 256) }
func BenchmarkSum64_1024(b *testing.B) { benchSum64(b, 1024) }

func benchSum64(b *testing.B, size int) {
	var key [16]byte
	msg := make([]byte, size)
	b.SetBytes(int64(size))
	b.ResetTimer()
	for range b.N {
		_ = Sum64(&key, msg)
	}
}
