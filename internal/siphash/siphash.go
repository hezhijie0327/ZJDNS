// Package siphash implements SipHash-2-4, a fast short-input PRF
// created by Jean-Philippe Aumasson and Daniel J. Bernstein.
//
// The implementation is based on github.com/dchest/siphash (public domain)
// with inlined rounds and manual little-endian parsing to avoid function-call
// overhead on the hot path.
package siphash

// Sum64 computes the SipHash-2-4 64-bit MAC of msg under the given 128-bit key.
func Sum64(key *[16]byte, msg []byte) uint64 {
	k0 := uint64(key[0]) | uint64(key[1])<<8 | uint64(key[2])<<16 | uint64(key[3])<<24 |
		uint64(key[4])<<32 | uint64(key[5])<<40 | uint64(key[6])<<48 | uint64(key[7])<<56
	k1 := uint64(key[8]) | uint64(key[9])<<8 | uint64(key[10])<<16 | uint64(key[11])<<24 |
		uint64(key[12])<<32 | uint64(key[13])<<40 | uint64(key[14])<<48 | uint64(key[15])<<56

	return Hash(k0, k1, msg)
}

// Hash returns the 64-bit SipHash-2-4 of p with two 64-bit key halves.
func Hash(k0, k1 uint64, p []byte) uint64 {
	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573

	// Compression.
	t := uint64(len(p)) << 56
	for len(p) >= 8 {
		m := uint64(p[0]) | uint64(p[1])<<8 | uint64(p[2])<<16 | uint64(p[3])<<24 |
			uint64(p[4])<<32 | uint64(p[5])<<40 | uint64(p[6])<<48 | uint64(p[7])<<56
		v3 ^= m

		// SipRound ×2.
		v0 += v1
		v1 = v1<<13 | v1>>51
		v1 ^= v0
		v0 = v0<<32 | v0>>32
		v2 += v3
		v3 = v3<<16 | v3>>48
		v3 ^= v2
		v0 += v3
		v3 = v3<<21 | v3>>43
		v3 ^= v0
		v2 += v1
		v1 = v1<<17 | v1>>47
		v1 ^= v2
		v2 = v2<<32 | v2>>32

		v0 += v1
		v1 = v1<<13 | v1>>51
		v1 ^= v0
		v0 = v0<<32 | v0>>32
		v2 += v3
		v3 = v3<<16 | v3>>48
		v3 ^= v2
		v0 += v3
		v3 = v3<<21 | v3>>43
		v3 ^= v0
		v2 += v1
		v1 = v1<<17 | v1>>47
		v1 ^= v2
		v2 = v2<<32 | v2>>32

		v0 ^= m
		p = p[8:]
	}

	// Last block with length padding.
	switch len(p) {
	case 7:
		t |= uint64(p[6]) << 48
		fallthrough
	case 6:
		t |= uint64(p[5]) << 40
		fallthrough
	case 5:
		t |= uint64(p[4]) << 32
		fallthrough
	case 4:
		t |= uint64(p[3]) << 24
		fallthrough
	case 3:
		t |= uint64(p[2]) << 16
		fallthrough
	case 2:
		t |= uint64(p[1]) << 8
		fallthrough
	case 1:
		t |= uint64(p[0])
	}

	v3 ^= t

	// SipRound ×2.
	v0 += v1
	v1 = v1<<13 | v1>>51
	v1 ^= v0
	v0 = v0<<32 | v0>>32
	v2 += v3
	v3 = v3<<16 | v3>>48
	v3 ^= v2
	v0 += v3
	v3 = v3<<21 | v3>>43
	v3 ^= v0
	v2 += v1
	v1 = v1<<17 | v1>>47
	v1 ^= v2
	v2 = v2<<32 | v2>>32

	v0 += v1
	v1 = v1<<13 | v1>>51
	v1 ^= v0
	v0 = v0<<32 | v0>>32
	v2 += v3
	v3 = v3<<16 | v3>>48
	v3 ^= v2
	v0 += v3
	v3 = v3<<21 | v3>>43
	v3 ^= v0
	v2 += v1
	v1 = v1<<17 | v1>>47
	v1 ^= v2
	v2 = v2<<32 | v2>>32

	v0 ^= t

	// Finalization: 4 SipRounds.
	v2 ^= 0xff

	v0 += v1
	v1 = v1<<13 | v1>>51
	v1 ^= v0
	v0 = v0<<32 | v0>>32
	v2 += v3
	v3 = v3<<16 | v3>>48
	v3 ^= v2
	v0 += v3
	v3 = v3<<21 | v3>>43
	v3 ^= v0
	v2 += v1
	v1 = v1<<17 | v1>>47
	v1 ^= v2
	v2 = v2<<32 | v2>>32

	v0 += v1
	v1 = v1<<13 | v1>>51
	v1 ^= v0
	v0 = v0<<32 | v0>>32
	v2 += v3
	v3 = v3<<16 | v3>>48
	v3 ^= v2
	v0 += v3
	v3 = v3<<21 | v3>>43
	v3 ^= v0
	v2 += v1
	v1 = v1<<17 | v1>>47
	v1 ^= v2
	v2 = v2<<32 | v2>>32

	v0 += v1
	v1 = v1<<13 | v1>>51
	v1 ^= v0
	v0 = v0<<32 | v0>>32
	v2 += v3
	v3 = v3<<16 | v3>>48
	v3 ^= v2
	v0 += v3
	v3 = v3<<21 | v3>>43
	v3 ^= v0
	v2 += v1
	v1 = v1<<17 | v1>>47
	v1 ^= v2
	v2 = v2<<32 | v2>>32

	v0 += v1
	v1 = v1<<13 | v1>>51
	v1 ^= v0
	v0 = v0<<32 | v0>>32
	v2 += v3
	v3 = v3<<16 | v3>>48
	v3 ^= v2
	v0 += v3
	v3 = v3<<21 | v3>>43
	v3 ^= v0
	v2 += v1
	v1 = v1<<17 | v1>>47
	v1 ^= v2
	v2 = v2<<32 | v2>>32

	return v0 ^ v1 ^ v2 ^ v3
}
