// Package siphash provides a self-contained implementation of SipHash-2-4
// (64-bit output) per the reference specification at https://131002.net/siphash/.
package siphash

import (
	"encoding/binary"
	"math/bits"
)

// Sum64 computes the SipHash-2-4 64-bit MAC of msg under the given key.
func Sum64(key *[16]byte, msg []byte) uint64 {
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
		sipRound(&v0, &v1, &v2, &v3)
		sipRound(&v0, &v1, &v2, &v3)
		v0 ^= m
		msg = msg[8:]
	}

	var last uint64
	for i := len(msg) - 1; i >= 0; i-- {
		last |= uint64(msg[i]) << (i * 8)
	}
	last |= b

	v3 ^= last
	sipRound(&v0, &v1, &v2, &v3)
	sipRound(&v0, &v1, &v2, &v3)
	v0 ^= last

	v2 ^= 0xff
	sipRound(&v0, &v1, &v2, &v3)
	sipRound(&v0, &v1, &v2, &v3)
	sipRound(&v0, &v1, &v2, &v3)
	sipRound(&v0, &v1, &v2, &v3)

	return v0 ^ v1 ^ v2 ^ v3
}

func sipRound(v0, v1, v2, v3 *uint64) {
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
