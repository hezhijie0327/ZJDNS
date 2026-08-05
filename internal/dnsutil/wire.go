package dnsutil

import (
	"fmt"

	"github.com/klauspost/compress/zstd"
)

const zstdCompressLevel = zstd.SpeedDefault

// zstd encoder/decoder for wire format compression. Created once, reused forever.
var (
	zstdEncoder *zstd.Encoder
	zstdDecoder *zstd.Decoder
)

func init() {
	var err error
	zstdEncoder, err = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstdCompressLevel))
	if err != nil {
		panic(fmt.Sprintf("zstd encoder init: %v", err))
	}
	zstdDecoder, err = zstd.NewReader(nil)
	if err != nil {
		panic(fmt.Sprintf("zstd decoder init: %v", err))
	}
}

// Compress compresses data with zstd. Returns nil for empty input.
func Compress(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	return zstdEncoder.EncodeAll(data, nil)
}

// Decompress decompresses data with zstd. Returns nil for empty input.
func Decompress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	return zstdDecoder.DecodeAll(data, nil)
}

// DecompressTo decompresses data with zstd, using dst as the output buffer
// when it has enough capacity (avoids allocation on the hot path, P3).
func DecompressTo(data, dst []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	return zstdDecoder.DecodeAll(data, dst[:0])
}

// SkipWireName returns the offset after the domain name at pos in a packed
// DNS message.  Handles both label sequences and compression pointers
// (RFC 1035 §4.1.4).  Returns ok=false when the walk runs past the wire end.
// The single shared implementation — bridge.go truncation and the cache's
// TTL-offset scans previously each carried their own copy, which diverged
// (the cache copy stopped at any NUL byte; the bridge copy handled pointers
// correctly — R3-L24 family).
func SkipWireName(wire []byte, pos int) (int, bool) {
	for {
		if pos >= len(wire) {
			return 0, false
		}
		l := wire[pos]
		if l == 0 {
			return pos + 1, true
		}
		if l&0xC0 == 0xC0 {
			// Compression pointer — skip 2 bytes, name ends here.
			return pos + 2, true
		}
		// Label: l bytes of label data.
		pos += int(l) + 1
	}
}
