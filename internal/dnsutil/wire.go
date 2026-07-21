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
