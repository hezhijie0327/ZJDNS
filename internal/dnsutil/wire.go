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

// BoolToInt converts a bool to 0 or 1 for SQLite INTEGER columns.
func BoolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// JoinPlaceholders joins string parts with a separator, used for building
// parameterized SQL IN-clauses and VALUES lists.
func JoinPlaceholders(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	total := 0
	for _, p := range parts {
		total += len(p) + len(sep)
	}
	b := make([]byte, 0, total-len(sep))
	b = append(b, parts[0]...)
	for _, p := range parts[1:] {
		b = append(b, sep...)
		b = append(b, p...)
	}
	return string(b)
}
