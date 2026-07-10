package cache

import (
	"fmt"

	"github.com/klauspost/compress/zstd"
)

const (
	zstdCompressLevel = zstd.SpeedDefault
)

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

// ── Wire format compression ──────────────────────────────────────────────────

func compress(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	return zstdEncoder.EncodeAll(data, nil)
}

func decompress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	return zstdDecoder.DecodeAll(data, nil)
}
