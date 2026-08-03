// Package persist provides zstd-compressed atomic file persistence — the
// shared IO substrate for per-subsystem persist files (cache entries,
// DNSCrypt state, stats). Each subsystem owns its file format; this package
// owns the compression and the crash-safe write.
package persist

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
)

// maxDecompressedBytes caps decompressed output: a corrupt or tampered file
// with a huge compression ratio must surface as a load error (backed up,
// cold start) instead of an OOM at startup — Load runs before any version
// check. Far above any legit persist file.
const maxDecompressedBytes = 512 << 20 // 512 MiB

// Save compresses data with zstd (fastest level) and atomically writes it to
// path (temp + rename, so a crash never leaves a truncated file). The parent
// directory must exist.
func Save(path string, data []byte) error {
	compressed, err := compress(data)
	if err != nil {
		return fmt.Errorf("persist: compress: %w", err)
	}
	if err := atomicWrite(path, compressed); err != nil {
		return fmt.Errorf("persist: write %s: %w", path, err)
	}
	return nil
}

// Load reads and decompresses the file at path. A missing file is not an
// error: it returns (nil, nil) so callers can treat it as a cold start.
// Corrupt files are surfaced as errors — silently discarding them would
// hide data loss.
func Load(path string) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is operator-configured persist file
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil //nolint:nilnil // cold start — missing file is not an error
		}
		return nil, fmt.Errorf("persist: read %s: %w", path, err)
	}
	raw, err := decompress(data)
	if err != nil {
		return nil, fmt.Errorf("persist: decompress %s: %w", path, err)
	}
	return raw, nil
}

// ── zstd ───────────────────────────────────────────────────────────────

// compress compresses raw with the fastest level — persist files are written
// at shutdown / rotation only, so latency is irrelevant.
func compress(raw []byte) ([]byte, error) {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		return nil, err
	}
	defer func() { _ = enc.Close() }()
	return enc.EncodeAll(raw, nil), nil
}

// decompress decompresses raw. Output is capped at maxDecompressedBytes (see
// above) so corrupt input cannot OOM the process at startup.
func decompress(raw []byte) ([]byte, error) {
	dec, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(maxDecompressedBytes))
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	out, err := dec.DecodeAll(raw, nil)
	if err != nil {
		return nil, err
	}
	if len(out) > maxDecompressedBytes {
		return nil, fmt.Errorf("persist: decompressed size %d exceeds limit %d", len(out), maxDecompressedBytes)
	}
	return out, nil
}

// Backup renames path to path+".bak", preserving a previous-format or
// corrupt persist file before it would be overwritten by a fresh write.
// Missing source is a no-op. The previous .bak is replaced (only the most
// recent backup survives).
func Backup(path string) error {
	backup := path + ".bak"
	_ = os.Remove(backup) //nolint:gosec // G703: Windows rename fails when the target exists
	if err := os.Rename(path, backup); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return nil
}

// ── Atomic write ───────────────────────────────────────────────────────

// atomicWrite writes data to path via a temp file in the same directory and
// an atomic rename, so a crash mid-write never leaves a truncated persist
// file. The directory must exist.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".zjdns-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}
