// Package snapfile provides generic atomic key-value snapshots: a magic +
// version header followed by a callback-serialised entry stream, written via
// temp file + rename so a crash never corrupts the previous snapshot.  Used
// by the cache, latency and delegation stores for restart persistence.
package snapfile

import (
	"errors"
	"io"
	"os"
)

// Magic identifies a snapshot file.
const Magic = "ZJNS"

// Save writes the entry stream produced by writeEntry to path atomically
// (temp file + rename).  writeEntry is called once per entry; returning an
// error aborts the save.
func Save(path string, version byte, writeEntry func(w io.Writer) error) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp) //nolint:gosec // G304: path from trusted config
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }() // no-op after a successful rename

	if _, err := f.WriteString(Magic); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write([]byte{version}); err != nil {
		_ = f.Close()
		return err
	}
	if err := writeEntry(f); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load reads a snapshot file, calling readEntry for each entry until EOF.
// A missing file returns nil (start cold); a wrong magic or version returns
// nil as well (foreign or outdated file — also start cold).  readEntry
// returning an error aborts the load.
func Load(path string, version byte, readEntry func(r io.Reader) error) error {
	f, err := os.Open(path) //nolint:gosec // G304: path from trusted config
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer func() { _ = f.Close() }()

	magic := make([]byte, len(Magic))
	if _, err := io.ReadFull(f, magic); err != nil || string(magic) != Magic {
		return nil
	}
	var versionByte [1]byte
	if _, err := io.ReadFull(f, versionByte[:]); err != nil || versionByte[0] != version {
		return nil
	}
	for {
		if err := readEntry(f); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}
