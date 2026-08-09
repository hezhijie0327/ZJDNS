// Package dnscryptstate persists the DNSCrypt provider identity and cert
// windows to a file, replacing the former SQLite dnscrypt_state table.
package dnscrypt

import (
	"encoding/binary"
	"errors"
	"os"
)

// FileStore persists the DNSCrypt identity + cert windows to a single small
// file (identity 96B + windows blob).  Written once per cert rotation,
// loaded once at startup — no atomicity needed beyond WriteFile semantics.
type FileStore struct {
	path string
}

// NewFileStore creates a FileStore writing to path.  An empty path disables
// persistence — the identity and cert windows are re-minted on every restart
// and no file is created, matching the cache/latency/delegation stores'
// empty-state_file semantics.
func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

// LoadDNSCryptState returns the persisted identity and windows blobs.
// Returns (nil, nil, nil) when persistence is disabled or no state file
// exists yet.
func (s *FileStore) LoadDNSCryptState() (identity, windows []byte, err error) {
	if s.path == "" {
		return nil, nil, nil // persistence disabled — start fresh
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	// Layout: [1B ver][96B identity][2B windows_len][windows]
	if len(data) < 1+96+2 || data[0] != stateLayoutVersion {
		return nil, nil, errors.New("dnscryptstate: corrupt state file")
	}
	identity = data[1:97]
	wlen := int(binary.BigEndian.Uint16(data[97:99]))
	if len(data) != 99+wlen {
		return nil, nil, errors.New("dnscryptstate: corrupt state file (length mismatch)")
	}
	return identity, data[99:], nil
}

// SaveDNSCryptState writes the identity and windows blobs to the state file.
// No-op when persistence is disabled.
func (s *FileStore) SaveDNSCryptState(identity, windows []byte) error {
	if s.path == "" {
		return nil // persistence disabled
	}
	if len(identity) != 96 {
		return errors.New("dnscryptstate: identity must be 96 bytes")
	}
	buf := make([]byte, 0, 99+len(windows))
	buf = append(buf, stateLayoutVersion)
	buf = append(buf, identity...)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(windows))) //nolint:gosec // G115: windows blob is a few hundred bytes
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, windows...)
	return os.WriteFile(s.path, buf, 0o600)
}
