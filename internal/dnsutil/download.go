package dnsutil

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"zjdns/internal/log"
)

const (
	downloadTimeout    = 30 * time.Second // matches config.DefaultRootDownloadTimeout
	otherWritePermMask = 0o022            // group/other write — root data files must be owner-writable only
)

var downloadClient = &http.Client{Timeout: downloadTimeout}

// rootFilesDir is an optional custom directory for root data files.
// When empty, files are auto-detected from the binary's directory.
var rootFilesDir string

// SetRootFilesDir sets the directory where root data files are looked up.
func SetRootFilesDir(dir string) {
	rootFilesDir = dir
}

// ResolveDataFile returns the path for a root data file. Uses the directory
// set by SetRootFilesDir if available; otherwise auto-detects from the
// binary's directory. If the file does not exist, attempts to download it
// from url. Writes to path and returns it, or returns "" on failure.
func ResolveDataFile(name, url string) string {
	var path string
	if rootFilesDir != "" {
		path = filepath.Join(rootFilesDir, name)
	} else if execPath, err := os.Executable(); err == nil {
		path = filepath.Join(filepath.Dir(execPath), name)
	}
	if path == "" {
		return ""
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := DownloadFile(url, path); err != nil {
			return ""
		}
	}
	// Refuse to load group/other-writable files — root data files contain
	// cryptographic trust material; a writable file can be tampered with by
	// any local user. Fail closed rather than loading potentially-modified
	// trust material. Windows has no POSIX permission model: Mode().Perm()
	// is always 0666-ish there, so the check would reject every file — skip it.
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err == nil {
			if info.Mode().Perm()&otherWritePermMask != 0 {
				log.Errorf("CONFIG: root data file %s has insecure permissions (%04o) — refusing to load trust material; run 'chmod 644 %s'",
					path, info.Mode().Perm(), path)
				return ""
			}
		}
	}
	return path
}

// DownloadFile fetches a URL and writes the content to a local file.
// The download is written to a temporary file and atomically renamed into
// place, so an interrupted download can never leave a partial file that a
// later start would treat as valid trust material.
func DownloadFile(url, path string) error {
	resp, err := downloadClient.Get(url) //nolint:gosec // callers pass hardcoded URLs
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }() // _ = error: body close after read, best-effort

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // cleanup if any step below fails

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("download %s: %w", url, err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	// Sync before the rename: after a crash the final path must never hold
	// a truncated/zero-length file that a later start would treat as valid
	// trust material.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	return os.Rename(tmpName, path)
}
