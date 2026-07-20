package dnsutil

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"zjdns/internal/log"
)

const (
	downloadTimeout    = 30 * time.Second
	otherWritePermMask = 0o022 // group/other write — root data files must be owner-writable only
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
	// Warn if the file is group/other writable — root data files contain
	// cryptographic trust material and must be protected from tampering.
	if info, err := os.Stat(path); err == nil {
		if info.Mode().Perm()&otherWritePermMask != 0 {
			log.Warnf("CONFIG: root data file has insecure permissions (%04o). Consider 'chmod 644 %s'",
				info.Mode().Perm(), path)
		}
	}
	return path
}

// DownloadFile fetches a URL and writes the content to a local file.
func DownloadFile(url, path string) error {
	resp, err := downloadClient.Get(url) //nolint:gosec // callers pass hardcoded URLs
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	//nolint:gosec // callers pass paths from os.Executable() or config
	return os.WriteFile(path, data, 0o644)
}
