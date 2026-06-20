// Package sysmem provides cross-platform total system memory detection.
package sysmem

import (
	"bufio"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// TotalBytes returns the total physical memory in bytes, or 0 if detection fails.
func TotalBytes() uint64 {
	switch runtime.GOOS {
	case "linux":
		return detectLinux()
	case "darwin":
		return detectDarwin()
	default:
		return 0
	}
}

// CacheSize returns a recommended cache entry count based on a percentage of
// system memory. percent is the fraction (1-100) of total memory to budget.
// avgEntryBytes is the estimated average size of a cache entry in bytes.
// Falls back to def entries if memory detection fails.
func CacheSize(percent int, avgEntryBytes, def int) int {
	total := TotalBytes()
	if total == 0 {
		return def
	}
	budget := total * uint64(percent) / 100
	entries := int(budget / uint64(avgEntryBytes))
	if entries < def {
		return def
	}
	return entries
}

func detectLinux() uint64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.ParseUint(fields[1], 10, 64)
				if err == nil {
					return kb * 1024
				}
			}
		}
	}
	return 0
}

func detectDarwin() uint64 {
	out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
	if err != nil {
		return 0
	}
	bytes, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return 0
	}
	return bytes
}
