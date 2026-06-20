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

// BudgetBytes returns the memory budget in bytes for the cache, derived from
// a percentage of total system memory. percent is the fraction (1-100).
// Falls back to def bytes if memory detection fails.
func BudgetBytes(percent int, def int64) int64 {
	total := TotalBytes()
	if total == 0 {
		return def
	}
	budget := int64(total) * int64(percent) / 100
	if budget < def {
		return def
	}
	return budget
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
