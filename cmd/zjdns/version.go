package main

import (
	"fmt"
	"runtime"
	"strings"
)

// ProjectName is the name of the project.
// Version is the current semantic version of the server.
// CommitHash is the git commit hash from which the binary was built.
// BuildTime is the UTC timestamp of when the binary was built.
var (
	ProjectName = "ZJDNS"
	Version     = "3.9.1"
	CommitHash  = "" // set via ldflags: -X main.CommitHash=$(git rev-parse --short HEAD)
	BuildTime   = "" // set via ldflags: -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)
)

func getVersion() string {
	// Each ldflags-populated field is surfaced independently — a build
	// pipeline that sets only one of CommitHash/BuildTime still shows the
	// provenance it has instead of silently dropping both.
	base := fmt.Sprintf("v%s (%s)", Version, runtime.Version())
	var parts []string
	if CommitHash != "" {
		parts = append(parts, CommitHash)
	}
	if BuildTime != "" {
		parts = append(parts, BuildTime)
	}
	if len(parts) == 0 {
		return base
	}
	return fmt.Sprintf("v%s-%s (%s)", Version, strings.Join(parts, "@"), runtime.Version())
}
