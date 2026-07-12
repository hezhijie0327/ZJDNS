package main

import (
	"fmt"
	"runtime"
)

// ProjectName is the name of the project.
// Version is the current semantic version of the server.
// CommitHash is the git commit hash from which the binary was built.
// BuildTime is the UTC timestamp of when the binary was built.
var (
	ProjectName = "ZJDNS"
	Version     = "3.2.22"
	CommitHash  = "" // set via ldflags: -X main.CommitHash=$(git rev-parse --short HEAD)
	BuildTime   = "" // set via ldflags: -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)
)

func getVersion() string {
	if CommitHash != "" && BuildTime != "" {
		return fmt.Sprintf("v%s-%s@%s (%s)", Version, CommitHash, BuildTime, runtime.Version())
	}
	return fmt.Sprintf("v%s (%s)", Version, runtime.Version())
}
