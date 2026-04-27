// Package main implements ZJDNS, a high-performance DNS server that supports DoT, DoH, DoQ, DoH3, and recursive resolution.
package main

import (
	"fmt"
	"runtime"
)

// Version information contains the current build version.

var (
	ProjectName = "ZJDNS" // ProjectName is the name of the project
	Version     = "1.6.0" // Version is the current version of ZJDNS
	CommitHash  = "dirty" // CommitHash is the git commit hash (set during build)
	BuildTime   = "dev"   // BuildTime is the build timestamp (set during build)
)

func getVersion() string {
	return fmt.Sprintf("v%s-%s@%s (%s)", Version, CommitHash, BuildTime, runtime.Version())
}
