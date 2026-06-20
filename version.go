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
	Version     = "2.0.0"
	CommitHash  = "dirty"
	BuildTime   = "dev"
)

func getVersion() string {
	return fmt.Sprintf("v%s-%s@%s (%s)", Version, CommitHash, BuildTime, runtime.Version())
}
