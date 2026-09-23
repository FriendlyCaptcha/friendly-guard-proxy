// Package buildinfo provides information about the build of the binary.
// The data in this package is injected by GoReleaser, or queried from runtime.
package buildinfo

import (
	"fmt"
	"runtime"
)

// Fields injected by GoReleaser.
var (
	version    = "0.0.0"
	commitDate = "date unknown"
	commit     = ""
)

// Version returns the binary version, or "0.0.0" if not injected.
func Version() string {
	return version
}

// CommitDate returns the commit date, or "date unknown" if not injected.
func CommitDate() string {
	return commitDate
}

// Commit returns the commit hash, or "" if not injected.
func Commit() string {
	return commit
}

// Target returns the target OS of the build.
func Target() string {
	return runtime.GOOS
}

// FullVersion returns the version, target OS and architecture, runtime version,
// commit date, and commit hash.
func FullVersion() string {
	return fmt.Sprintf("%s %s/%s %s (%s) %s",
		version, runtime.GOOS, runtime.GOARCH, runtime.Version(), commitDate, commit)
}
