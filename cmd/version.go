package cmd

import (
	"fmt"
	"runtime/debug"
	"strings"
)

// Build identifies the binary, as the version command prints it.
type Build struct {
	Version string
	Commit  string
	Date    string
}

func (b Build) String() string {
	return fmt.Sprintf("technitium-configurator %s (commit %s, built %s)", b.Version, b.Commit, b.Date)
}

// ResolveBuild completes b, as -ldflags set it, from the build information Go
// records in the binary, so that `go install module@version` and builds from a
// checkout report their version and commit too.
func ResolveBuild(b Build) Build {
	info, _ := debug.ReadBuildInfo()
	return resolveBuild(b, info)
}

func resolveBuild(b Build, info *debug.BuildInfo) Build {
	if info != nil {
		// "(devel)" is what Go records when it knows no version.
		if b.Version == "" && info.Main.Version != "" && info.Main.Version != "(devel)" {
			b.Version = strings.TrimPrefix(info.Main.Version, "v")
		}
		// vcs.time is the commit's time, not the build's, so Date stays unset.
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && b.Commit == "" {
				b.Commit = s.Value
			}
		}
	}
	if b.Version == "" {
		b.Version = "dev"
	}
	if b.Commit == "" {
		b.Commit = "unknown"
	}
	if b.Date == "" {
		b.Date = "unknown"
	}
	return b
}
