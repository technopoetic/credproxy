package main

import (
	"fmt"
	"runtime/debug"
	"strings"
)

// versionString reports the binary's version using the module metadata Go
// embeds at build time. `go install module@version` stamps the tag (e.g.
// v0.2.1); a local `go build` reports "(devel)" plus the VCS revision.
func versionString() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "credproxy (unknown)"
	}

	var revision string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}

	return formatVersion(info.Main.Version, revision, dirty)
}

func formatVersion(moduleVersion, revision string, dirty bool) string {
	if moduleVersion != "" && moduleVersion != "(devel)" {
		return "credproxy " + moduleVersion
	}
	if revision == "" {
		return "credproxy devel"
	}
	rev := revision
	if len(rev) > 7 {
		rev = rev[:7]
	}
	var b strings.Builder
	fmt.Fprintf(&b, "credproxy devel (commit %s", rev)
	if dirty {
		b.WriteString(", dirty")
	}
	b.WriteString(")")
	return b.String()
}
