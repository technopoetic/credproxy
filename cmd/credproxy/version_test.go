package main

import "testing"

func TestFormatVersion(t *testing.T) {
	cases := []struct {
		name      string
		moduleVer string
		revision  string
		dirty     bool
		want      string
	}{
		{name: "tagged install", moduleVer: "v0.2.1", want: "credproxy v0.2.1"},
		{name: "local build clean", moduleVer: "(devel)", revision: "abdda48f1e2b", want: "credproxy devel (commit abdda48)"},
		{name: "local build dirty", moduleVer: "(devel)", revision: "abdda48f1e2b", dirty: true, want: "credproxy devel (commit abdda48, dirty)"},
		{name: "devel no vcs info", moduleVer: "(devel)", want: "credproxy devel"},
		{name: "empty version with revision", revision: "1234567890ab", want: "credproxy devel (commit 1234567)"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatVersion(tc.moduleVer, tc.revision, tc.dirty)
			if got != tc.want {
				t.Errorf("formatVersion(%q, %q, %v) = %q, want %q", tc.moduleVer, tc.revision, tc.dirty, got, tc.want)
			}
		})
	}
}
