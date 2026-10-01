// SPDX-License-Identifier: AGPL-3.0-only

package podaro

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestVersionMatchesFile(t *testing.T) {
	raw, err := os.ReadFile("VERSION")
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	if got, want := Version(), strings.TrimSpace(string(raw)); got != want {
		t.Fatalf("Version() = %q, VERSION file = %q", got, want)
	}
}

func TestVersionIsSemver(t *testing.T) {
	semver := regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)
	if v := Version(); !semver.MatchString(v) {
		t.Fatalf("Version() = %q, not a semantic version", v)
	}
}
