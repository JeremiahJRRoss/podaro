// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"sort"
	"strings"
	"testing"
)

// The reconciliation plan's R6, task 2: the identity guard
// (hack/identity_guard.sh) reads `podaro <command> --help` for every
// command the binary has — the hidden ones too, which the help listing
// leaves out — so it takes the list from this test and runs each command
// on the binary it built. The test is the list's own check: every command
// in the tree, hidden or not, says what it is and renders its help without
// an error, and `go test -v -run TestEveryCommandRendersItsHelp` prints one
// "command: podaro <path>" line per command for the guard to read.
func TestEveryCommandRendersItsHelp(t *testing.T) {
	valid, _ := commandPaths(newRoot())
	paths := []string{""}
	for p := range valid {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		args := strings.Fields(p)
		root := newRoot()
		cmd, _, err := root.Find(args)
		if err != nil || cmd == nil {
			t.Errorf("podaro %s: not found in the tree it came from (%v)", p, err)
			continue
		}
		if strings.TrimSpace(cmd.Short) == "" {
			t.Errorf("podaro %s: no Short — its help does not say what it is", p)
		}
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs(append(args, "--help"))
		if err := root.Execute(); err != nil {
			t.Errorf("podaro %s --help: %v", p, err)
			continue
		}
		if !strings.Contains(out.String(), "Usage:") {
			t.Errorf("podaro %s --help printed no usage:\n%s", p, out.String())
			continue
		}
		t.Logf("command: %s", strings.TrimSpace("podaro "+p))
	}
}
