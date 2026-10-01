// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// Review round 20, the two P3 findings — as a rule
// rather than two strings.
//
// An error's `next` is the line an operator types. Two of them named
// commands the CLI does not register: `podaro access grant` (the command
// is `access create`) and `podaro list` (instance discovery is `podaro
// status`). Following either produces an unknown-command error, in the
// exact moment the hint exists to rescue.
//
// So this walks the real command tree and every remediation in the
// source, and fails on any hint naming something that cannot be run.
// The rule is deliberately narrow — it reads `Next` literals, not prose
// — because those are what UX §7 promises are runnable.
func TestEveryRemediationNamesACommandThatExists(t *testing.T) {
	valid, group := commandPaths(newRoot())
	root := filepath.Join("..", "..")
	hint := regexp.MustCompile(`Next\s*[:=]\s*"((?:[^"\\]|\\.)*)"`)
	// The command a hint names: `podaro` and the one or two lowercase
	// words after it. A third word is never part of a path here — the
	// tree is two deep at most (`auth token create` is reached by its
	// two-word parent being a group).
	named := regexp.MustCompile(`podaro ([a-z][a-z-]*)(?: ([a-z][a-z-]*))?`)

	var bad []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if name := info.Name(); name == ".git" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range hint.FindAllStringSubmatch(string(raw), -1) {
			for _, c := range named.FindAllStringSubmatch(m[1], -1) {
				first, second := c[1], c[2]
				switch {
				case !valid[first]:
					bad = append(bad, path+": podaro "+first+" — no such command")
				case group[first] && !valid[first+" "+second]:
					bad = append(bad, path+": podaro "+first+" "+second+" — "+first+" has no such subcommand")
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bad {
		t.Errorf("a remediation names something an operator cannot run — %s", b)
	}
}

// commandPaths is every runnable path in the tree ("access", "access
// create", …) and which of them are groups, whose own name is not a
// command an operator can run alone.
func commandPaths(root *cobra.Command) (valid, group map[string]bool) {
	valid, group = map[string]bool{}, map[string]bool{}
	var walk func(prefix string, c *cobra.Command)
	walk = func(prefix string, c *cobra.Command) {
		for _, sub := range c.Commands() {
			name := strings.Fields(sub.Use)[0]
			path := strings.TrimSpace(prefix + " " + name)
			valid[path] = true
			if len(sub.Commands()) > 0 && sub.Run == nil && sub.RunE == nil {
				group[path] = true
			}
			walk(path, sub)
		}
	}
	walk("", root)
	return valid, group
}
