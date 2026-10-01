// SPDX-License-Identifier: AGPL-3.0-only

package system

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/render"
)

// The review of the S1 uninstall path found
// the rule this file already applies to engine liveness missing from every
// other step: an error that means "I cannot tell" was read as "nothing
// there", or as "done".
//
// Each test below creates its failure with a wrong file type — ENOTDIR or
// ENOTEMPTY — because those are the errors no uid can bypass. The realistic
// trigger is EACCES on a directory the owner locked or a root-owned parent,
// which reaches the same non-ENOENT branch; it cannot be used in a test
// that may run as root, since root bypasses permission checks.

// paths points every path the uninstall touches at writable temp dirs.
func paths(t *testing.T) (state, home string) {
	t.Helper()
	state, home = t.TempDir(), t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	t.Setenv("HOME", home)
	return state, home
}

// Uninstall's one guard against destroying a learner's labs is the instance
// list. A list it could not read is not an empty one: the run aborts with
// PDR-E026 and removes nothing — before the confirmation, before the
// service is touched.
func TestUninstallRefusesAnUnreadableInstanceList(t *testing.T) {
	state, home := paths(t)
	if err := os.MkdirAll(filepath.Join(state, "podaro"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A regular file where the instances directory belongs: ReadDir → ENOTDIR.
	instances := filepath.Join(state, "podaro", "instances")
	if err := os.WriteFile(instances, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(UnitPath()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(UnitPath(), []byte("[Unit]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	code, err := Uninstall(render.New(&buf, false, true), func() bool {
		t.Error("confirm was reached: uninstall asked to remove things without knowing whether instances exist")
		return false
	})
	if err == nil {
		t.Fatalf("an unreadable instance list must abort the run: code=%d out=%q", code, buf.String())
	}
	// The literal code, not the constant: this test is also run against the
	// pre-fix commit, where the constant does not exist.
	if !strings.Contains(err.Error(), "PDR-E026") {
		t.Errorf("the abort must carry PDR-E026: %v", err)
	}
	if _, statErr := os.Stat(instances); statErr != nil {
		t.Errorf("the state directory was touched: %v", statErr)
	}
	if _, statErr := os.Stat(UnitPath()); statErr != nil {
		t.Errorf("the unit file was removed by a run that refused: %v", statErr)
	}
	_ = home
}

// A unit file that survives removal is the revival hazard the liveness
// probes exist to prevent — Restart=on-failure with the state gone. The row
// says what happened, the run fails, and nothing further is removed.
func TestUninstallReportsAUnitFileItCouldNotRemove(t *testing.T) {
	state, _ := paths(t)
	if err := os.MkdirAll(filepath.Join(state, "podaro"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A non-empty directory at the unit's path: os.Remove → ENOTEMPTY.
	if err := os.MkdirAll(filepath.Join(UnitPath(), "occupied"), 0o755); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	code := removeInstallation(render.New(&buf, false, true))
	out := buf.String()
	if code == 0 {
		t.Errorf("a unit that could not be removed must fail the run:\n%s", out)
	}
	if strings.Contains(out, "service stopped and removed") {
		t.Errorf("the run claimed the service was removed while its unit is still there:\n%s", out)
	}
	if !strings.Contains(out, "unit removal failed") {
		t.Errorf("the failure is not reported:\n%s", out)
	}
	if _, err := os.Stat(config.StateDir()); err != nil {
		t.Errorf("state was removed under a unit that survived: %v", err)
	}
	// A failing row is readable: label, then the column, then the detail.
	if !regexp.MustCompile(`(?m)^✗ unit removal failed {2,}\S`).MatchString(out) {
		t.Errorf("the failure row runs its label into its detail:\n%s", out)
	}
}

// "binary not installed" is a claim. When the binary cannot be looked at,
// the run says that instead of guessing that it is gone.
func TestUninstallReportsABinaryItCannotSee(t *testing.T) {
	state, home := paths(t)
	if err := os.MkdirAll(filepath.Join(state, "podaro"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A regular file where ~/.local/bin belongs: Stat of the binary → ENOTDIR.
	if err := os.MkdirAll(filepath.Join(home, ".local"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".local", "bin"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	code := removeInstallation(render.New(&buf, false, true))
	out := buf.String()
	if strings.Contains(out, "binary not installed") {
		t.Errorf("the run reported the binary absent when it could not look:\n%s", out)
	}
	if code == 0 || !strings.Contains(out, "binary state unknown") {
		t.Errorf("an unreadable binary path must fail the run and say so: code=%d\n%s", code, out)
	}
}

// Every failing row in this path carries its column, so the detail never
// runs into the label. Two of them need a tree that refuses deletion, which
// only an unprivileged owner can build, so the guard is on the source: no
// detail may be printed against width 0.
func TestUninstallFailureRowsCarryTheirColumn(t *testing.T) {
	src, err := os.ReadFile("uninstall.go")
	if err != nil {
		t.Fatal(err)
	}
	if m := regexp.MustCompile(`render\.Fail, "[^"]+", 0, [a-z]`).FindAllString(string(src), -1); m != nil {
		t.Errorf("failing rows print a detail with no column: %v", m)
	}
}
