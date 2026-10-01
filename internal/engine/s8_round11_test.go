// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Round 1 taught `readAsset` to refuse a `source:` that reaches outside
// the template through a symlink. A delivery instance never reaches that
// check with a symlink to refuse: Engine.Create snapshots the tree
// FIRST, and copyTree reads every non-directory entry with os.ReadFile,
// which follows the link. The host file's contents land in the snapshot
// as an ordinary file, and validation — running afterwards, on the
// snapshot — sees nothing to object to. The template then ships that
// content into the container.
//
// The wall belongs where the copy happens, which is also the earliest
// point and covers the whole tree rather than the declared assets alone.
func TestASnapshotRefusesASymlinkOutOfTheTemplate(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "host-secret")
	if err := os.WriteFile(outside, []byte("a host file the template does not ship\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "lab.yaml"), []byte("kind: Template\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(src, "assets", "external")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("this filesystem does not do symlinks: %v", err)
	}

	// The premise: the link really does reach the host file, so the case
	// is about a copy that follows it and not about a broken link.
	if raw, err := os.ReadFile(link); err != nil || !strings.Contains(string(raw), "host file") {
		t.Fatalf("the fixture's link does not reach the outside file: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "snapshot")
	err := copyTree(src, dst)
	if err == nil {
		if raw, readErr := os.ReadFile(filepath.Join(dst, "assets", "external")); readErr == nil {
			t.Fatalf("the snapshot admitted a host file the template does not ship: %q", strings.TrimSpace(string(raw)))
		}
		t.Fatal("a symlink out of the template was copied without complaint")
	}
	if !strings.Contains(err.Error(), "assets/external") || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("the refusal should name the link: %v", err)
	}
}
