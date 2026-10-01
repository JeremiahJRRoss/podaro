// SPDX-License-Identifier: AGPL-3.0-only

package system

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/state"
)

// The downgrade guard stripped a pre-release suffix before comparing, so
// 1.0.0 and 1.0.0-rc1 were equal: `--to 1.0.0-rc1` from a released 1.0.0
// was not a downgrade and went ahead, installing older code over state
// the newer release had migrated. That is the one thing the guard is
// for. Pre-releases are compared now, by SemVer §11 precedence.
func TestADowngradeIsOneEvenWhenThePrereleaseHidesIt(t *testing.T) {
	for _, c := range []struct {
		candidate, current string
		want               bool
	}{
		{"1.0.0-rc1", "1.0.0", true},  // a pre-release is below its release
		{"1.0.0", "1.0.0-rc1", false}, // and the release is above it
		{"1.0.0-rc1", "1.0.0-rc2", true},
		{"1.0.0-rc2", "1.0.0-rc1", false},
		{"1.0.0-rc1", "1.0.0-rc1", false}, // the same version is not older
		// SemVer §11.4: numeric identifiers rank below alphanumeric
		// ones, and a shorter run of otherwise equal fields is lower.
		{"1.0.0-1", "1.0.0-alpha", true},
		{"1.0.0-alpha", "1.0.0-alpha.1", true},
		{"1.0.0-alpha.1", "1.0.0-alpha", false},
		// Build metadata takes no part in precedence (§10).
		{"1.0.0+build.9", "1.0.0+build.1", false},
		{"1.0.0-rc1+build.9", "1.0.0", true},
		// The numbers still decide first.
		{"0.9.9", "1.0.0-rc1", true},
		{"1.0.1-rc1", "1.0.0", false},
		// A version this cannot read is not called older: refusing an
		// upgrade over a parse is worse than performing one.
		{"not-a-version", "1.0.0", false},
		{"1.0.0", "not-a-version", false},
	} {
		if got := older(c.candidate, c.current); got != c.want {
			t.Errorf("older(%q, %q) = %v, want %v", c.candidate, c.current, got, c.want)
		}
	}
}

// Round 7: a retried upgrade must not destroy the rollback copy it
// already has before making its replacement. `vacuum into` refuses an
// existing file, so the old backup was removed first — and an
// interruption in that window left the binary intact and the recovery
// point gone.
func TestARetriedBackupKeepsTheOneItHasUntilTheNewOneIsWhole(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "state.db")
	store, err := state.OpenSQLite(src)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC().Truncate(time.Second)
	if err := store.PutInstance(state.Instance{Name: "class", Template: "t", Mode: "delivery",
		Source: "/s", Created: now, Updated: now}); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "state.db.bak-v0.0.1-dev")
	if ok, err := backupState(src, dst); err != nil || !ok {
		t.Fatalf("the first backup: %v %v", ok, err)
	}

	// The retry: the same command again, over the backup it made. The
	// old one is still readable at every point, and the new one replaces
	// it whole.
	if ok, err := backupState(src, dst); err != nil || !ok {
		t.Fatalf("the retried backup: %v %v", ok, err)
	}
	if got := backedUpInstances(t, dst); len(got) != 1 || got[0].Name != "class" {
		t.Errorf("the retried backup holds %+v", got)
	}
	// And nothing is left beside it: the partial name is the working
	// file, not a second artefact an operator has to reason about.
	if _, err := os.Stat(dst + ".partial"); !os.IsNotExist(err) {
		t.Errorf("a partial backup was left behind: %v", err)
	}

	// A backup that cannot be made leaves the one that exists alone —
	// the property the removal destroyed. The source is made unreadable
	// as a database *after* a good backup exists, which is the shape of
	// the real failure: the second attempt cannot produce anything, and
	// the question is whether the first survives it.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("not a database any more"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := backupState(src, dst); err == nil {
		t.Fatal("a backup that cannot be written should say so")
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("the failed attempt destroyed the backup it already had: %v", err)
	}
	if got := backedUpInstances(t, dst); len(got) != 1 || got[0].Name != "class" {
		t.Errorf("the backup that survived is not the one that was made: %+v", got)
	}
}
