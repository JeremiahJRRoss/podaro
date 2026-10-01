// SPDX-License-Identifier: AGPL-3.0-only

package state

import (
	"path/filepath"
	"testing"
	"time"
)

// Plan S14 — migration 15, the high-water mark.
//
// A regression is a fall *from* ready (UX §5) and the stage alone cannot
// say one happened: a lab at `seeded` may be climbing for the first time
// or may have fallen back an hour ago. The mark is what tells them
// apart, and an existing state file has no record of it.
//
// The backfill claims only what it can: each row's mark becomes the
// stage it stands at. A lab that had already fallen before this column
// existed therefore reads as one that never reached ready — it says less
// and nothing untrue, which is the rule migration 14 settled for the run
// facts. Its own next climb to ready records the mark, and from there
// the fall is sayable.
func TestMigrationBackfillsTheMarkFromTheStageAndClaimsNoMore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	full := migrationSet
	migrationSet = func() []string { return full()[:14] }
	old, err := OpenSQLite(path)
	if err != nil {
		migrationSet = full
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	for _, r := range []struct{ name, stage string }{
		{"standing", "ready"},
		{"climbing", "seeded"},
		{"fallen-before-the-upgrade", "seeded"},
	} {
		if _, err := old.db.Exec(`insert into instances (name, template, version, profile, mode, source, created, updated, stage, licenses, seed_salt, audit_from)
			values (?, 't', '', '', 'delivery', '/s', ?, ?, ?, '', '', 0)`, r.name, fmtTime(now), fmtTime(now), r.stage); err != nil {
			migrationSet = full
			t.Fatal(err)
		}
	}
	if err := old.Close(); err != nil {
		migrationSet = full
		t.Fatal(err)
	}
	migrationSet = full

	store, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, c := range []struct{ name, stage, mark Stage }{
		{"standing", StageReady, StageReady},
		{"climbing", StageSeeded, StageSeeded},
		// Indistinguishable from the one above, and deliberately so: the
		// upgrade cannot know it had been ready, so it does not say so.
		{"fallen-before-the-upgrade", StageSeeded, StageSeeded},
	} {
		in, err := store.GetInstance(string(c.name))
		if err != nil {
			t.Fatalf("%s after the upgrade: %v", c.name, err)
		}
		if in.Stage != c.stage || in.Reached != c.mark {
			t.Errorf("%s: stage %q mark %q, want stage %q mark %q", c.name, in.Stage, in.Reached, c.stage, c.mark)
		}
	}
	// And the column is live from here: a stage written low leaves the
	// mark where the upgrade put it.
	in, _ := store.GetInstance("standing")
	in.Stage = StageSeeded
	if err := store.PutInstance(*in); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.GetInstance("standing"); got.Stage != StageSeeded || got.Reached != StageReady {
		t.Errorf("the mark outlives a lowered stage: %+v", got)
	}
}
