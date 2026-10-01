// SPDX-License-Identifier: AGPL-3.0-only

package state

import (
	"path/filepath"
	"testing"
	"time"
)

// Migration 11 marked every pre-existing job `-1`, on the reasoning that
// a job survives its instance on purpose and a surviving row proves
// nothing. That is right for a job that has finished and wrong for one
// still running: an upgrade promises persistent jobs are reattached, and
// `Engine.Start` resumes exactly those rows against the instance that is
// there now. Marked `-1`, the resumed job matched no generation, so the
// attendee whose session carries the instance's real `audit_from` could
// neither poll it nor follow its events — the create they were watching
// vanished across the upgrade that promises it would not.
//
// An active job for an instance that still exists belongs to that
// instance as it stands. A finished one keeps the sentinel, and so does
// an active row whose instance is gone.
func TestMigrationKeepsAResumableJobReachable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	full := migrationSet
	migrationSet = func() []string { return full()[:10] }
	old, err := OpenSQLite(path)
	if err != nil {
		migrationSet = full
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := old.db.Exec(`insert into instances (name, template, version, profile, mode, source, created, updated, stage, licenses, seed_salt, audit_from)
		values ('class', 't', '', '', 'delivery', '/s', ?, ?, 'ready', '', '', 7)`, fmtTime(now), fmtTime(now)); err != nil {
		migrationSet = full
		t.Fatal(err)
	}
	for _, j := range []struct{ id, instance, state string }{
		{"job_running", "class", "running"},
		{"job_queued", "class", "queued"},
		{"job_done", "class", "succeeded"},
		{"job_orphan", "gone", "running"},
	} {
		if _, err := old.db.Exec(`insert into jobs (id, kind, instance, state, stage, started, seq)
			values (?, 'create', ?, ?, '', ?, 0)`, j.id, j.instance, j.state, fmtTime(now)); err != nil {
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
	gen := func(id string) int64 {
		t.Helper()
		var g int64
		if err := store.db.QueryRow(`select gen from jobs where id = ?`, id).Scan(&g); err != nil {
			t.Fatal(err)
		}
		return g
	}
	for _, id := range []string{"job_running", "job_queued"} {
		if got := gen(id); got != 7 {
			t.Errorf("%s has gen %d after the upgrade — the lab it is being resumed for is generation 7, "+
				"and its attendee can neither poll it nor follow it", id, got)
		}
	}
	// A finished job keeps the sentinel: it is the record of what
	// happened, and a name used twice cannot tell whose it was.
	if got := gen("job_done"); got != -1 {
		t.Errorf("a finished job was given a generation it cannot be known to belong to: %d", got)
	}
	// And an active row whose instance is gone has nothing to belong to.
	if got := gen("job_orphan"); got != -1 {
		t.Errorf("an active job for an instance that no longer exists was given generation %d", got)
	}
}
