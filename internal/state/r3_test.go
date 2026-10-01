// SPDX-License-Identifier: AGPL-3.0-only

package state

import (
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// The reconciliation plan's R3 — installed state survives the retirement.
// Migration 16 adds the unsupported mark and nothing else, and
// InstanceRowsOf is `system upgrade`'s read of the instance rows before
// anything is replaced.

// A state file an earlier build left — at migration 15, holding an
// instance, its services, a job, a result and an audit row — is brought
// to 16 with every row exactly as it was: the migration adds a column
// and changes, deletes and backfills nothing (which templates are retired
// is the embedded manifest's to say, never a statement's).
func TestMigration16AddsTheMarkAndChangesNothingElse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	full := migrationSet
	migrationSet = func() []string { return full()[:15] }
	old, err := OpenSQLite(path)
	if err != nil {
		migrationSet = full
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	in := Instance{Name: "old-lab", Template: "a-template", Version: "1.0.0", Profile: "standard", Mode: ModeDelivery,
		Source: "/state/instances/old-lab/template", Created: now, Updated: now, Stage: StageReady, Reached: StageReady,
		Licenses: []string{"some-terms"}, SeedSalt: "salt"}
	fill := func(s *SQLite) error {
		if err := s.PutInstance(in); err != nil {
			return err
		}
		if err := s.PutService(Service{Instance: "old-lab", Name: "web", Image: "example/web@sha256:" + zeros, Container: "pdr-old-lab-web", ContainerID: "c1", Stage: StageReady}); err != nil {
			return err
		}
		if err := s.PutJob(Job{ID: "job_1", Kind: "create", Instance: "old-lab", State: JobSucceeded, Stage: "done", Started: now, Finished: &now}); err != nil {
			return err
		}
		if err := s.PutCheckpointResult(CheckpointResult{Instance: "old-lab", ID: "web-up", Class: "baseline", Adapter: "http", Status: "pass", At: now}); err != nil {
			return err
		}
		return s.AppendAudit(Audit{At: now, Instance: "old-lab", Action: "reveal", Actor: "operator", Detail: "admin-password"})
	}
	if err := fill(old); err != nil {
		migrationSet = full
		t.Fatal(err)
	}
	before := snapshot(t, old)
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
	if v, err := store.SchemaVersion(); err != nil || v != 16 {
		t.Fatalf("schema version %d %v, want 16", v, err)
	}
	if after := snapshot(t, store); !reflect.DeepEqual(before, after) {
		t.Fatalf("migration 16 changed what the file held:\nbefore %+v\nafter  %+v", before, after)
	}
	if reason, err := store.Unsupported("old-lab"); err != nil || reason != "" {
		t.Fatalf("the migration marks nothing: %q %v", reason, err)
	}
	// And the way back exists, as it does for every migration: the state
	// as the earlier schema left it, beside the file (INSTALL §6).
	backups, _ := filepath.Glob(path + ".bak-v*")
	if len(backups) != 1 {
		t.Fatalf("want one pre-migration backup beside the state file, got %v", backups)
	}
}

const zeros = "0000000000000000000000000000000000000000000000000000000000000000"

// held is what a state file holds for the rows the migration must leave
// alone.
type held struct {
	Instance *Instance
	Services []Service
	Jobs     []Job
	Results  []CheckpointResult
	Audit    []Audit
}

func snapshot(t *testing.T, s *SQLite) held {
	t.Helper()
	var h held
	var err error
	if h.Instance, err = s.GetInstance("old-lab"); err != nil {
		t.Fatal(err)
	}
	if h.Services, err = s.ListServices("old-lab"); err != nil {
		t.Fatal(err)
	}
	if h.Jobs, err = s.ListJobs("old-lab"); err != nil {
		t.Fatal(err)
	}
	if h.Results, err = s.ListCheckpointResults("old-lab"); err != nil {
		t.Fatal(err)
	}
	if h.Audit, err = s.ListAudit("old-lab"); err != nil {
		t.Fatal(err)
	}
	return h
}

// InstanceRowsOf reads what the preflight needs and nothing else, and
// never writes: a file that is not there, and a database no engine has
// opened, hold none; a file it cannot read as a state database is an
// error, never "no instances" — the preflight refuses on it.
func TestInstanceRowsOfReadsWithoutWritingAndRefusesWhatItCannotRead(t *testing.T) {
	dir := t.TempDir()
	if rows, err := InstanceRowsOf(filepath.Join(dir, "absent.db")); err != nil || rows != nil {
		t.Fatalf("a state file that is not there: %v %v", rows, err)
	}

	// A database no engine opened: the shape hack/upgrade_test.sh hands
	// the upgrade, a table of its own and no migrations table.
	bare := filepath.Join(dir, "bare.db")
	db, err := sql.Open("sqlite", "file:"+bare)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`create table marker (id text primary key)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if rows, err := InstanceRowsOf(bare); err != nil || rows != nil {
		t.Fatalf("a database no engine has opened holds no instance rows: %v %v", rows, err)
	}

	// A state file an engine wrote, held open by that engine meanwhile.
	real := filepath.Join(dir, "state.db")
	store, err := OpenSQLite(real)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC().Truncate(time.Second)
	for _, in := range []Instance{
		{Name: "intro", Template: "grafana-prometheus-intro", Mode: ModeDelivery, Source: "/s", Created: now, Updated: now, Stage: StageReady},
		{Name: "old-lab", Template: "a-retired-name", Mode: ModeDelivery, Source: "/s", Created: now, Updated: now, Stage: StageSeeded},
	} {
		if err := store.PutInstance(in); err != nil {
			t.Fatal(err)
		}
	}
	info, _ := os.Stat(real)
	rows, err := InstanceRowsOf(real)
	if err != nil {
		t.Fatal(err)
	}
	want := []InstanceRow{{Name: "intro", Template: "grafana-prometheus-intro", Stage: StageReady}, {Name: "old-lab", Template: "a-retired-name", Stage: StageSeeded}}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows = %+v, want %+v", rows, want)
	}
	if after, _ := os.Stat(real); !after.ModTime().Equal(info.ModTime()) || after.Size() != info.Size() {
		t.Errorf("the read wrote to the state file")
	}

	// Not a database at all.
	junk := filepath.Join(dir, "junk.db")
	if err := os.WriteFile(junk, []byte("not a database, and long enough to be read as one's header: 0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rows, err := InstanceRowsOf(junk); err == nil {
		t.Fatalf("a file that is not a database was read as %v", rows)
	}

	// A migrations table and no instances table: the rows cannot be read.
	torn := filepath.Join(dir, "torn.db")
	db, err = sql.Open("sqlite", "file:"+torn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`create table schema_migrations (version integer primary key, applied text not null); insert into schema_migrations values (3, 'then')`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if rows, err := InstanceRowsOf(torn); err == nil {
		t.Fatalf("a state file without its instances table was read as %v", rows)
	}
}
