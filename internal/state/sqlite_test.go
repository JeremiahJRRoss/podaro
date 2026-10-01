// SPDX-License-Identifier: AGPL-3.0-only

package state

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

func TestSQLiteStoreConformance(t *testing.T) {
	RunStoreTests(t, func(t *testing.T) Store {
		s, err := OpenSQLite(filepath.Join(t.TempDir(), "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

// Reopening finds the same rows: the point of a persistent store.
func TestSQLitePersistsAcrossOpens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutJob(Job{ID: "job_x", Kind: "create", Instance: "a", State: JobRunning, Stage: "pulling web"}); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.SchemaVersion(); v != len(migrations) {
		t.Fatalf("schema version %d, want %d", v, len(migrations))
	}
	s.Close()
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state.db mode: %v %v (INSTALL §3 says 0600)", fi, err)
	}
	s2, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	j, err := s2.GetJob("job_x")
	if err != nil || j.State != JobRunning || j.Stage != "pulling web" {
		t.Fatalf("job after reopen: %+v %v", j, err)
	}
	// No pending migrations → no backup files appear.
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".bak-") {
			t.Errorf("unexpected backup %s", e.Name())
		}
	}
}

// The pre-migration backup is taken through SQLite, so rows that live only
// in the write-ahead log after an unclean stop are in it.
func TestMigrationBackupIncludesWAL(t *testing.T) {
	// One more migration than the file has seen, so opening it must back
	// up first.
	migrationSet = func() []string { return append(append([]string(nil), migrations...), `create table probe (x integer)`) }
	t.Cleanup(func() { migrationSet = func() []string { return migrations } })
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	// A schema-version-1 database as the first engine left it, with its
	// last writes still in the WAL: checkpointing is off and the connection
	// stays open, as after a kill -9.
	old, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=wal_autocheckpoint(0)")
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	exec := func(stmt string) {
		t.Helper()
		if _, err := old.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	exec(`create table schema_migrations (version integer primary key, applied text not null)`)
	exec(migrations[0])
	exec(`insert into schema_migrations (version, applied) values (1, '2026-09-03T00:00:00Z')`)
	// The schema reached the main file (as the first engine's checkpoint
	// left it); the rows below did not.
	exec(`pragma wal_checkpoint(TRUNCATE)`)
	exec(`insert into instances (name, template, mode, source, created, updated, stage) values ('pii-lab', 'conformance-lab', 'delivery', '/snap', '2026-09-03T00:00:00Z', '2026-09-03T00:00:00Z', 'healthy')`)
	exec(`insert into jobs (id, kind, instance, state, stage, started, seq) values ('job_1', 'create', 'pii-lab', 'running', 'pulling', '2026-09-03T00:00:00Z', 1)`)
	if fi, err := os.Stat(path + "-wal"); err != nil || fi.Size() == 0 {
		t.Fatalf("expected an uncheckpointed WAL: %v %v", fi, err)
	}
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if v, _ := s.SchemaVersion(); v != len(migrations)+1 {
		t.Fatalf("schema version %d", v)
	}
	// Migration 4 records that this instance — older than the ui columns
	// it adds — still owes the gateway facts; the engine derives them at
	// its next start and clears the mark (round 27).
	if pending, err := s.GatewayBackfill("pii-lab"); err != nil || !pending {
		t.Fatalf("an instance older than the ui columns must be marked: %v %v", pending, err)
	}
	var backup string
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".bak-") {
			backup = filepath.Join(dir, e.Name())
		}
	}
	if backup == "" {
		t.Fatal("no backup written before the migration")
	}
	if fi, _ := os.Stat(backup); fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode %04o", fi.Mode().Perm())
	}
	b, err := sql.Open("sqlite", "file:"+backup+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var instances, jobs, version int
	if err := b.QueryRow(`select count(*) from instances`).Scan(&instances); err != nil {
		t.Fatal(err)
	}
	_ = b.QueryRow(`select count(*) from jobs where state = 'running'`).Scan(&jobs)
	_ = b.QueryRow(`select max(version) from schema_migrations`).Scan(&version)
	if instances != 1 || jobs != 1 || version != 1 {
		t.Fatalf("backup is not the complete pre-migration state: instances=%d running jobs=%d version=%d", instances, jobs, version)
	}
	// And the migrated database still has everything.
	if inst, err := s.GetInstance("pii-lab"); err != nil || inst.Stage != StageHealthy {
		t.Fatalf("instance after migration: %+v %v", inst, err)
	}
}

// An older binary refuses a state.db a newer one migrated:
// the schema is not one it knows, so nothing is read, written,
// or backed up — and the newer binary still finds everything in place.
func TestNewerDatabaseIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	newer := func() []string { return append(append([]string(nil), migrations...), `create table probe (x integer)`) }
	migrationSet = newer
	t.Cleanup(func() { migrationSet = func() []string { return migrations } })
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	inst := Instance{Name: "pii-lab", Template: "conformance-lab", Version: "1.0.0", Mode: ModeDelivery, Source: "/snap", Stage: StageHealthy}
	if err := s.PutInstance(inst); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// This binary: one migration short.
	migrationSet = func() []string { return migrations }
	_, err = OpenSQLite(path)
	var pe *pdr.Error
	if !errors.As(err, &pe) || pe.Code != pdr.CodeStateNewer {
		t.Fatalf("an older engine must refuse a newer state.db with %s: %v", pdr.CodeStateNewer, err)
	}
	if !strings.Contains(pe.Message, "schema version "+strconv.Itoa(len(migrations)+1)) || pe.Next == "" {
		t.Fatalf("the refusal must name the versions and a way out: %+v", pe)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".bak-") {
			t.Fatalf("a refused open must not write a backup: %s", e.Name())
		}
	}
	// The binary that wrote it still opens it, with everything in place.
	migrationSet = newer
	again, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("the newer engine must still open its own state: %v", err)
	}
	defer again.Close()
	if v, _ := again.SchemaVersion(); v != len(migrations)+1 {
		t.Fatalf("schema version after the refusal: %d", v)
	}
	if got, err := again.GetInstance("pii-lab"); err != nil || got.Stage != StageHealthy || got.Version != "1.0.0" {
		t.Fatalf("instance after the refusal: %+v %v", got, err)
	}
}

// A fresh state.db abandoned before SQLite's first automatic checkpoint
// (kill -9 seconds after install) still holds its rows on the next open.
func TestFreshDatabaseSurvivesUncleanStop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	first, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.PutJob(Job{ID: "job_1", Kind: "create", Instance: "a", State: JobRunning, Stage: "pulling"}); err != nil {
		t.Fatal(err)
	}
	// Not closed: the process died. Another engine opens the same file.
	second, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if j, err := second.GetJob("job_1"); err != nil || j.State != JobRunning {
		t.Fatalf("job after unclean stop: %+v %v", j, err)
	}
	first.Close()
}

// Two creations racing for one token name: exactly one wins and every
// other result is the documented conflict, never a raw constraint error.
func TestConcurrentTokenNamesConflictNever500(t *testing.T) {
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	for round := 0; round < 6; round++ {
		const racers = 16
		results := make(chan error, racers)
		var wg sync.WaitGroup
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				id := fmt.Sprintf("tok_%d_%d", round, i)
				results <- s.PutToken(Token{ID: id, Name: fmt.Sprintf("race-%d", round), Prefix: "pfx", Hash: "hash-" + id, Scope: "read", Created: now})
			}(i)
		}
		wg.Wait()
		close(results)
		wins := 0
		for err := range results {
			switch {
			case err == nil:
				wins++
			case errors.Is(err, ErrConflict):
			default:
				t.Fatalf("round %d: a loser got a raw store error instead of ErrConflict: %v", round, err)
			}
		}
		if wins != 1 {
			t.Fatalf("round %d: %d winners, want exactly one", round, wins)
		}
	}
}

// A destroy that commits between the instance check and the history insert
// leaves no orphaned rows: the insert is conditional on the instance row in
// the same statement and the check reads inside the same transaction, so a
// re-created instance of the same name inherits nothing (sqlite.go:392).
func TestHistoryInsertIsAtomicWithTheInstanceCheck(t *testing.T) {
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC().Truncate(time.Second)
	inst := Instance{Name: "race", Template: "t", Mode: ModeAuthoring, Source: "/w", Created: now, Updated: now}
	if err := s.PutInstance(inst); err != nil {
		t.Fatal(err)
	}
	beforeAddGeneratedSecrets = func() {
		if err := s.DeleteInstance("race"); err != nil {
			t.Error(err)
		}
	}
	defer func() { beforeAddGeneratedSecrets = nil }()
	if err := s.AddGeneratedSecrets("race", []string{"tok"}); err != ErrNotFound {
		t.Fatalf("an instance destroyed meanwhile has no history to add to: %v", err)
	}
	beforeAddGeneratedSecrets = nil
	if err := s.PutInstance(inst); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GeneratedSecrets("race"); len(got) != 0 {
		t.Fatalf("a re-created instance inherits no orphaned history: %v", got)
	}
}
