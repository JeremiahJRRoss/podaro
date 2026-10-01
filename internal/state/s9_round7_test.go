// SPDX-License-Identifier: AGPL-3.0-only

package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Migration 9 gave every pre-existing instance `audit_from = 0`, which
// means "everything". A name that had been destroyed and reused *before*
// the upgrade would then have handed its attendees the older
// generation's joins and reveals — the leak the column exists to close,
// carried across the upgrade that closes it.
//
// A migrated instance starts at the high-water mark instead. The cost is
// real and is the safe direction: it shows none of its own earlier audit
// rows in its evidence either, because nothing here can tell the two
// apart. The operator's stream keeps all of them.
func TestMigrationDrawsTheLineWhereItCannotKnow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	// A store as it stood before the column: migrations up to 8, an
	// instance, and audit rows under its name.
	full := migrationSet
	migrationSet = func() []string { return full()[:8] }
	old, err := OpenSQLite(path)
	if err != nil {
		migrationSet = full
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	// Written with the columns that existed then: PutInstance writes
	// audit_from, which is exactly what this schema has not got yet.
	if _, err := old.db.Exec(`insert into instances (name, template, version, profile, mode, source, created, updated, stage, licenses, seed_salt)
		values ('class', 't', '', '', 'delivery', '/s', ?, ?, '', '', '')`, fmtTime(now), fmtTime(now)); err != nil {
		t.Fatal(err)
	}
	for _, a := range []Audit{
		{At: now, Instance: "class", Action: "join", Actor: "alice", Mechanism: "instance-access"},
		{At: now, Instance: "class", Action: "reveal", Actor: "alice", Detail: "admin"},
	} {
		if err := old.AppendAudit(a); err != nil {
			t.Fatal(err)
		}
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	migrationSet = full

	// The upgrade runs migration 9 over it.
	store, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	inst, err := store.GetInstance("class")
	if err != nil || inst == nil {
		t.Fatalf("the migrated instance: %+v %v", inst, err)
	}
	if inst.AuditFrom == 0 {
		t.Fatalf("a migrated instance was left at zero, which means every row ever written under its name")
	}
	rows, err := store.ListAudit("class")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range rows {
		if a.Seq > inst.AuditFrom {
			t.Errorf("row %d is above the line, so a pre-existing row would still be shown", a.Seq)
		}
	}
	// Nothing was deleted: the operator's stream still holds them.
	if len(rows) != 2 {
		t.Errorf("the migration changed the audit stream: %d rows", len(rows))
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
