// SPDX-License-Identifier: AGPL-3.0-only

package state

import (
	"path/filepath"
	"testing"
	"time"
)

// Review round 29 — the migrations behind rounds 27
// and 28.
//
// Those rounds bound the image and the module to the run because the
// plan's copies move. The migrations then filled the new columns *from
// those same plan values*: `ran_image` from `image` where a start time
// existed, and `ran_module` from `module` where `ran_image` was set. For
// a row caught between an edited retry's publish and its start, that is
// exactly the false pairing the columns exist to prevent — and worse
// than before, because the value now carries the claim "this is what
// ran" rather than "this is what the plan says".
//
// A run fact that cannot be proven is left unknown. An upgraded lab's
// "What ran" is empty until it runs again, which says less and nothing
// untrue.
func TestMigrationInfersNoRunFactsFromThePlan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	full := migrationSet
	migrationSet = func() []string { return full()[:12] }
	old, err := OpenSQLite(path)
	if err != nil {
		migrationSet = full
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := old.db.Exec(`insert into instances (name, template, version, profile, mode, source, created, updated, stage, licenses, seed_salt, audit_from)
		values ('class', 't', '', '', 'authoring', '/s', ?, ?, 'ready', '', '', 0)`, fmtTime(now), fmtTime(now)); err != nil {
		migrationSet = full
		t.Fatal(err)
	}
	// The row an edited retry leaves: a start time from the run that
	// happened, and a plan that has moved on since.
	if _, err := old.db.Exec(`insert into services (instance, name, module, image, container, container_id, stage, ports, typical, budget, started_at, healthy_at, readiness, error, ui_port, ui_scheme, embed)
		values ('class', 'web', 'edited-module', 'img@sha256:edited', 'pdr-class-web', 'c1', 'none', '{}', '', '', ?, null, '', '', 0, '', '')`,
		fmtTime(now)); err != nil {
		migrationSet = full
		t.Fatal(err)
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
	svcs, err := store.ListServices("class")
	if err != nil || len(svcs) != 1 {
		t.Fatalf("services after the upgrade: %+v %v", svcs, err)
	}
	if got := svcs[0].RanImage; got != "" {
		t.Errorf("the upgrade claimed a run image it cannot prove: %q", got)
	}
	if got := svcs[0].RanModule; got != "" {
		t.Errorf("the upgrade claimed a run module it cannot prove: %q", got)
	}
	// The plan's own values are untouched: the engine still needs them
	// to pull and create.
	if svcs[0].Image != "img@sha256:edited" || svcs[0].Module != "edited-module" {
		t.Errorf("the upgrade disturbed the plan's own facts: %+v", svcs[0])
	}
}
