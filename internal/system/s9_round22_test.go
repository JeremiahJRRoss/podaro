// SPDX-License-Identifier: AGPL-3.0-only

package system

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// Two upgrades from the old binary can overlap. The slower one can still
// be downloading while the first replaces the binary, restarts it and
// lets the new engine migrate `state.db` — and then it runs its own
// backup step and writes the *migrated* database over
// `state.db.bak-v<old>`. That file is half of the rollback the manual
// documents: the old binary refuses a schema a newer one migrated
// (PDR-E211), so the pair is the binary and a backup it can open. After
// the overwrite there is no such backup anywhere.
//
// The lock is held for the whole sequence — version check, backup,
// replacement, restart — so the second invocation refuses before it can
// touch anything. It is `upgrade.lock` in the state directory, flock,
// advisory and released by the kernel if a process dies: the same
// mechanism the engine's own single-process lock uses. The test holds it
// the way the first process would.
func TestOneUpgradeAtATimeKeepsTheRollbackPair(t *testing.T) {
	exe, stateDB := upgradeEnv(t)
	rel := newRelease(t, "9.9.9", "the new binary")

	// The first upgrade makes the recovery point.
	if err := Upgrade(render.New(io.Discard, false, false), UpgradeOptions{
		Base: rel.srv.URL, Exe: exe, Restart: func() error { return nil },
	}); err != nil {
		t.Fatalf("the first upgrade: %v", err)
	}
	backup := stateDB + ".bak-v" + podaro.Version()
	if got := backedUpInstances(t, backup); len(got) != 1 || got[0].Name != "class" {
		t.Fatalf("the recovery point holds %+v", got)
	}

	// The state moves on, as a restarted engine's forward-only
	// migrations move it. From here the backup is the only copy the old
	// binary could open.
	store, err := state.OpenSQLite(stateDB)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if err := store.PutInstance(state.Instance{Name: "after-migration", Template: "t", Mode: "delivery",
		Source: "/s", Created: now, Updated: now}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// The first process, still running: it holds the lock for its whole
	// sequence, and the overlapping invocation meets it.
	held, err := os.OpenFile(filepath.Join(config.StateDir(), "upgrade.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}

	err = Upgrade(render.New(io.Discard, false, false), UpgradeOptions{
		Base: rel.srv.URL, Exe: exe,
		Restart: func() error { t.Error("an overlapping upgrade restarted the service"); return nil },
	})
	if code(err) != pdr.CodeUpgradeRefused {
		t.Errorf("an upgrade that overlaps another: %v — want %s", err, pdr.CodeUpgradeRefused)
	}
	if got := backedUpInstances(t, backup); len(got) != 1 || got[0].Name != "class" {
		t.Errorf("the overlapping upgrade wrote the migrated database over the recovery point: %+v", got)
	}
}
