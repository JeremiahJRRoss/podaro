// SPDX-License-Identifier: AGPL-3.0-only

package system

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// The reconciliation plan's R3, INSTALL §6: `system upgrade`'s preflight
// inventories what an earlier build left of a template the owner has
// since retired — before anything is fetched or replaced — and proceeds;
// it refuses only a state database whose instance rows cannot be read.
// Names come from the embedded manifest (retiredTemplateName, in
// r3_install_test.go); nothing here spells one.

// containerStub is a runtime read the preflight can make without Podman.
type containerStub struct {
	containers map[string]bool // name → running
	err        error
}

func (s containerStub) Objects(ctx context.Context, instance string) (runtime.Objects, error) {
	if s.err != nil {
		return runtime.Objects{}, s.err
	}
	var o runtime.Objects
	for name := range s.containers {
		if strings.HasPrefix(name, "pdr-"+instance+"-") {
			o.Containers = append(o.Containers, name)
		}
	}
	return o, nil
}

func (s containerStub) Inspect(ctx context.Context, name string) (*runtime.ContainerState, error) {
	running, ok := s.containers[name]
	if !ok {
		return nil, nil
	}
	return &runtime.ContainerState{ID: name, Running: running}, nil
}

// The preflight lists the retired catalog entry and the instance of the
// retired template with its running containers, before anything is
// fetched — and proceeds: the upgrade completes.
func TestUpgradePreflightListsWhatAnEarlierBuildLeftAndProceeds(t *testing.T) {
	retired := retiredTemplateName(t)
	exe, stateDB := upgradeEnv(t)
	leaveRetiredCatalogEntry(t, retired)
	store, err := state.OpenSQLite(stateDB) // a second connection beside the engine's
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if err := store.PutInstance(state.Instance{Name: "old-lab", Template: retired, Mode: state.ModeDelivery, Source: "/s", Created: now, Updated: now, Stage: state.StageReady}); err != nil {
		t.Fatal(err)
	}
	store.Close()
	rel := newRelease(t, "9.9.9", "the new binary")
	var out strings.Builder
	err = Upgrade(render.New(&out, false, true), UpgradeOptions{
		Base: rel.srv.URL, Exe: exe, Restart: func() error { return nil },
		Containers: func() (runtime.ContainerReader, error) {
			return containerStub{containers: map[string]bool{"pdr-old-lab-index": true, "pdr-old-lab-search": false, "pdr-class-web": true}}, nil
		},
	})
	if err != nil {
		t.Fatalf("the upgrade must proceed past what it reports: %v\n%s", err, out.String())
	}
	board := out.String()
	for _, want := range []string{
		"! retired template              " + retired + " in the catalog · not offered, never recreated · " + pdr.CodeRetiredPresent + "\n",
		"! unsupported instance          old-lab · retired template · 1 of 2 containers running, left as they are · not reconciled · " + pdr.CodeRetiredPresent + "\n",
	} {
		if !strings.Contains(board, want) {
			t.Errorf("the board lacks %q:\n%s", want, board)
		}
	}
	if strings.Index(board, "unsupported instance") > strings.Index(board, "downloading") {
		t.Errorf("the inventory must come before anything is fetched:\n%s", board)
	}
	if strings.Contains(board, "class ·") {
		t.Errorf("a supported instance is not inventoried:\n%s", board)
	}
	if got, _ := os.ReadFile(exe); string(got) != "the new binary" {
		t.Errorf("the binary was not replaced: the preflight reports, it does not refuse")
	}
}

// A runtime the preflight cannot read is said, not refused: the rows
// that matter — the instance rows — were read.
func TestUpgradePreflightSaysWhenTheRuntimeCannotBeRead(t *testing.T) {
	retired := retiredTemplateName(t)
	_, stateDB := upgradeEnv(t)
	store, err := state.OpenSQLite(stateDB)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if err := store.PutInstance(state.Instance{Name: "old-lab", Template: retired, Mode: state.ModeDelivery, Source: "/s", Created: now, Updated: now, Stage: state.StageReady}); err != nil {
		t.Fatal(err)
	}
	store.Close()
	var out strings.Builder
	inv, err := inventoryRetired(context.Background(), config.StateDir(), func() (runtime.ContainerReader, error) {
		return nil, errors.New("podman: not installed")
	})
	if err != nil {
		t.Fatal(err)
	}
	inv.render(render.New(&out, false, true))
	if !strings.Contains(out.String(), "old-lab · retired template · its containers cannot be read: podman: not installed") {
		t.Fatalf("the row: %q", out.String())
	}
}

// A state database whose instance rows cannot be read refuses the
// upgrade before anything is fetched or replaced, and says why: nothing
// could say which instances the new engine must leave alone.
func TestUpgradePreflightRefusesUnreadableInstanceRows(t *testing.T) {
	exe, stateDB := upgradeEnv(t)
	// A migrations table and no instances table: a state file the engine
	// cannot have written whole.
	torn := filepath.Join(filepath.Dir(stateDB), "torn.db")
	db, err := sql.Open("sqlite", "file:"+torn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`create table schema_migrations (version integer primary key, applied text not null); insert into schema_migrations values (3, 'then')`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err := os.Rename(torn, stateDB); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(stateDB + "-wal")
	_ = os.Remove(stateDB + "-shm")
	var fetched atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetched.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	err = Upgrade(render.New(io.Discard, false, false), UpgradeOptions{
		Base: srv.URL, Exe: exe, Restart: func() error { t.Error("restarted"); return nil },
	})
	var pe *pdr.Error
	if !errors.As(err, &pe) || pe.Code != pdr.CodeUpgradeRefused || !strings.Contains(pe.Message, "read the instance rows") || !strings.Contains(pe.Next, "nothing was replaced") {
		t.Fatalf("unreadable instance rows: %v, want %s naming them", err, pdr.CodeUpgradeRefused)
	}
	if got, _ := os.ReadFile(exe); string(got) != "the running binary" {
		t.Fatal("the binary was replaced")
	}
	if n := fetched.Load(); n != 0 {
		t.Errorf("the release location was asked %d time(s) before the preflight passed", n)
	}
	if _, err := os.Stat(stateDB + ".bak-v" + podaro.Version()); err == nil {
		t.Error("the state was backed up by a refused upgrade")
	}
}
