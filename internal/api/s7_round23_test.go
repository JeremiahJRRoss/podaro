// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/lab"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// auditOnce is a store whose audit read — and so `Engine.Evidence`, which
// merges it — fails the first time and works after.
type auditOnce struct {
	state.Store
	mu    sync.Mutex
	armed bool
}

// arm makes the next audit read fail, once.
func (a *auditOnce) arm() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.armed = true
}

func (a *auditOnce) ListAudit(instance string) ([]state.Audit, error) {
	a.mu.Lock()
	if a.armed {
		a.armed = false
		a.mu.Unlock()
		return nil, errors.New("database is locked (transient)")
	}
	a.mu.Unlock()
	return a.Store.ListAudit(instance)
}

// TestAFeedWhoseFirstReadFailedStillStartsAtTheTail.
//
// A client that names no `Last-Event-ID` starts at the tail: it is here to
// watch what happens next, not to be handed the history. The connect read
// places the cursor there — and when that read failed, the cursor stayed
// at its zero value, which means "nothing has been sent". The first
// successful read in the tick loop then sent the instance's entire
// journal as though it had just happened.
//
// A transient fault is not a reason to replay a lab's history as live
// activity. The feed stands at the tail on the first read it manages,
// wherever that read happens.
func TestAFeedWhoseFirstReadFailedStillStartsAtTheTail(t *testing.T) {
	// The events harness, with a store that can fail one audit read: the
	// same engine options the other feed cases use, so the instance
	// journals what they journal.
	t.Setenv(runtime.EnvFakeReadyDelay, "50ms")
	dir := t.TempDir()
	fake, err := runtime.NewFake(filepath.Join(dir, "world.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fake.Close)
	store := &auditOnce{Store: state.NewMemory()}
	eng := engine.New(engine.Options{Store: store, Runtime: fake, StateDir: dir,
		Library:      lab.DirLibrary(filepath.Join("..", "lab", "testdata", "modules")),
		PollInterval: 20 * time.Millisecond})
	t.Cleanup(func() { shutdown(eng) })
	srv := httptest.NewServer(New(Options{Engine: eng}).SocketHandler())
	t.Cleanup(srv.Close)
	ctx := context.Background()
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	job, err := eng.Create(ctx, engine.CreateRequest{Path: fixture, Name: "transient"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Wait(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	// A history worth not replaying: the create's own journal, and some
	// audit rows, which is what a lab that has been used looks like.
	base := time.Now().UTC()
	for i := 1; i <= 4; i++ {
		if err := store.AppendAudit(state.Audit{Seq: int64(i), At: base.Add(time.Duration(i) * time.Millisecond),
			Action: "reveal", Actor: "operator", Mechanism: "session", Instance: "transient",
			Detail: "nginx-admin"}); err != nil {
			t.Fatal(err)
		}
	}
	// The fixture produced the state: there is a history to replay, and
	// the next evidence read is the one that fails.
	entries, err := eng.Evidence("transient", engine.EvidenceFilter{}, engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 4 {
		t.Fatalf("this case needs a history to wrongly replay, got %d entries", len(entries))
	}
	// The feed's connect read is the one that fails.
	store.arm()

	body, closeFeed := openFeed(t, srv, "transient", "")
	defer closeFeed()
	// Whatever arrives, none of it may be the history: this client asked
	// for no replay. The ladder snapshot and the job rows are snapshots
	// and carry no id; a journal fact does.
	frames := readFrames(t, body, len(entries), 5*time.Second, closeFeed)
	var replayed []sseFrame
	for _, f := range frames {
		if f.ID != "" {
			replayed = append(replayed, f)
		}
	}
	if len(replayed) > 0 {
		t.Fatalf("a fresh feed replayed %d journal facts after its first read failed; first: %s %v",
			len(replayed), replayed[0].Event, replayed[0].Data)
	}
}
