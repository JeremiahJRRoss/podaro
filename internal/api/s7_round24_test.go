// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/lab"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// Round 23 made a feed whose connect read failed take its position on the
// first read that worked — at the tail. For a client that named no
// `Last-Event-ID` that is right. For one that named a good id it is not:
// the header was still there and was never looked at, so every entry
// written while that client was away was skipped for good, against the
// replay API §4 documents.
//
// I wrote at the time that such a client "gets no replay, which is what
// an unplaceable cursor has always meant". That is not the same thing.
// An unplaceable cursor is an id the journal does not hold; this was an
// id nobody looked for. The resume is the same on the first read that
// works, wherever that read happens.
func TestAReconnectStillReplaysWhenTheFirstReadFailed(t *testing.T) {
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
	job, err := eng.Create(ctx, engine.CreateRequest{Path: fixture, Name: "resumed"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Wait(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC()
	for i := 1; i <= 4; i++ {
		if err := store.AppendAudit(state.Audit{Seq: int64(i), At: base.Add(time.Duration(i) * time.Millisecond),
			Action: "reveal", Actor: "operator", Mechanism: "session", Instance: "resumed",
			Detail: "nginx-admin"}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := eng.Evidence("resumed", engine.EvidenceFilter{}, engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 4 {
		t.Fatalf("this case needs entries to replay, got %d", len(entries))
	}
	// The client saw the first entry and went away; everything after it
	// is the replay it is owed.
	from := entries[0].ID
	want := len(entries) - 1
	// And its reconnect finds the evidence store briefly unreadable.
	store.arm()

	// The replay arrives after the connect snapshots — a ladder frame per
	// service, one for the instance, and one per job row — so the read
	// has to be long enough to reach it.
	v, err := eng.View("resumed", engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := eng.Jobs("resumed", engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	body, closeFeed := openFeed(t, srv, "resumed", from)
	defer closeFeed()
	frames := readFrames(t, body, len(v.Services)+1+len(rows)+want, 8*time.Second, closeFeed)
	replayed := 0
	for _, f := range frames {
		if f.ID != "" {
			replayed++
		}
	}
	if replayed < want {
		t.Fatalf("a reconnect whose first read failed replayed %d of the %d entries it was owed; frames: %s",
			replayed, want, describe(frames))
	}
}
