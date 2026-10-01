// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// A destroy removes the instance and *then* `Engine.run` records the
// job's terminal state (destroySteps deletes the row and the directory;
// finish() writes `succeeded` after it returns). The feed's next tick
// read the view, found the instance gone, said `end` and stopped —
// before the job it was following had a state to report. So the one job
// a client most wants followed to completion was the one job the feed
// never followed, and what it got instead was a frame API §4 did not
// document.
//
// Job rows outlive their instance in both stores (DeleteInstance clears
// services, results, progress and secrets, never jobs), so the feed
// drains: it keeps reading the rows it can still read, sends what moved,
// and says `end` once nothing is running.
func TestTheFeedFollowsADestroyToItsEnd(t *testing.T) {
	srv, eng, _ := eventsHarness(t)
	ctx := context.Background()
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	job, err := eng.Create(ctx, engine.CreateRequest{Path: fixture, Name: "leaving"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Wait(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	v, err := eng.View("leaving", engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	body, closeFeed := openFeed(t, srv, "leaving", "")
	defer closeFeed()
	rows, err := eng.Jobs("leaving", engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	readFrames(t, body, len(v.Services)+1+len(rows), 5*time.Second, closeFeed)

	gone, err := eng.Destroy(ctx, "leaving", "leaving")
	if err != nil {
		t.Fatal(err)
	}
	// The fixture produced the state: the destroy finished, and the
	// instance it was following is gone.
	final, err := eng.Wait(ctx, gone.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.State != state.JobSucceeded {
		t.Fatalf("the fixture's destroy did not succeed: %s %v", final.State, final.Error)
	}
	if _, err := eng.View("leaving", engine.Socket); err == nil {
		t.Fatal("the fixture must destroy the instance; it is still readable")
	}

	frames := readFrames(t, body, 8, 8*time.Second, closeFeed)
	destroyed := jobFrames(frames, gone.ID)
	if len(destroyed) == 0 {
		t.Fatalf("the feed never said how the destroy ended; frames: %s", describe(frames))
	}
	if got := destroyed[len(destroyed)-1].Data["state"]; got != string(state.JobSucceeded) {
		t.Fatalf("the destroy was followed to %v, not %s", got, state.JobSucceeded)
	}
	// And the stream still ends, after that and not before it.
	last, end := -1, -1
	for i, f := range frames {
		if f.Event == "job" && f.Data["id"] == gone.ID {
			last = i
		}
		if f.Event == "end" && end < 0 {
			end = i
		}
	}
	if end < 0 {
		t.Fatalf("the feed never ended after the instance was destroyed; frames: %s", describe(frames))
	}
	if last > end {
		t.Errorf("the destroy's outcome arrived after the stream said it had ended; frames: %s", describe(frames))
	}
}
