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

// Rounds 12 and 13 gave the `job` frame the `state` API §4 documents and
// made the reconnect symmetric — but the feed still had exactly one
// source, the evidence journal, and a job's terminal transition is not
// written there. `Engine.run` records `succeeded`/`failed` in the state
// event log and then updates the job row; neither is evidence. So the
// documented promise — "a client can follow a job it started to
// `succeeded` or `failed` without polling" — held only for jobs whose
// last journal entry happened to be written after the row, and not at
// all for a job that ends without journalling.
//
// The row is the persistent record of a job's state, the feed already
// re-reads the instance view every tick, and the view carries it. So the
// feed sends the row as a snapshot: on connect, and again whenever it
// changes. Like `ladder` it carries no id — it is not a journal fact and
// must never move a client's Last-Event-ID.
//
// The fixture is a job row with no evidence of its own, which is what a
// job that ends without journalling leaves behind. The journal is
// asserted not to grow across the transition, so the frame under test
// can only have come from the row.
func TestTheFeedFollowsAJobRowToItsTerminalState(t *testing.T) {
	srv, eng, store := eventsHarness(t)
	ctx := context.Background()
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	job, err := eng.Create(ctx, engine.CreateRequest{Path: fixture, Name: "follow"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Wait(ctx, job.ID); err != nil {
		t.Fatal(err)
	}

	// A job whose only record is its row: no lifecycle entry, no seed
	// entry, nothing in the journal to carry it onto the feed.
	row := state.Job{ID: "job_round14", Kind: "verify", Instance: "follow",
		State: state.JobRunning, Stage: "running its checkpoints", Started: time.Now().UTC()}
	if err := store.PutJob(row); err != nil {
		t.Fatal(err)
	}
	// The fixture produced the state this case is about, before anything
	// is asserted about the behaviour: the instance's view names this
	// job, and the journal holds nothing about it.
	v, err := eng.View("follow", engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if v.Job == nil || v.Job.ID != row.ID || v.Job.State != state.JobRunning {
		t.Fatalf("the fixture did not put a running job on the instance's view: %+v", v.Job)
	}
	before, err := eng.Evidence("follow", engine.EvidenceFilter{}, engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range before {
		if e.Job == row.ID {
			t.Fatalf("the fixture journalled entry %s for %s; this case is about a job the journal does not carry", e.ID, row.ID)
		}
	}

	body, closeFeed := openFeed(t, srv, "follow", "")
	defer closeFeed()
	// The connect snapshot says what the instance is running, so a client
	// that opened the feed after starting a job — or after it finished —
	// is told where that job stands rather than waiting for a frame that
	// never comes.
	// One ladder frame per service, one for the instance, and one
	// snapshot per job row — round 17 stopped the connect withholding
	// rows this connection had not sent, so the opening burst grew by
	// the instance's job count. Asking for more than arrives would spend
	// the budget and close the stream this case still has to watch.
	rows, err := eng.Jobs("follow", engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	want := len(v.Services) + 1 + len(rows)
	opening := readFrames(t, body, want, 5*time.Second, closeFeed)
	running := jobFrames(opening, row.ID)
	if len(running) == 0 {
		t.Fatalf("the feed opened without saying what job %s is doing; frames: %s", row.ID, describe(opening))
	}
	if got := running[len(running)-1].Data["state"]; got != string(state.JobRunning) {
		t.Fatalf("the opening job frame says state %v, the row says %s", got, state.JobRunning)
	}
	for _, f := range running {
		if f.ID != "" {
			t.Fatalf("a job snapshot carries the SSE id %q; it is not a journal fact and must not move Last-Event-ID", f.ID)
		}
	}

	// The job ends. Nothing is journalled — exactly as `Engine.run`
	// leaves a job whose terminal record is the row and the state event
	// log — and the client must still be told.
	done := time.Now().UTC()
	row.State, row.Stage, row.Finished = state.JobSucceeded, "done", &done
	if err := store.PutJob(row); err != nil {
		t.Fatal(err)
	}
	settled, err := eng.View("follow", engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if settled.Job == nil || settled.Job.State != state.JobSucceeded {
		t.Fatalf("the fixture did not land the terminal state: %+v", settled.Job)
	}
	after, err := eng.Evidence("follow", engine.EvidenceFilter{}, engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("the fixture wrote %d evidence entries; this case proves the row alone drives the frame", len(after)-len(before))
	}

	// The row's state decides the ladder's `in_progress` too, so the
	// ladder is re-sent beside the one row that moved.
	frames := readFrames(t, body, len(v.Services)+2, 5*time.Second, closeFeed)
	terminal := jobFrames(frames, row.ID)
	if len(terminal) == 0 {
		t.Fatalf("job %s finished and the feed said nothing; frames: %s", row.ID, describe(frames))
	}
	last := terminal[len(terminal)-1]
	if got := last.Data["state"]; got != string(state.JobSucceeded) {
		t.Fatalf("the feed followed job %s to state %v, not %s", row.ID, got, state.JobSucceeded)
	}
	if got := last.Data["stage"]; got != "done" {
		t.Fatalf("the terminal frame carries stage %v, the row says done", got)
	}
	if last.ID != "" {
		t.Fatalf("a job snapshot carries the SSE id %q; it is not a journal fact", last.ID)
	}
}

// jobFrames are the `job` frames naming one job, in the order they came.
func jobFrames(frames []sseFrame, id string) []sseFrame {
	var out []sseFrame
	for _, f := range frames {
		if f.Event == "job" && f.Data["id"] == id {
			out = append(out, f)
		}
	}
	return out
}

// describe names the frames a failure actually saw, so a case that reads
// the wrong number of them says so instead of blaming the feed.
func describe(frames []sseFrame) string {
	if len(frames) == 0 {
		return "none"
	}
	out := ""
	for i, f := range frames {
		if i > 0 {
			out += ", "
		}
		out += f.Event
		if id, ok := f.Data["id"].(string); ok && id != "" {
			out += "(" + id + ")"
		}
	}
	return out
}
