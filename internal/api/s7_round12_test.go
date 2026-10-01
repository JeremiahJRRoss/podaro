// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/evidence"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// The round-2 fix gave the feed a cursor that holds both sequences, and
// its test walks an audit row that lands before the cursor *on an open
// connection*. The reconnect path rebuilds the cursor from the merged
// list — `cursorAt(entries, start+1)` — and that prefix now contains the
// late row, whose sequence is the highest of any audit. The cursor
// therefore starts past a row the client never saw, and the feed
// suppresses it for good.
//
// A single `Last-Event-ID` names one entry and so can prove the position
// of one sequence. The journal's own order never changes — the merge
// preserves it — so a journal id places the journal exactly. It says
// nothing about the audit stream, and the feed no longer pretends it
// does: it replays the audits rather than risk dropping one. Audits are
// few (joins, reveals, resets), a client dedupes on id, and a reveal
// that never arrives is the failure that matters.
func TestAReconnectDoesNotSwallowAnAuditWrittenWhileItWasAway(t *testing.T) {
	srv, eng, store := eventsHarness(t)
	ctx := context.Background()
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	job, err := eng.Create(ctx, engine.CreateRequest{Path: fixture, Name: "reconnect"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Wait(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	entries, err := eng.Evidence("reconnect", engine.EvidenceFilter{}, engine.Socket)
	if err != nil || len(entries) == 0 {
		t.Fatalf("evidence: %v %d", err, len(entries))
	}
	last := entries[len(entries)-1]

	// The client saw everything through `last` and went away. While it
	// was away a reveal was audited, and the host's clock had stepped
	// back, so the row lands *before* `last` in the merged list.
	if err := store.AppendAudit(state.Audit{At: last.At.Add(-time.Hour), Instance: "reconnect",
		Action: "reveal", Actor: "alice", Mechanism: "session", Detail: "audited-while-away"}); err != nil {
		t.Fatal(err)
	}
	after, err := eng.Evidence("reconnect", engine.EvidenceFilter{}, engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if after[len(after)-1].Audit != nil {
		t.Fatalf("the fixture must place the new row before the resume point to prove anything")
	}

	body, stop := openFeed(t, srv, "reconnect", last.ID)
	defer stop()
	frames := readFrames(t, body, 4, 6*time.Second, stop)
	for _, f := range frames {
		if f.Data["detail"] == "audited-while-away" {
			return
		}
	}
	t.Fatalf("the reveal audited while the client was away was never replayed; frames: %+v", frames)
}

// API §4 documents a `job` frame as {"id","state","stage"} with state in
// queued|running|succeeded|failed. The feed emitted a lifecycle `event`
// — `init`, `ready` — and no `state` at all, so a client following the
// advertised feed could not tell a job it started from one that
// finished. The console never noticed because it uses the frame only as
// a signal to re-read.
func TestAJobFrameCarriesTheStateItsDocumentPromises(t *testing.T) {
	srv, eng, _ := eventsHarness(t)
	ctx := context.Background()
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	job, err := eng.Create(ctx, engine.CreateRequest{Path: fixture, Name: "states"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Wait(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	// The feed opens on the finished instance, then a job runs, so the
	// frames under test arrive on this connection rather than as replay.
	body, stop := openFeed(t, srv, "states", "")
	defer stop()
	v, err := eng.VerifyAs(ctx, "states", "", engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Wait(ctx, v.ID); err != nil {
		t.Fatal(err)
	}
	frames := readFrames(t, body, 4, 10*time.Second, stop)
	seen := 0
	for _, f := range frames {
		if f.Event != "job" {
			continue
		}
		seen++
		st, _ := f.Data["state"].(string)
		switch st {
		case "queued", "running", "succeeded", "failed":
		default:
			t.Errorf("a job frame carries state %q; API §4 documents queued|running|succeeded|failed: %+v", st, f.Data)
		}
		if _, ok := f.Data["id"]; !ok {
			t.Errorf("a job frame carries no id: %+v", f.Data)
		}
	}
	if seen == 0 {
		t.Fatalf("no job frame arrived to check; frames: %+v", frames)
	}
}

// Review round 13: the mirror of the round-12 finding, and the half I
// argued myself out of. Round 12's comment states the rule — one id
// proves the position of one sequence — and the code applied it to one
// branch. `cursorAt(entries, start+1)` was still used whatever the id
// named, so when `Last-Event-ID` names an *audit* the journal position
// is inferred from the merged prefix, which is exactly the inference a
// backward clock correction invalidates: a journal entry appended while
// the client was away can merge before that audit, be counted as
// delivered, and have its job or checkpoint frame suppressed for good.
//
// The rule now runs both ways. An audit id places the audit sequence and
// the journal replays; a journal id places the journal and the audits
// replay. Neither sequence is ever inferred from where the merge happens
// to put the other.
func TestAnAuditResumePointDoesNotSwallowAJournalEntry(t *testing.T) {
	srv, eng, store, dir := eventsHarnessDir(t)
	ctx := context.Background()
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	job, err := eng.Create(ctx, engine.CreateRequest{Path: fixture, Name: "mirror"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Wait(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	entries, err := eng.Evidence("mirror", engine.EvidenceFilter{}, engine.Socket)
	if err != nil || len(entries) == 0 {
		t.Fatalf("evidence: %v %d", err, len(entries))
	}
	last := entries[len(entries)-1]

	// The last frame the client received was an audit, so that is the
	// id it resumes from.
	if err := store.AppendAudit(state.Audit{At: last.At.Add(time.Hour), Instance: "mirror",
		Action: "reveal", Actor: "alice", Mechanism: "session", Detail: "the-resume-point"}); err != nil {
		t.Fatal(err)
	}
	entries, _ = eng.Evidence("mirror", engine.EvidenceFilter{}, engine.Socket)
	resume := entries[len(entries)-1]
	if resume.Audit == nil {
		t.Fatalf("the fixture must resume from an audit to prove anything")
	}

	// While the client was away the host's clock stepped back, and a
	// journal entry was written that merges *before* that audit. It goes
	// into the instance's evidence journal — the store's event rows are
	// a different stream and never reach this feed.
	j := evidence.Open(filepath.Join(dir, "instances", "mirror", "evidence"))
	if _, err := j.Append(evidence.Entry{At: resume.At.Add(-30 * time.Minute), Instance: "mirror",
		Type: evidence.TypeLifecycle, Job: job.ID,
		Lifecycle: &evidence.Lifecycle{Event: "stage", Stage: "ready", Detail: "journal-entry-behind-the-audit"}}); err != nil {
		t.Fatal(err)
	}
	after, _ := eng.Evidence("mirror", engine.EvidenceFilter{}, engine.Socket)
	if len(after) != len(entries)+1 {
		t.Fatalf("the appended journal entry never reached the instance's evidence: %d entries before, %d after", len(entries), len(after))
	}
	if after[len(after)-1].ID != resume.ID {
		t.Fatalf("the fixture must place the new journal entry before the resume point; it is last")
	}

	body, stop := openFeed(t, srv, "mirror", resume.ID)
	defer stop()
	// Enough frames to reach it: the journal replays whole, so the
	// entry under test arrives after the ones that were always there.
	frames := readFrames(t, body, 8, 8*time.Second, stop)
	for _, f := range frames {
		if f.Data["detail"] == "journal-entry-behind-the-audit" {
			return
		}
	}
	t.Fatalf("the journal entry written while the client was away was never replayed; frames: %+v", frames)
}
