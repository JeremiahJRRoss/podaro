// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// guidedOnlyLab writes a lab whose one playbook declares Guided and not
// Presenter, and carries a presenter note — the author-written line that
// Presenter is the only manner meant to show.
func guidedOnlyLab(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	lab, err := os.ReadFile(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx", "lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), lab, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "playbooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	pb := `apiVersion: lab.podaro.dev/v1alpha1
kind: Playbook
metadata:
  name: guided-only
  title: Guided only
  modes: [guided]
steps:
  - id: look-around
    title: Look around
    body: Open the product tab.
    notes: SAY-THIS-ONLY-ON-STAGE
    checkpoint:
      id: web-serves
      adapter: http
      params: { url: http://web:80/ }
      expect: { status: 200 }
      hint: nginx answers on port 80 once the service is healthy.
`
	if err := os.WriteFile(filepath.Join(dir, "playbooks", "guided-only.yaml"), []byte(pb), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestPresenterIsRefusedForAPlaybookThatDoesNotDeclareIt.
//
// Presenter is a manner the *playbook* declares (spec 0001). Round 5
// stopped the chooser offering a link to a manner a playbook does not
// declare — and the render path went on serving it to anyone who typed
// the query, so `?mode=presenter` showed the presenter notes, suppressed
// the Verify button a learner needs, and started the Presenter rechecks.
//
// A hidden link is not a rule. The rule is the same predicate the
// chooser consults, applied where the manner is actually chosen; an
// undeclared manner falls back to Guided, as an unknown one does, so it
// can never cost a learner their controls.
func TestPresenterIsRefusedForAPlaybookThatDoesNotDeclareIt(t *testing.T) {
	srv, eng := newServer(t)
	dir := guidedOnlyLab(t)
	job, err := eng.Create(context.Background(), engine.CreateRequest{Path: dir, Name: "declared"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := eng.Wait(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	// The fixture produced the state: the playbook declares Guided and
	// not Presenter, and it carries a note only Presenter shows.
	code, out := call(t, srv, http.MethodGet, "/instances/declared/playbooks", nil)
	pbs, _ := out["playbooks"].([]any)
	if code != http.StatusOK || len(pbs) != 1 {
		t.Fatalf("playbooks: %d %v", code, out)
	}
	modes, _ := pbs[0].(map[string]any)["modes"].([]any)
	if len(modes) != 1 || modes[0] != "guided" {
		t.Fatalf("the fixture's playbook must declare guided alone, got %v", modes)
	}

	status, body := getHTML(t, srv, "/instances/declared/playbooks/guided-only?mode=presenter")
	if status != http.StatusOK {
		t.Fatalf("the rail was refused outright (%d); an undeclared manner falls back, it does not fail: %s", status, body)
	}
	if strings.Contains(body, `data-presenter="true"`) {
		t.Errorf("a playbook that declares only guided rendered its Presenter rail for ?mode=presenter")
	}
	if strings.Contains(body, "SAY-THIS-ONLY-ON-STAGE") {
		t.Errorf("the presenter note reached a rail the playbook never declared Presenter for")
	}
	if !strings.Contains(body, "verify-button") {
		t.Errorf("the fallback cost the learner the Verify button:\n%s", body)
	}
	// And the manner it does declare still renders as itself.
	if _, presenter := getHTML(t, srv, "/instances/declared/playbooks/guided-only"); strings.Contains(presenter, `data-presenter="true"`) {
		t.Errorf("the default manner is not Guided")
	}
}

// TestAReconnectIsToldWhereEveryJobStands.
//
// Round 15 seeded the connect from every job row and sent only the
// newest, by analogy with the journal's "stand at the tail". The analogy
// was wrong: the journal is append-only
// *events*, so standing at its tail withholds history a client can ask
// for again with `Last-Event-ID` — while a job row is *current state*,
// and row frames carry no id, so a reconnecting client has no way to ask
// about one at all. Marking a row delivered that this connection never
// sent lost that job's outcome for good.
//
// The fixture is the shape the finding names: a job that ended without
// journalling while the client was away, with a newer job admitted
// behind it.
func TestAReconnectIsToldWhereEveryJobStands(t *testing.T) {
	srv, eng, store := eventsHarness(t)
	ctx := context.Background()
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	job, err := eng.Create(ctx, engine.CreateRequest{Path: fixture, Name: "away"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Wait(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	// While the client was away: one job ended, another was admitted
	// behind it, and neither wrote to the journal.
	done := time.Now().UTC()
	ended := state.Job{ID: "job_ended17", Kind: "seed", Instance: "away", State: state.JobSucceeded,
		Stage: "done", Started: done.Add(-time.Second), Finished: &done}
	newer := state.Job{ID: "job_newer17", Kind: "verify", Instance: "away", State: state.JobRunning,
		Stage: "running its checkpoints", Started: done}
	for _, j := range []state.Job{ended, newer} {
		if err := store.PutJob(j); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := eng.Jobs("away", engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 3 || rows[0].ID != newer.ID || rows[1].ID != ended.ID {
		t.Fatalf("the fixture must leave the ended job behind the newer one; rows: %v", rows)
	}
	entries, err := eng.Evidence("away", engine.EvidenceFilter{}, engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Job == ended.ID {
			t.Fatalf("the fixture journalled %s; this case is about a job the journal does not carry", ended.ID)
		}
	}

	// The client comes back, naming the last journal fact it saw — which
	// says nothing about job rows, and is exactly why the feed cannot
	// assume any of them were delivered.
	body, closeFeed := openFeed(t, srv, "away", entries[len(entries)-1].ID)
	defer closeFeed()
	v, err := eng.View("away", engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	frames := readFrames(t, body, len(rows)+len(v.Services)+1, 6*time.Second, closeFeed)
	if got := jobFrames(frames, ended.ID); len(got) == 0 {
		t.Fatalf("a reconnecting client was never told job %s had ended; frames: %s", ended.ID, describe(frames))
	} else if got[len(got)-1].Data["state"] != string(state.JobSucceeded) {
		t.Fatalf("job %s was reported as %v, not %s", ended.ID, got[len(got)-1].Data["state"], state.JobSucceeded)
	}
	if len(jobFrames(frames, newer.ID)) == 0 {
		t.Errorf("the job admitted behind it was never reported; frames: %s", describe(frames))
	}
	if len(jobFrames(frames, job.ID)) == 0 {
		t.Errorf("the create job's row was never reported; frames: %s", describe(frames))
	}
}
