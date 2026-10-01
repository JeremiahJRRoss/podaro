// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/state"
)

// UX §5: a regression — ready → anything less — is said in the bar. The
// stage alone cannot say one happened, so the engine keeps the highest
// rung the ladder has stood at and the view derives the fall from it.
// This drives a real one: a lab that reaches ready, a gate baseline that
// goes red under it, and the same baseline green again.
func TestARegressionIsSaidOnlyAfterTheLadderHasBeenReady(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	body := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: fallen, version: 1.0.0 }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }
checkpoints:
  - id: web-answers
    adapter: http
    params: { url: http://web:80/ }
    expect: { status: 200 }
    retries: { attempts: 1 }
`
	write := func(s string) {
		if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(body)
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "fallen"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	v, _ := h.eng.View("fallen", Socket)
	if v.Ladder.Stage != string(state.StageReady) || v.Ladder.Regressed {
		t.Fatalf("a lab that reached ready has not regressed: %+v", v.Ladder)
	}
	inst, err := h.store.GetInstance("fallen")
	if err != nil {
		t.Fatal(err)
	}
	if inst.Reached != state.StageReady {
		t.Fatalf("the high-water mark records ready: %q", inst.Reached)
	}

	// The baseline goes red under it: the ladder falls to seeded and the
	// bar says so.
	write(`apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: fallen, version: 1.0.0 }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }
checkpoints:
  - id: web-answers
    adapter: http
    params: { url: http://web:80/ }
    expect: { body_contains: "not in the page" }
    retries: { attempts: 1 }
`)
	vj, err := h.eng.VerifyAs(ctx, "fallen", "", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(vj.ID); j.State != state.JobSucceeded {
		t.Fatalf("a verify is a successful run whatever it finds: %+v", j)
	}
	v, _ = h.eng.View("fallen", Socket)
	if v.Ladder.Stage != string(state.StageSeeded) || !v.Ladder.Regressed {
		t.Fatalf("a red gate baseline under a ready lab is a regression: %+v", v.Ladder)
	}
	// The mark is the high-water mark: a demote never lowers it, which is
	// the whole reason the fall is sayable a second time.
	inst, _ = h.store.GetInstance("fallen")
	if inst.Stage != state.StageSeeded || inst.Reached != state.StageReady {
		t.Fatalf("the demote lowers the stage and not the mark: stage %q mark %q", inst.Stage, inst.Reached)
	}

	// Green again: ready, and nothing amber left behind.
	write(body)
	vj, err = h.eng.VerifyAs(ctx, "fallen", "", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(vj.ID); j.State != state.JobSucceeded {
		t.Fatalf("verify: %+v", j)
	}
	if v, _ := h.eng.View("fallen", Socket); v.Ladder.Stage != string(state.StageReady) || v.Ladder.Regressed {
		t.Fatalf("a lab that is ready again is not regressed: %+v", v.Ladder)
	}
}

// A lab that has never been ready is never amber, however low it stands:
// the first climb is not a fall. TestGateBaselineFailureStopsAtSeeded
// drives one to seeded the hard way; this asks the derivation directly,
// including the clause a running job supplies — a reset dips below ready
// by design, and UX §5's Presenter rule allows no alarm for it.
func TestTheLadderCallsAFallARegressionAndNothingElse(t *testing.T) {
	running := &state.Job{Kind: "reset", State: state.JobRunning}
	for _, c := range []struct {
		what    string
		stage   state.Stage
		reached state.Stage
		active  bool
		latest  *state.Job
		want    bool
	}{
		{"climbing for the first time", state.StageSeeded, state.StageSeeded, false, nil, false},
		{"never been ready, idle at seeded", state.StageSeeded, state.StageVerified, false, nil, false},
		{"ready and standing there", state.StageReady, state.StageReady, false, nil, false},
		{"fallen from ready", state.StageSeeded, state.StageReady, false, nil, true},
		{"fallen to nothing at all", state.StageNone, state.StageReady, false, nil, true},
		{"being worked on", state.StageSeeded, state.StageReady, true, running, false},
		{"still climbing, nothing reached", state.StageNone, state.StageNone, false, nil, false},
	} {
		got := ladderView(c.stage, c.reached, c.active, c.latest).Regressed
		if got != c.want {
			t.Errorf("%s (stage %q, mark %q, active %v): regressed = %v, want %v", c.what, c.stage, c.reached, c.active, got, c.want)
		}
	}
}
