// SPDX-License-Identifier: AGPL-3.0-only

package engine

// Plan S9, User Manual §8: after a reboot the baselines re-verify — and
// the engine says so. "Ready" that survives a restart is a claim, and
// the evidence must carry the proof behind it: which run judged the
// board, and which half of it that run covered.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/evidence"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// TestReconcileReVerifiesTheBaselinesAndSaysSo: the baseline result is
// judged again — a new verdict with a later time, not the one carried
// over — and the journal and the evidence both name the run that did it.
func TestReconcileReVerifiesTheBaselinesAndSaysSo(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	body := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: proven, version: 1.0.0 }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }
checkpoints:
  - id: web-up
    adapter: http
    params: { url: http://web:80/ }
    expect: { status: 200 }
    retries: { attempts: 1 }
    hint: Is the web service answering on port 80?
  - id: the-work
    class: objective
    adapter: http
    params: { url: http://web:80/done }
    expect: { status: 200 }
    retries: { attempts: 1 }
    hint: The learner's work.
`
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "proven"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	before := map[string]time.Time{}
	rows, err := h.store.ListCheckpointResults("proven")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		before[r.ID] = r.At
	}
	if before["web-up"].IsZero() || before["the-work"].IsZero() {
		t.Fatalf("the create judged both classes: %+v", before)
	}

	// The host restarts: every container stops, and the next start
	// reconciles. The clock must move, or "judged again" is unprovable.
	h.fake.Close()
	if err := runtime.Reboot(h.world); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	h.open()
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, _ := h.store.ListJobs("proven")
	if len(jobs) != 2 || jobs[0].Kind != "reconcile" {
		t.Fatalf("expected a reconcile job, got %+v", jobs)
	}
	if j := h.wait(jobs[0].ID); j.State != state.JobSucceeded {
		t.Fatalf("reconcile: %+v\n%s", j, journalOf(h, jobs[0].ID))
	}

	rows, err = h.store.ListCheckpointResults("proven")
	if err != nil {
		t.Fatal(err)
	}
	after := map[string]state.CheckpointResult{}
	for _, r := range rows {
		after[r.ID] = r
	}
	// The baseline was judged again: a verdict earned before the reboot
	// says nothing about a lab that has since restarted.
	if !after["web-up"].At.After(before["web-up"]) {
		t.Errorf("the baseline was not re-verified: %s then %s", before["web-up"], after["web-up"].At)
	}
	if after["web-up"].Status != "pass" {
		t.Errorf("the baseline did not pass after the reconcile: %+v", after["web-up"])
	}
	// The objective was not: it is the learner's work, and the container
	// kept what it held.
	if !after["the-work"].At.Equal(before["the-work"]) {
		t.Errorf("the objective was re-judged by a reconcile that recreated nothing: %s then %s",
			before["the-work"], after["the-work"].At)
	}

	// And the engine says so, in the journal a reader watches…
	journal := journalOf(h, jobs[0].ID)
	for _, want := range []string{
		"verifying ok reconcile: baselines re-verified; the objectives keep their verdicts",
		"verified ok reconciled · baseline 1/1",
		"ready ok reconciled ·",
	} {
		if !strings.Contains(journal, want) {
			t.Errorf("the reconcile journal lacks %q:\n%s", want, journal)
		}
	}
	// …and in the evidence a reader reads afterwards.
	entries, err := h.eng.Evidence("proven", EvidenceFilter{Type: string(evidence.TypeLifecycle)}, Socket)
	if err != nil {
		t.Fatal(err)
	}
	var recon, ready *evidence.Lifecycle
	for i := range entries {
		switch entries[i].Lifecycle.Event {
		case "reconcile":
			recon = entries[i].Lifecycle
		case "ready":
			ready = entries[i].Lifecycle
		}
	}
	if recon == nil || !strings.Contains(recon.Detail, "baselines re-verified") {
		t.Fatalf("evidence carries no reconcile entry saying what it re-verified: %+v", recon)
	}
	if ready == nil || !strings.HasPrefix(ready.Detail, "reconciled ·") {
		t.Fatalf("the ready entry does not say which run produced its counts: %+v", ready)
	}
}

// TestAReconcileThatRecreatedAContainerSaysTheOtherThing: when the
// container is gone, the data a verdict was earned in is gone with it,
// so both classes are judged again — and the record says that instead.
func TestAReconcileThatRecreatedAContainerSaysTheOtherThing(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "gone"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	// The container does not come back: it is removed outright, which is
	// what a `podman rm` between engine runs looks like.
	svcs, err := h.store.ListServices("gone")
	if err != nil || len(svcs) == 0 {
		t.Fatalf("services of gone: %v %d", err, len(svcs))
	}
	h.fake.Close()
	if err := runtime.Reboot(h.world); err != nil {
		t.Fatal(err)
	}
	h.open()
	if err := h.fake.Remove(ctx, svcs[0].Container); err != nil {
		t.Fatal(err)
	}
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, _ := h.store.ListJobs("gone")
	if len(jobs) != 2 || jobs[0].Kind != "reconcile" {
		t.Fatalf("expected a reconcile job, got %+v", jobs)
	}
	if j := h.wait(jobs[0].ID); j.State != state.JobSucceeded {
		t.Fatalf("reconcile: %+v\n%s", j, journalOf(h, jobs[0].ID))
	}
	journal := journalOf(h, jobs[0].ID)
	if !strings.Contains(journal, "a container was recreated, so the data a verdict was earned in is gone") {
		t.Fatalf("the reconcile does not say it re-judged everything:\n%s", journal)
	}
}
