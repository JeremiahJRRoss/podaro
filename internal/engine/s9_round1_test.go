// SPDX-License-Identifier: AGPL-3.0-only

package engine

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

// The reconcile's lifecycle entry — the durable one, the proof an
// operator reads afterwards — was appended before the evaluation ran. If
// the evaluation then failed, the evidence permanently claimed a
// re-verification that never completed, which is the exact opposite of
// what the entry exists for. Evidence is immutable, so the claim could
// not be taken back either.
// countBeforeEvaluate is which ListCheckpointResults call belongs to the
// reconcile's evaluation: the reads before it are the stage's own.
const countBeforeEvaluate = 2

func TestNoReconcileIsRecordedThatDidNotHappen(t *testing.T) {
	h := newHarness(t)
	faulty := &faultyStore{Store: h.store}
	h.store = faulty
	h.open()
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
`
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "proven"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}

	// The host restarts, and the re-verification cannot run: the store
	// refuses the read every evaluation begins with.
	h.fake.Close()
	if err := runtime.Reboot(h.world); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	// The reconcile reads the results before it re-verifies them; it is
	// the evaluation's own read that must fail, so the count says which.
	faulty.set(func(f *faultyStore) { f.listResults = 0; f.failListResultsFrom = countBeforeEvaluate })
	h.open()
	if err := h.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, _ := h.store.ListJobs("proven")
	if len(jobs) == 0 || jobs[0].Kind != "reconcile" {
		t.Fatalf("expected a reconcile job, got %+v", jobs)
	}
	if j := h.wait(jobs[0].ID); j.State != state.JobFailed {
		t.Fatalf("the reconcile should have failed on the refused read: %+v", j)
	}
	faulty.set(func(f *faultyStore) { f.failListResultsFrom = 0 })

	entries, err := h.eng.Evidence("proven", EvidenceFilter{Type: string(evidence.TypeLifecycle)}, Socket)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Lifecycle != nil && entry.Lifecycle.Event == "reconcile" {
			t.Fatalf("the evidence claims a re-verification that never ran: %q", entry.Lifecycle.Detail)
		}
	}

	// And the live feed still said it was under way — the commentary is
	// not the proof, and losing it would leave an operator watching a
	// silent restart.
	if journal := journalOf(h, jobs[0].ID); !strings.Contains(journal, "reconcile: baselines re-verified") {
		t.Errorf("the feed did not say the re-verification had begun:\n%s", journal)
	}
}
