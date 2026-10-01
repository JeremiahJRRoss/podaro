// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// Review round 68: RunCheckpoint's standing-attestation shortcut returned a
// row without the guarded rebuild check every other answer goes through,
// so a reset admitted after the first check but before the read had the
// run answer 200 with a confirmation the reset was about to clear.

const attestTemplate = "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: att, version: 1.0.0 }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\ncheckpoints:\n  - id: confirmed\n    adapter: attest\n    class: objective\n    params: { prompt: \"Did you look at the page?\" }\n    retries: { attempts: 1 }\n    hint: Open the page and confirm.\n"

func attestedInstance(t *testing.T, h *harness) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(attestTemplate), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "att"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	if _, err := h.eng.Attest(ctx, "att", "confirmed", "looked", Actor{Subject: "operator", Mechanism: "socket"}); err != nil {
		t.Fatal(err)
	}
}

func TestAStandingAttestationIsNotAnsweredWhileAResetOwnsTheLab(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	attestedInstance(t, h)

	// The standing row exists and is what an unraced run answers.
	res, err := h.eng.RunCheckpoint(ctx, "att", "confirmed", Socket)
	if err != nil {
		t.Fatalf("an unraced run must answer the standing attestation: %v", err)
	}
	if res.Status != "attested" {
		t.Fatalf("unraced run: %+v", res)
	}

	// Now admit a reset in the window the shortcut used to run through.
	var resetJob *state.Job
	beforeStandingAttestation = func(name string) {
		if resetJob != nil {
			return
		}
		j, err := h.eng.ResetAs(ctx, name, Actor{Subject: "operator", Mechanism: "socket"})
		if err != nil {
			t.Errorf("admitting the reset: %v", err)
			return
		}
		resetJob = j
	}
	t.Cleanup(func() { beforeStandingAttestation = nil })

	_, err = h.eng.RunCheckpoint(ctx, "att", "confirmed", Socket)
	if err == nil {
		t.Fatal("the run answered a standing attestation while a reset owned the lab")
	}
	if code(err) != pdr.CodeInstanceBusy {
		t.Fatalf("want %s, got %v", pdr.CodeInstanceBusy, err)
	}
	if resetJob == nil {
		t.Fatal("the seam did not admit a reset; the case proves nothing")
	}
	// Let the reset finish so the harness tears down cleanly, and confirm
	// it did what the refusal said it would: the confirmation is cleared.
	h.wait(resetJob.ID)
	rows, err := h.store.ListCheckpointResults("att")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.ID == "confirmed" && r.Status == "attested" {
			t.Fatalf("the reset left the attestation standing: %+v", r)
		}
	}
}

// The guard refuses; it does not lose the row. With no reset in the way,
// the standing attestation is still answered from inside the guard.
func TestAStandingAttestationIsStillAnsweredUnderTheGuard(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	attestedInstance(t, h)
	for i := 0; i < 3; i++ {
		res, err := h.eng.RunCheckpoint(ctx, "att", "confirmed", Socket)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if res.Status != "attested" || res.ID != "confirmed" {
			t.Fatalf("run %d: %+v", i, res)
		}
	}
}
