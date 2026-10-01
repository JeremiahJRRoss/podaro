// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/state"
)

// Review round 75, finding 2: a reset removes a service's container and
// then records `none`. When that record — or the event after it — fails,
// the demotion rewrote the row to `alive`: a service reported running
// with no container and no id, which the stage recompute may then read as
// a live rung. What the container did is what the row must say.

// refuseRemovalEvent lets the removal and its row through, and refuses
// the journal line that follows — the second of the two failures the
// finding names, and the one that leaves the row correct until the
// demotion rewrites it.
type refuseRemovalEvent struct {
	state.Store
	service string
}

func (r *refuseRemovalEvent) AppendEvent(e state.Event) error {
	if e.Step == "remove" && e.Service == r.service && e.Status == "ok" {
		return errors.New("refused: the journal is locked")
	}
	return r.Store.AppendEvent(e)
}

func TestAResetKeepsARemovedServiceAtNoneWhenItsRecordIsRefused(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	attestedInstance(t, h)

	h.eng.opts.Store = &refuseRemovalEvent{Store: h.eng.opts.Store, service: "web"}
	rj, err := h.eng.ResetAs(ctx, "att", Actor{Subject: "operator", Mechanism: "socket"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(rj.ID); j.State != state.JobFailed {
		t.Fatalf("the reset was expected to fail: %+v", j)
	}
	// The container is gone. Whatever the store did about recording it,
	// the row must not claim a running one.
	svc, err := h.eng.Service("att", "web")
	if err != nil || svc == nil {
		t.Fatalf("service row: %v %+v", err, svc)
	}
	if svc.Stage != state.StageNone {
		t.Fatalf("a removed container left the row saying %s with container id %q", svc.Stage, svc.ContainerID)
	}
	if svc.ContainerID != "" {
		t.Fatalf("the row keeps a container id for a container that is gone: %q", svc.ContainerID)
	}
}

// Review round 75, finding 1: an exec checkpoint whose image cannot be
// prepared — a pull that fails, an image that runs as root — recorded no
// capture at all, so the evidence omits the image and the grants the
// checkpoint asked for. Both are known before anything is pulled.
func TestExecEvidenceRecordsTheImageAndGrantsWhenPreparationFails(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	// An image the engine refuses at preparation, before anything runs:
	// the conformance fixture's root variant (PDR-E505).
	missing := "docker.io/podaro/exec-conformance-root@sha256:" + strings.Repeat("b", 64)
	lab := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: pulls, version: 1.0.0 }
secrets:
  tok: { kind: token }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }
checkpoints:
  - id: judged
    adapter: exec
    params: { image: MISSING, args: [pass], secrets: [tok, tok] }
    expect: { ok: true }
    severity: warn
    retries: { attempts: 1 }
`
	_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(strings.ReplaceAll(lab, "MISSING", missing)), 0o644)
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "pulls"})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)
	entries, _ := h.eng.Evidence("pulls", EvidenceFilter{Type: "checkpoint"}, Socket)
	var observed string
	found := false
	for _, e := range entries {
		if e.Checkpoint != nil && e.Checkpoint.ID == "judged" {
			found = true
			observed = string(e.Checkpoint.Observed)
		}
	}
	if !found {
		t.Fatal("the refused checkpoint left no evidence entry at all")
	}
	if observed == "" || observed == "null" {
		t.Fatalf("the evidence entry carries no capture: the image and the grants are known before anything is pulled (observed %q)", observed)
	}
	flat := strings.Join(strings.Fields(observed), "")
	if !strings.Contains(flat, `"secrets":["tok"]`) {
		t.Fatalf("evidence must record the grants the checkpoint asked for, once: %s", observed)
	}
	if !strings.Contains(observed, missing) {
		t.Fatalf("evidence must record the image that could not be prepared: %s", observed)
	}
}
