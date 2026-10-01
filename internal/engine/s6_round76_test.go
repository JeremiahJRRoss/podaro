// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Review round 76: an exec verdict's `evidence.capture` is arbitrary JSON
// under the contract, and the engine merged it over its own keys — so an
// adapter could make immutable evidence claim an image digest and a
// grant set the run never used. Evidence is what a lab is judged on; the
// two facts the engine knows first-hand are its own to state.

func TestAnAdapterCannotClaimTheEnginesCaptureKeys(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	image := "docker.io/podaro/exec-conformance@sha256:" + strings.Repeat("e", 64)
	lab := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: claims, version: 1.0.0 }
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
    params: { image: IMAGE, args: [claim], secrets: [tok] }
    expect: { ok: true }
    retries: { attempts: 1 }
`
	_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(strings.ReplaceAll(lab, "IMAGE", image)), 0o644)
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "claims"})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)

	entries, _ := h.eng.Evidence("claims", EvidenceFilter{Type: "checkpoint"}, Socket)
	observed := ""
	for _, e := range entries {
		if e.Checkpoint != nil && e.Checkpoint.ID == "judged" {
			observed = string(e.Checkpoint.Observed)
		}
	}
	if observed == "" {
		t.Fatal("the checkpoint left no evidence")
	}
	if strings.Contains(observed, "attacker/other") {
		t.Fatalf("evidence carries the image the adapter claimed, not the one the run used: %s", observed)
	}
	if !strings.Contains(observed, image) {
		t.Fatalf("evidence must carry the image the run used: %s", observed)
	}
	if strings.Contains(observed, "never-granted") {
		t.Fatalf("evidence carries the grant set the adapter claimed: %s", observed)
	}
	flat := strings.Join(strings.Fields(observed), "")
	if !strings.Contains(flat, `"secrets":["tok"]`) {
		t.Fatalf("evidence must carry the grants the run made: %s", observed)
	}
	// The adapter's other capture keys still arrive — only the engine's
	// own are reserved.
	if !strings.Contains(observed, "run_id") {
		t.Fatalf("an adapter's own capture keys are kept: %s", observed)
	}
}
