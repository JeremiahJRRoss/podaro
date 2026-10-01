// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/state"
)

// Review round 74: round 73 made a repeated grant one grant — the run
// creates one object and the contract's stdin lists it once — but the
// seed's evidence still copied the authored list, so an immutable record
// claimed two grants where one was made. Evidence says what happened.

func TestSeedEvidenceRecordsTheGrantsTheRunMade(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	image := "docker.io/podaro/exec-conformance@sha256:" + strings.Repeat("e", 64)
	lab := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: grants, version: 1.0.0 }
secrets:
  tok: { kind: token }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }
seeds:
  orders: { generator: { exec: { image: IMAGE, args: [pass], secrets: [tok, tok] } }, count: 1 }
`
	lab = strings.ReplaceAll(lab, "IMAGE", image)
	_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644)
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "grants"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	seeds, _ := h.eng.Evidence("grants", EvidenceFilter{Type: "seed"}, Socket)
	if len(seeds) != 1 || seeds[0].Seed == nil {
		t.Fatalf("one seed run in evidence, got %d", len(seeds))
	}
	if got := seeds[0].Seed.Secrets; len(got) != 1 || got[0] != "tok" {
		t.Fatalf("evidence records the grants the run made: %v, and the run made one", got)
	}
}
