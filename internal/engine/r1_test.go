// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/evidence"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// The reconciliation plan's R1: the licence gate is proven on a fixture
// that declares a EULA nobody holds. API §6.2 promises that an
// acceptance is explicit, per create, and recorded in evidence with
// actor and timestamp; until R1 the engine kept it on the instance row
// alone, where no evidence reader could see it.
func TestALicenceAcceptanceIsRecordedWithActorAndTimestamp(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\n" +
		"metadata: { name: gated, version: 1.0.0 }\n" +
		"licenses: [example-terms]\n" +
		"services:\n" +
		"  gated:\n    image: docker.io/example/terms-gated@sha256:" + strings.Repeat("9", 64) + "\n" +
		"    eula: { id: example-terms, name: Example Terms, url: \"https://example.com/terms\", env: { ACCEPT_EXAMPLE_TERMS: \"yes\" } }\n" +
		"    endpoints: [ { purpose: ui, port: 80 } ]\n" +
		"    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	// Refused without the acceptance, and nothing recorded for the refusal.
	if _, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "gated"}); err == nil || !strings.Contains(err.Error(), "PDR-E031") {
		t.Fatalf("a create without the acceptance must be refused with PDR-E031: %v", err)
	}
	if audits, _ := h.store.ListAudit("gated"); len(audits) != 0 {
		t.Fatalf("a refused create recorded %d audit rows", len(audits))
	}

	alice := Actor{Subject: "alice", Mechanism: "session"}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "gated", AcceptLicenses: []string{"example-terms"}, Actor: alice})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}
	inst, err := h.store.GetInstance("gated")
	if err != nil {
		t.Fatal(err)
	}
	// The audit stream: one row, inside the instance's own window, naming
	// the id, the actor and the door — never the terms' text.
	audits, err := h.store.ListAudit("gated")
	if err != nil {
		t.Fatal(err)
	}
	var accepted []state.Audit
	for _, a := range audits {
		if a.Action == "accept-license" {
			accepted = append(accepted, a)
		}
	}
	if len(accepted) != 1 || accepted[0].Detail != "example-terms" || accepted[0].Actor != "alice" || accepted[0].Mechanism != "session" || accepted[0].At.IsZero() {
		t.Fatalf("the acceptance in the audit stream: %+v", accepted)
	}
	if accepted[0].Seq <= inst.AuditFrom {
		t.Fatalf("the acceptance (seq %d) falls before the instance's window (%d)", accepted[0].Seq, inst.AuditFrom)
	}
	// The evidence journal carries it too, as it carries a reveal.
	entries, err := h.eng.journal("gated").List(evidence.Filter{Type: evidence.TypeAudit})
	if err != nil {
		t.Fatal(err)
	}
	var journaled []evidence.Entry
	for _, en := range entries {
		if en.Audit != nil && en.Audit.Action == "accept-license" {
			journaled = append(journaled, en)
		}
	}
	if len(journaled) != 1 || journaled[0].Audit.Detail != "example-terms" || journaled[0].Audit.Actor != "alice" || journaled[0].At.IsZero() {
		t.Fatalf("the acceptance in evidence: %+v", journaled)
	}
	// Recorded once: a create that presents no new terms records nothing
	// more, and the instance keeps the one id.
	if _, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "gated", AcceptLicenses: []string{"example-terms"}, Actor: alice}); err == nil {
		t.Fatal("a second create of a running instance is refused")
	}
	audits, _ = h.store.ListAudit("gated")
	n := 0
	for _, a := range audits {
		if a.Action == "accept-license" {
			n++
		}
	}
	if n != 1 || len(inst.Licenses) != 1 {
		t.Fatalf("the acceptance is recorded once: %d rows, licenses %v", n, inst.Licenses)
	}
	// The local door's create records the socket as the mechanism.
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "lab.yaml"), []byte(strings.Replace(lab, "name: gated", "name: gated2", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err = h.eng.Create(ctx, CreateRequest{Path: other, Name: "gated2", AcceptLicenses: []string{"example-terms"}})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)
	audits, _ = h.store.ListAudit("gated2")
	found := false
	for _, a := range audits {
		if a.Action == "accept-license" && a.Mechanism == "socket" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the local door's acceptance names the socket: %+v", audits)
	}
}
