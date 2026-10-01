// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/lab"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
	"github.com/jeremiahjrross/podaro/internal/verify"
)

// Review round 69, finding 1: freshness compared wall-clock instants, so a
// host clock corrected backwards reversed the order of two evaluations —
// a later one read as older and was discarded, and an attestation begun
// before a reset could read as later than the reset's own mark and
// survive it. Order is now a counter that only counts up.

// orderingInstance creates a lab whose checkpoints are ordinary machine
// checks, so freshness is the only thing that can supersede a result —
// an attest checkpoint would be superseded by its standing attestation
// for a different reason entirely, and prove nothing about ordering.
func orderingInstance(t *testing.T, h *harness) (*labView, lab.FlatCheckpoint) {
	t.Helper()
	job, err := h.eng.Create(context.Background(), CreateRequest{Template: "grafana-prometheus-intro", Name: "ord"})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)
	lv, err := h.eng.instanceView("ord")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range lv.checkpoints {
		if c.Adapter == "http" {
			return lv, c
		}
	}
	t.Fatal("the template has no http checkpoint")
	return nil, lab.FlatCheckpoint{}
}

// Two evaluations, the second beginning after the first. Whatever the
// host clock says, the later ticket is the later observation and the
// earlier one never replaces it.
func TestFreshnessOrdersByTicketNotByTheClock(t *testing.T) {
	h := newHarness(t)
	lv, cp := orderingInstance(t, h)

	first := h.eng.evalTicket()
	second := h.eng.evalTicket()
	if !(first < second) {
		t.Fatalf("tickets must increase: %d then %d", first, second)
	}
	pass := verify.Result{Status: verify.StatusPass, Observed: map[string]any{"status": 200}, Expected: map[string]any{"status": 200}, Message: "later"}
	if _, err := h.eng.record(lv, cp, pass, "", second); err != nil {
		t.Fatal(err)
	}
	// The earlier evaluation records last. It is the older observation
	// and must not become the latest result, however the clock moved.
	older := verify.Result{Status: verify.StatusFail, Observed: map[string]any{"status": 500}, Expected: map[string]any{"status": 200}, Message: "earlier"}
	rec, err := h.eng.record(lv, cp, older, "", first)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.superseded {
		t.Fatalf("an evaluation that began earlier replaced a later one: %+v", rec)
	}
	if rec.latest.Message != "later" {
		t.Fatalf("the standing result is not the later evaluation's: %+v", rec.latest)
	}
}

// An attestation that began before a reset stays in evidence only, and a
// clock cannot rescue it: its ticket is smaller than the reset's, full
// stop.
func TestAnAttestationBeforeAResetCannotOutrankItByTheClock(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	attestedInstance(t, h)
	lv, err := h.eng.instanceView("att")
	if err != nil {
		t.Fatal(err)
	}
	var cp lab.FlatCheckpoint
	for _, c := range lv.checkpoints {
		if c.ID == "confirmed" {
			cp = c
		}
	}
	before := h.eng.evalTicket()
	rj, err := h.eng.ResetAs(ctx, "att", Actor{Subject: "operator", Mechanism: "socket"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(rj.ID); j.State != state.JobSucceeded {
		t.Fatalf("reset: %+v", j)
	}
	att := verify.Result{Status: verify.StatusAttested, Observed: map[string]any{"attested": true}, Expected: map[string]any{"attested": true}, Message: "looked"}
	rec, err := h.eng.record(lv, cp, att, "", before)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.superseded {
		t.Fatalf("an attestation begun before the reset survived it: %+v", rec)
	}
	// And one that began after it stands.
	rec2, err := h.eng.record(lv, cp, att, "", h.eng.evalTicket())
	if err != nil {
		t.Fatal(err)
	}
	if rec2.superseded {
		t.Fatalf("an attestation begun after the reset was discarded: %+v", rec2)
	}
}

// Review round 69, finding 3: a reset that fails after teardown began left
// the instance claiming `ready` with its old green results, for
// containers that were already gone.

func TestAResetThatFailsAfterTeardownDemotesTheInstance(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	attestedInstance(t, h)

	// Ready, with a standing confirmation, before the reset.
	before, err := h.eng.View("att", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if before.Ladder.Stage != "ready" {
		t.Fatalf("the lab must be ready first: %+v", before.Ladder)
	}
	rows, _ := h.store.ListCheckpointResults("att")
	if len(rows) == 0 {
		t.Fatal("the lab must have results first")
	}

	// The removal of the (only) service fails — after its route is gone,
	// which is the window this round is about. A wrapper refuses it, as
	// earlier rounds wrap the fake to stage a runtime fault. The removal
	// addresses the container by the id it recorded (rounds 45–48), so
	// that is what the wrapper must refuse.
	svcs, err := h.store.ListServices("att")
	if err != nil || len(svcs) == 0 {
		t.Fatalf("services of att: %v %v", svcs, err)
	}
	h.eng.opts.Runtime = &refuseRemove{Runtime: h.eng.opts.Runtime,
		refs: map[string]bool{svcs[0].ContainerID: true, "pdr-att-" + svcs[0].Name: true}}
	rj, err := h.eng.ResetAs(ctx, "att", Actor{Subject: "operator", Mechanism: "socket"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(rj.ID); j.State != state.JobFailed {
		t.Fatalf("the reset was expected to fail: %+v", j)
	}

	after, err := h.eng.View("att", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if after.Ladder.Stage == "ready" {
		t.Errorf("a reset that tore the lab down and failed left it claiming ready: %+v", after.Ladder)
	}
	rows, err = h.store.ListCheckpointResults("att")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Status != "" {
			t.Errorf("a stale result survived a failed reset: %+v", r)
		}
	}
	if after.Checkpoints.Baseline.Passed != 0 || after.Checkpoints.Objective.Passed != 0 {
		t.Errorf("the tally still claims passes: %+v", after.Checkpoints)
	}
}

// refuseRemove fails the removal of one container and passes everything
// else through: the runtime fault a reset can meet halfway down.
type refuseRemove struct {
	runtime.Runtime
	refs map[string]bool
}

func (r *refuseRemove) Remove(ctx context.Context, ref string) error {
	if r.refs[ref] {
		return errors.New("refused: the container is in use")
	}
	return r.Runtime.Remove(ctx, ref)
}
