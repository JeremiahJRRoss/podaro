// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/evidence"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// Review round 70, finding 2: the evidence merge sorted the combined list
// by wall-clock `At`, which undoes round 65's guarantee — Journal.List
// returns entries in monotonic id order, and a clock-keyed comparator
// puts them back in clock order, reversing two appends across a
// correction. The API says §10's listing is append order.

func TestEvidenceKeepsTheJournalsOrderWhateverTheClock(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "ord"})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)

	// Append three entries with the clock moving *backwards* between
	// them. Their ids stay monotonic (round 65), so append order is
	// recoverable — and must survive the read.
	j := h.eng.journal("ord")
	base := time.Now().UTC()
	var ids []string
	for i, at := range []time.Time{base, base.Add(-time.Second), base.Add(-2 * time.Second)} {
		e, err := j.Append(evidence.Entry{Type: evidence.TypeLifecycle, Instance: "ord", At: at,
			Lifecycle: &evidence.Lifecycle{Event: "mark", Detail: string(rune('a' + i))}})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, e.ID)
	}

	entries, err := h.eng.Evidence("ord", EvidenceFilter{}, Socket)
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	for _, e := range entries {
		for _, want := range ids {
			if e.ID == want {
				seen = append(seen, e.ID)
			}
		}
	}
	if len(seen) != len(ids) {
		t.Fatalf("the three appended entries are not all listed: %v", seen)
	}
	for i := range ids {
		if seen[i] != ids[i] {
			t.Fatalf("the listing is not append order:\n got: %v\nwant: %v", seen, ids)
		}
	}
}

// An audit row still lands among them, and the journal's own order is
// still the one that survives.
func TestEvidenceMergesAuditWithoutDisturbingTheJournal(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "ord"})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)

	j := h.eng.journal("ord")
	base := time.Now().UTC()
	var ids []string
	for i := 0; i < 3; i++ {
		e, err := j.Append(evidence.Entry{Type: evidence.TypeLifecycle, Instance: "ord",
			At:        base.Add(-time.Duration(i) * time.Second), // the clock moves back
			Lifecycle: &evidence.Lifecycle{Event: "mark"}})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, e.ID)
	}
	if err := h.store.AppendAudit(state.Audit{Seq: 1, At: base.Add(-1500 * time.Millisecond),
		Instance: "ord", Action: "reveal", Actor: "operator", Mechanism: "socket", Detail: "secret x"}); err != nil {
		t.Fatal(err)
	}

	entries, err := h.eng.Evidence("ord", EvidenceFilter{}, Socket)
	if err != nil {
		t.Fatal(err)
	}
	var journalOrder []string
	audits := 0
	for _, e := range entries {
		for _, want := range ids {
			if e.ID == want {
				journalOrder = append(journalOrder, e.ID)
			}
		}
		if e.Type == evidence.TypeAudit {
			audits++
		}
	}
	if audits == 0 {
		t.Fatal("the audit row was not merged in")
	}
	for i := range ids {
		if journalOrder[i] != ids[i] {
			t.Fatalf("merging audit disturbed the journal's order:\n got: %v\nwant: %v", journalOrder, ids)
		}
	}
}

// Review round 70, findings 1 and 3: after the lab is down, every failure
// must still demote — including a store that refuses the clearing, which
// must not also cost the stage refresh.

// refuseResults fails the store operations a reset's clearing needs.
type refuseResults struct {
	state.Store
	on string
}

func (r *refuseResults) DeleteCheckpointResults(instance, id string) error {
	if r.on == "delete" {
		return errors.New("refused: the results table is locked")
	}
	return r.Store.DeleteCheckpointResults(instance, id)
}

func TestAResetDemotesEvenWhenTheClearingIsRefused(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	attestedInstance(t, h)

	before, err := h.eng.View("att", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if before.Ladder.Stage != "ready" {
		t.Fatalf("the lab must be ready first: %+v", before.Ladder)
	}

	// The lab comes down cleanly, and then the store refuses to clear.
	h.eng.opts.Store = &refuseResults{Store: h.eng.opts.Store, on: "delete"}
	rj, err := h.eng.ResetAs(ctx, "att", Actor{Subject: "operator", Mechanism: "socket"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(rj.ID); j.State != state.JobFailed {
		t.Fatalf("the reset was expected to fail: %+v", j)
	}

	// The containers are gone, so the instance must not still say ready —
	// whatever the store did about the results.
	after, err := h.eng.View("att", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if after.Ladder.Stage == "ready" {
		t.Errorf("a reset whose clearing was refused left the instance claiming ready: %+v", after.Ladder)
	}
}
