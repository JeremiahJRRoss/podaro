// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// Round 13 bound the six operations that carry an Actor and I wrote down
// what that left: the reads which carry none. The review took the note
// and made it the finding, which is the right answer — a read of the
// replacement lab hands over its metadata, its attendee list and its
// reveal records, and "metadata rather than a secret" is a smaller leak,
// not an acceptable one.
//
// Every attendee-reachable read now takes the actor and resolves for its
// generation, in the same call that will use the instance.
func TestEveryAttendeeReadIsBoundToItsGeneration(t *testing.T) {
	h := newHarness(t)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = h.eng.Shutdown(ctx)
	})
	job, err := h.eng.Create(context.Background(), CreateRequest{Path: fixture, Name: "gen"})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)
	inst, err := h.eng.Instance("gen", Socket)
	if err != nil {
		t.Fatal(err)
	}
	stale := inst.AuditFrom - 1
	mine := inst.AuditFrom
	as := func(gen int64) Actor {
		return Actor{Subject: "alice", Mechanism: "instance-access", Gen: &gen}
	}

	for _, c := range []struct {
		name string
		read func(by Actor) error
	}{
		{"view", func(by Actor) error { _, err := h.eng.View("gen", by); return err }},
		{"instance", func(by Actor) error { _, err := h.eng.Instance("gen", by); return err }},
		{"checkpoints", func(by Actor) error { _, err := h.eng.Checkpoints("gen", by); return err }},
		{"playbooks", func(by Actor) error { _, err := h.eng.Playbooks("gen", by); return err }},
		{"progress", func(by Actor) error { _, err := h.eng.Progress("gen", "p", by); return err }},
		{"step seeds", func(by Actor) error { _, err := h.eng.StepSeeds("gen", by); return err }},
		{"secrets", func(by Actor) error { _, err := h.eng.Secrets("gen", by); return err }},
		{"evidence", func(by Actor) error { _, err := h.eng.Evidence("gen", EvidenceFilter{}, by); return err }},
		{"report", func(by Actor) error { _, err := h.eng.Report("gen", by); return err }},
		{"junit", func(by Actor) error { _, err := h.eng.JUnit("gen", by); return err }},
	} {
		t.Run(c.name, func(t *testing.T) {
			// As in round 13: the code is the assertion. A read that
			// refused on its *target* had already resolved the lab.
			err := c.read(as(stale))
			if err == nil {
				t.Fatal("a bearer of an earlier generation read this one")
			}
			if got := code(err); got != pdr.CodeInstanceNotFound {
				t.Fatalf("refused with %s, not %s: the read reached the lab first", got, pdr.CodeInstanceNotFound)
			}
			// Its own generation still reads.
			if err := c.read(as(mine)); code(err) == pdr.CodeInstanceNotFound {
				t.Fatalf("the bearer's own generation was refused: %v", err)
			}
			// And the operator, bound to no generation, always reads.
			if err := c.read(Socket); code(err) == pdr.CodeInstanceNotFound {
				t.Fatalf("the operator was refused: %v", err)
			}
		})
	}
}
