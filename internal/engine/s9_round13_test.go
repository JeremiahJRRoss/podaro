// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// Round 12 put the generation check in the API, before the handler ran.
// That is a *precheck*: it resolves the instance, compares, throws the
// result away, and the handler resolves the lab again. Between those two
// resolutions the name can become a different lab, and the operation
// acts on the one it resolved rather than the one that was checked. The
// post-body checks round 12 added have the identical window — they are
// prechecks too, only later ones.
//
// The generation is now compared inside the operation's own resolution,
// against the instance that operation is about to use. There is no
// second resolution to disagree with the first.
//
// This exercises the engine directly, because that is where the property
// lives: an Actor entitled to one generation cannot reach another,
// whatever the caller checked beforehand.
func TestAnActorReachesOnlyItsOwnGeneration(t *testing.T) {
	h := newHarness(t)
	job, err := h.eng.Create(context.Background(), CreateRequest{Path: fixture, Name: "gen"})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)
	inst, err := h.eng.Instance("gen", Socket)
	if err != nil {
		t.Fatal(err)
	}

	stale := inst.AuditFrom - 1 // the generation before this one
	mine := inst.AuditFrom
	attendee := func(gen int64) Actor {
		return Actor{Subject: "alice", Mechanism: "instance-access", Gen: &gen}
	}

	// Every operation an attendee can reach that carries an Actor. Each
	// resolves the instance itself, and each must refuse the generation
	// that is not its own.
	for _, c := range []struct {
		name string
		call func(by Actor) error
	}{
		{"reveal", func(by Actor) error {
			_, err := h.eng.Reveal(context.Background(), "gen", "nothing", by)
			return err
		}},
		{"attest", func(by Actor) error {
			_, err := h.eng.Attest(context.Background(), "gen", "nginx-up", "by hand", by)
			return err
		}},
		{"verify", func(by Actor) error {
			_, err := h.eng.VerifyAs(context.Background(), "gen", "", by)
			return err
		}},
		{"seed", func(by Actor) error {
			_, err := h.eng.SeedAs(context.Background(), "gen", "nothing", by)
			return err
		}},
		{"run checkpoint", func(by Actor) error {
			_, err := h.eng.RunCheckpoint(context.Background(), "gen", "nginx-up", by)
			return err
		}},
		{"put progress", func(by Actor) error {
			_, err := h.eng.PutProgress("gen", "p", state.Progress{}, by)
			return err
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			// The code matters, not just that it failed. Refusing on
			// the *target* — no such secret, no such checkpoint — means
			// the operation resolved the lab and got that far, which is
			// the defect: the generation was never part of the
			// resolution. Only the instance's own not-found says the
			// lab was never reached.
			err := c.call(attendee(stale))
			if err == nil {
				t.Fatal("an actor entitled to an earlier generation reached this one")
			}
			if got := code(err); got != pdr.CodeInstanceNotFound {
				t.Fatalf("refused with %s, not %s: the operation reached the lab and stopped on its target, so the generation was never checked",
					got, pdr.CodeInstanceNotFound)
			}

			// And its own generation is not refused as a missing lab: a
			// guard that answered not-found to everyone would satisfy
			// the check above and break every instance.
			if err := c.call(attendee(mine)); code(err) == pdr.CodeInstanceNotFound {
				t.Fatalf("the actor's own generation was refused: %v", err)
			}
		})
	}
}
