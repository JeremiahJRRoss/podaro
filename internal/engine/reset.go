// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jeremiahjrross/podaro/internal/state"
)

// ResetPlan is the impact preview (API §7; UX §6's two-column dialog):
// what a reset destroys and what survives it.
type ResetPlan struct {
	Destroyed []string `json:"destroyed"`
	Survives  []string `json:"survives"`
}

// ResetPlanFor computes the preview for an instance. Full scope in this
// release (User Manual §8): every container and the data inside it go;
// objective results and playbook progress are cleared; the instance,
// its hostnames, its secrets (credentials stay valid), its networks,
// and its evidence survive.
func (e *Engine) ResetPlanFor(name string) (*ResetPlan, error) {
	lv, err := e.instanceView(name)
	if err != nil {
		return nil, err
	}
	p := &ResetPlan{}
	for _, ps := range lv.plan.Services {
		p.Destroyed = append(p.Destroyed, fmt.Sprintf("container %s and the data inside it", ps.Name))
	}
	objectives := 0
	for _, cp := range lv.checkpoints {
		if cp.ResolvedClass == "objective" {
			objectives++
		}
	}
	p.Destroyed = append(p.Destroyed, fmt.Sprintf("objective progress: %d objective checkpoint(s) return to red, playbook positions clear", objectives))
	for _, name := range lv.actions {
		p.Destroyed = append(p.Destroyed, "data sent by seed "+name+" (a step action; press it again)")
	}
	p.Survives = append(p.Survives, "instance "+lv.inst.Name+" and its hostnames", "secrets (credentials stay the same)", "networks and routes", "evidence (immutable; the history stays)")
	if len(lv.standing) > 0 {
		p.Survives = append(p.Survives, "standing seeds re-run: "+strings.Join(lv.standing, ", "))
	}
	p.Survives = append(p.Survives, "baselines re-verified before the instance is ready again")
	return p, nil
}

// ResetAs admits a reset job (API §7: 202 + job that ends by re-running
// seeds and checkpoints — reset is not done until the instance is
// verified again). Audited before the job exists (API §2.5).
func (e *Engine) ResetAs(ctx context.Context, name string, by Actor) (*state.Job, error) {
	return e.admit(name, "reset", "", nil, &state.Audit{Instance: name, Action: "reset", Actor: by.Subject, Mechanism: by.Mechanism, Detail: "instance " + name})
}

// resetSteps takes the containers down (routes withdrawn first,
// ownership checked), clears objective results and progress, records the
// reset in evidence, then walks the create path again: containers,
// init, standing seeds, verify.
func (e *Engine) resetSteps(ctx context.Context, job *state.Job) error {
	lv, err := e.jobLab(job)
	if err != nil {
		return err
	}
	services, err := e.opts.Store.ListServices(lv.inst.Name)
	if err != nil {
		return storeErr("list services of "+lv.inst.Name, err)
	}
	// Once the first route is withdrawn or the first container removed,
	// the lab no longer runs as its rows say — so no failure after that
	// point may return leaving the instance claiming `ready` with its old
	// green results, which is what a reader would otherwise see for
	// containers that are gone. torn says
	// destructive work has begun; failed() demotes before returning.
	torn := false
	var inFlight *state.Service
	// removed says the in-flight service's container is already gone, so
	// a demotion records `none` rather than `alive`: a row claiming a
	// running container the runtime no longer has is worse than the stale
	// row it replaces, and the stage recompute would read it as a live
	// rung.
	removed := false
	failed := func(err error) error {
		if !torn {
			return err
		}
		// The service whose route this job withdrew no longer serves,
		// whatever became of its container: its row must say so, or the
		// stage recompute below reads the rows it left behind and lands
		// back on ready. A container that is still there is `alive`; it
		// is simply no longer proven healthy or routed.
		if inFlight != nil {
			if removed {
				// The container is gone; the record of that is what
				// failed, so the demotion is that record, retried.
				inFlight.Stage, inFlight.ContainerID, inFlight.StartedAt, inFlight.HealthyAt, inFlight.RanImage, inFlight.RanModule, inFlight.Readiness, inFlight.Ports, inFlight.Error = state.StageNone, "", nil, nil, "", "", "", nil, ""
			} else {
				inFlight.Stage, inFlight.HealthyAt, inFlight.Readiness, inFlight.Ports = state.StageAlive, nil, "", nil
			}
			if perr := e.putService(inFlight); perr != nil {
				e.opts.Logf("%s: the reset failed and %s could not be demoted: %v", lv.inst.Name, inFlight.Name, perr)
			}
		}
		if derr := e.clearForReset(lv); derr != nil {
			// The demotion is best-effort by necessity — the reset is
			// already failing — but it is never silent.
			e.opts.Logf("%s: the reset failed and the instance could not be demoted: %v", lv.inst.Name, derr)
		}
		return err
	}
	for i := range services {
		svc := &services[i]
		if svc.Stage == state.StageNone && svc.ContainerID == "" {
			continue // already taken down by this job before an interruption
		}
		e.stage(job, "removing "+svc.Name)
		inFlight, removed = svc, false
		if err := e.withdrawRoute(svc); err != nil {
			return failed(err)
		}
		torn = true // the route is gone whether or not the rest succeeds
		if err := e.removeOwnedContainer(ctx, lv.inst.Name, *svc); err != nil {
			if jerr := e.event(job.ID, "remove", svc.Name, "failed", err.Error()); jerr != nil {
				return failed(jerr)
			}
			return failed(err)
		}
		removed = true
		svc.Stage, svc.ContainerID, svc.StartedAt, svc.HealthyAt, svc.RanImage, svc.RanModule, svc.Readiness, svc.Error = state.StageNone, "", nil, nil, "", "", "", ""
		if err := e.putService(svc); err != nil {
			return failed(storeErr("record removal of "+svc.Name, err))
		}
		if err := e.event(job.ID, "remove", svc.Name, "ok", "reset"); err != nil {
			return failed(err)
		}
		inFlight = nil // this one is down and recorded; nothing to demote
	}
	// Every latest result goes: the objectives' because the learner's work
	// is undone with the containers (User Manual §8), the baselines' because
	// what they proved no longer runs — the tally reads 0/n until the
	// re-create re-verifies, never a stale green over a lab being rebuilt.
	// Evidence keeps every run (invariant: immutable).
	e.stage(job, "clearing results and objective progress")
	// Under the instance guard (guard.go): a checkpoint record or a
	// progress write in flight lands before the clearing or after it —
	// never between its read and its write.
	// Everything from here to the stage refresh runs after the lab is
	// down, so every one of these returns is a post-teardown failure and
	// goes through failed(): a store that refuses the clearing, or an
	// evidence write that fails, must not leave the instance row saying
	// `ready` over service rows that say `none`.
	var t Tally
	if err := e.clearForResetTally(lv, &t); err != nil {
		return failed(err)
	}
	if err := e.event(job.ID, "progress", "", "ok", fmt.Sprintf("results cleared: %d baseline · %d objective (re-verified below); playbook progress cleared; evidence kept", t.Baseline.Total, t.Objective.Total)); err != nil {
		return failed(err)
	}
	if err := e.lifecycle(lv, job.ID, "reset", "", "containers removed; results and objective progress cleared; re-creating to a verified baseline"); err != nil {
		return failed(err)
	}
	if err := e.refreshInstanceStage(lv.inst.Name); err != nil {
		return failed(err)
	}
	// The instance is at the bottom of the ladder now; the create path
	// takes it back up and re-verifies before it is ready again.
	lv.inst.Updated = time.Now().UTC()
	return e.createSteps(ctx, job)
}

// clearForResetTally turns the generation and clears what a reset clears:
// every latest checkpoint result and all playbook progress. Evidence is
// untouched — it is immutable — and the tally the caller reports is read
// inside the same locked section, so it describes exactly what was
// cleared.
//
// Under the instance guard (guard.go): a checkpoint record or a progress
// write in flight lands before the clearing or after it, never between
// its read and its write.
func (e *Engine) clearForResetTally(lv *labView, out *Tally) error {
	lock := e.instanceLock(lv.inst.Name)
	lock.Lock()
	defer lock.Unlock()
	results, err := e.opts.Store.ListCheckpointResults(lv.inst.Name)
	if err != nil {
		return storeErr("list checkpoint results of "+lv.inst.Name, err)
	}
	if out != nil {
		*out = tally(results)
	}
	// The generation turns here: what took its ticket before this one is
	// pre-reset, and stays in evidence only if it records after.
	e.markReset(lv.inst.Name, e.evalTicket())
	if err := e.opts.Store.DeleteCheckpointResults(lv.inst.Name, ""); err != nil {
		return storeErr("clear checkpoint results of "+lv.inst.Name, err)
	}
	if err := e.opts.Store.DeleteProgress(lv.inst.Name); err != nil {
		return storeErr("clear playbook progress of "+lv.inst.Name, err)
	}
	return nil
}

// clearForReset is the failure path's demotion: the same clearing, plus
// the stage refresh, so an instance whose teardown began but did not
// finish reads as what it is — not ready, nothing proven — rather than
// keeping a ready ladder and green results for containers that are gone.
// The two halves are independent on purpose: a store that refuses to
// list or delete the results must not also cost the stage refresh, or
// the instance row keeps `ready` over service rows that no longer run.
// Both are attempted, and the first
// error is returned once both have been.
func (e *Engine) clearForReset(lv *labView) error {
	clearErr := e.clearForResetTally(lv, nil)
	stageErr := e.refreshInstanceStage(lv.inst.Name)
	if clearErr != nil {
		return clearErr
	}
	return stageErr
}
