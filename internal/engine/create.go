// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jeremiahjrross/podaro/internal/evidence"
	"github.com/jeremiahjrross/podaro/internal/lab"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/secrets"
	"github.com/jeremiahjrross/podaro/internal/state"
	"github.com/jeremiahjrross/podaro/internal/verify"
)

// The rungs above healthy (plan S6; User Manual §2: ready means baselines
// verified): per service, the one-shot init helper (initialized); then,
// for the instance, endpoints accepting connections (connected), the
// standing seeds (seeded), every checkpoint evaluated with baselines
// gating (verified), and ready. Each rung is journaled and idempotent, so
// a resumed job re-walks it.

// bringUpOrder is the order a job walks the plan's services: name order,
// except that a service another service's init targets comes up first,
// so the init runs against a target that exists (spec 0003 §9.1).
// A cycle among init targets cannot be started
// in any order; validation reports it as init-cycle, and a job that meets
// one anyway refuses rather than guessing.
func bringUpOrder(plan *lab.Plan, res *lab.Result) ([]lab.PlanService, error) {
	byName := make(map[string]lab.PlanService, len(plan.Services))
	names := make([]string, 0, len(plan.Services))
	for _, ps := range plan.Services {
		byName[ps.Name] = ps
		names = append(names, ps.Name)
	}
	var deps map[string]map[string]int
	if res != nil && res.Composition != nil {
		deps = lab.InitDependencies(res.Composition)
	}
	order, err := orderServices(names, deps)
	if err != nil {
		pe := pdr.New(pdr.CodeRuntimeFailed, "the services cannot be brought up in any order: %s", err.Error())
		pe.Cause = "an init request targets a service whose own init targets it back (spec 0003 §9.1)"
		pe.Next = "podaro lab validate names the cycle (init-cycle); change one module's init to target only services that need nothing from it"
		return nil, pe
	}
	out := make([]lab.PlanService, 0, len(order))
	for _, name := range order {
		out = append(out, byName[name])
	}
	return out, nil
}

// orderServices sorts names so that every service listed in deps comes
// after the services its init targets, ties broken by name (Kahn's
// algorithm over a name-sorted frontier). Targets that are not among the
// names are ignored: validation reports those. A cycle is an error naming
// the services that could not be placed.
func orderServices(names []string, deps map[string]map[string]int) ([]string, error) {
	known := make(map[string]bool, len(names))
	for _, n := range names {
		known[n] = true
	}
	indegree := make(map[string]int, len(names))
	dependants := map[string][]string{} // target → services whose init needs it
	for _, n := range names {
		for target := range deps[n] {
			if !known[target] || target == n {
				continue
			}
			indegree[n]++
			dependants[target] = append(dependants[target], n)
		}
	}
	var frontier []string
	for _, n := range names {
		if indegree[n] == 0 {
			frontier = append(frontier, n)
		}
	}
	sort.Strings(frontier)
	order := make([]string, 0, len(names))
	for len(frontier) > 0 {
		n := frontier[0]
		frontier = frontier[1:]
		order = append(order, n)
		freed := false
		for _, d := range dependants[n] {
			indegree[d]--
			if indegree[d] == 0 {
				frontier = append(frontier, d)
				freed = true
			}
		}
		if freed {
			sort.Strings(frontier)
		}
	}
	if len(order) != len(names) {
		var stuck []string
		for _, n := range names {
			if indegree[n] > 0 {
				stuck = append(stuck, n)
			}
		}
		sort.Strings(stuck)
		return nil, fmt.Errorf("init targets form a cycle among %s", strings.Join(stuck, ", "))
	}
	return order, nil
}

// secretsStep generates every declared secret once (an existing value is
// kept: a resumed create keeps the credentials its containers carry).
func (e *Engine) secretsStep(job *state.Job, lv *labView) (map[string]string, error) {
	store := e.secretStore(lv.inst.Name)
	var made []string
	for _, s := range lv.plan.Secrets {
		created, err := store.Ensure(s.Name, s.Kind)
		if err != nil {
			if jerr := e.event(job.ID, "secrets", "", "failed", err.Error()); jerr != nil {
				return nil, jerr
			}
			var ke *secrets.KindError
			if errors.As(err, &ke) {
				pe := pdr.New(pdr.CodeRuntimeFailed, "secret %s changed kind: %s", s.Name, err.Error())
				pe.Cause = "values are kept across resets by design (spec 0003 §6), so the kind on record is what the containers were configured with"
				pe.Next = "restore the declaration to " + ke.Generated + ", or podaro destroy " + lv.inst.Name + " and up again to generate the secret afresh"
				return nil, pe
			}
			pe := pdr.New(pdr.CodeRuntimeFailed, "cannot generate secret %s", s.Name)
			pe.Cause = err.Error()
			pe.Next = "check the state directory's permissions, then re-run"
			return nil, pe
		}
		if created {
			made = append(made, s.Name)
		}
		// The name joins the instance's history of generated secrets —
		// append-only in the state database until destroy — so the
		// redaction filter must hold its value from here on, whatever a
		// later authoring edit declares (expectedSecrets).
		if err := e.opts.Store.AddGeneratedSecrets(lv.inst.Name, []string{s.Name}); err != nil {
			return nil, storeErr("record the generated secret "+s.Name+" of "+lv.inst.Name, err)
		}
	}
	values, err := store.Values()
	if err != nil {
		return nil, storeErr("read the secrets of "+lv.inst.Name, err)
	}
	detail := "none declared"
	if len(lv.plan.Secrets) > 0 {
		detail = fmt.Sprintf("%d declared", len(lv.plan.Secrets))
		if len(made) > 0 {
			detail += " · generated " + strings.Join(made, ", ")
		} else {
			detail += " · all present"
		}
	}
	if err := e.event(job.ID, "secrets", "", "ok", detail); err != nil {
		return nil, err
	}
	if len(made) > 0 {
		if err := e.lifecycle(lv, job.ID, "secrets", "", "generated "+strings.Join(made, ", ")+" (values in the secret store only)"); err != nil {
			return nil, err
		}
	}
	return values, nil
}

// lifecycle appends a lifecycle evidence entry; a journal the store
// refuses is logged, not fatal — the job's own journal is the truth. A
// detail the redaction filter cannot be built for is another matter: it
// is not written, and the step fails (PDR-E412, round 21).
func (e *Engine) lifecycle(lv *labView, job, event, stage, detail string) error {
	red, perr := e.redactor(lv.inst.Name)
	if perr != nil {
		return perr
	}
	entry := evidence.Entry{Type: evidence.TypeLifecycle, Instance: lv.inst.Name, Authoring: lv.inst.Mode == state.ModeAuthoring, Job: job,
		Lifecycle: &evidence.Lifecycle{Event: event, Stage: stage, Detail: red.Redact(detail)}}
	if _, err := e.journal(lv.inst.Name).Append(entry); err != nil {
		e.opts.Logf("%s: evidence: %v", lv.inst.Name, err)
	}
	return nil
}

// warning appends a lifecycle warning (PDR-W101) to evidence.
func (e *Engine) warning(lv *labView, job, code, detail string) {
	entry := evidence.Entry{Type: evidence.TypeLifecycle, Instance: lv.inst.Name, Authoring: lv.inst.Mode == state.ModeAuthoring, Job: job,
		Lifecycle: &evidence.Lifecycle{Event: "warning", Code: code, Detail: detail}}
	if _, err := e.journal(lv.inst.Name).Append(entry); err != nil {
		e.opts.Logf("%s: evidence: %v", lv.inst.Name, err)
	}
}

// initStep runs a service's init helper once its container is healthy:
// the requests rendered with the instance's secrets, executed by the
// module's pinned helper image on the internal network. No init declared
// is a skipped rung; a helper that fails is the service's failure, its
// redaction-filtered output attached.
func (e *Engine) initStep(ctx context.Context, job *state.Job, lv *labView, ps lab.PlanService, svc *state.Service, values map[string]string) error {
	if svc.Stage.Rank() >= state.StageInitialized.Rank() {
		return nil // recorded on this container run by a job this one resumes
	}
	if svc.Stage.Rank() < state.StageHealthy.Rank() {
		// Never healthy (no readiness declared: the ladder honestly stops
		// at alive for it, plan S4) — nothing above alive is claimed, not
		// even a skipped init.
		return nil
	}
	init := lab.InitOf(lv.res, ps.Name)
	if init == nil {
		if err := e.event(job.ID, "init", ps.Name, "skipped", "no init declared"); err != nil {
			return err
		}
		return e.setStage(svc, state.StageInitialized)
	}
	e.stage(job, "initializing "+ps.Name)
	program, err := renderInitProgram(lv, ps.Name, init, values)
	if err != nil {
		if jerr := e.event(job.ID, "init", ps.Name, "failed", err.Error()); jerr != nil {
			return jerr
		}
		pe := pdr.New(pdr.CodeRuntimeFailed, "init of %s cannot be rendered", ps.Name)
		pe.Cause = err.Error()
		pe.Next = "fix the module's init block (spec 0003 §9.1), then re-run"
		return pe
	}
	files, err := renderInitFiles(program)
	if err != nil {
		return runtimeErr("render init of "+ps.Name, err)
	}
	image := init.Image.Ref()
	if err := e.opts.Runtime.Pull(ctx, image); err != nil {
		if jerr := e.event(job.ID, "init", ps.Name, "failed", "pull "+image+": "+err.Error()); jerr != nil {
			return jerr
		}
		return runtimeErr("pull init helper "+image, err)
	}
	timeout := initTimeout(program)
	helper := initHelperName(lv.inst.Name, ps.Name)
	// The helper's name is the same on every attempt, so an engine stopped
	// between podman create and the cleanup leaves a container under it:
	// an owned leftover is removed before the name is used again, and a
	// stranger under the name is refused, never removed.
	// Only this very helper is a leftover: the run label
	// must name it and no service label may be present — a service
	// container is never removed by the init step (round 39).
	if st, ierr := e.opts.Runtime.Inspect(ctx, helper); ierr == nil && st != nil {
		if st.Labels[runtime.LabelManaged] != "true" || st.Labels[runtime.LabelInstance] != lv.inst.Name || st.Labels[runtime.LabelRun] != "init-"+ps.Name || st.Labels[runtime.LabelService] != "" {
			if jerr := e.event(job.ID, "init", ps.Name, "failed", "the helper's name "+helper+" is held by a container Podaro does not own"); jerr != nil {
				return jerr
			}
			return runtimeErr("init helper "+helper, errors.New("a container Podaro does not own holds the name; remove or rename it"))
		}
		e.opts.Logf("%s: init %s: removing a stale helper left by an interrupted run", lv.inst.Name, ps.Name)
		// By the id the inspection saw, never by the name: a container
		// that took the name meanwhile is not the one inspected, and
		// stands — the run's create then refuses the name in use.
		if rerr := e.opts.Runtime.Remove(ctx, st.ID); rerr != nil {
			return runtimeErr("remove stale init helper "+helper, rerr)
		}
	}
	e.opts.Logf("%s: init %s: %d requests via %s (timeout %s)", lv.inst.Name, ps.Name, len(program.Requests), image, timeout)
	res, err := e.opts.Runtime.Run(ctx, runtime.RunSpec{
		Name: helper, Image: image, Network: internalNetworkName(lv.inst.Name),
		Labels:     map[string]string{runtime.LabelInstance: lv.inst.Name, runtime.LabelManaged: "true", runtime.LabelRun: "init-" + ps.Name},
		Entrypoint: initEntrypoint(), Command: initCommand(), Files: files, Timeout: timeout, MaxStderr: runtime.DefaultMaxStderr,
	})
	if err != nil {
		if jerr := e.event(job.ID, "init", ps.Name, "failed", err.Error()); jerr != nil {
			return jerr
		}
		return runtimeErr("run init helper of "+ps.Name, err)
	}
	red, perr := e.redactor(lv.inst.Name)
	if perr != nil {
		return perr // the helper's output is not journaled unfiltered (PDR-E412)
	}
	// A stream the cap cut first loses the trailing fragment of a value it
	// may hold — a rendered path or header echoed by the helper, cut in
	// two — before the filter runs, as an exec run's streams do.
	stdout, stderr := res.Stdout, res.Stderr
	if res.StdoutTruncated {
		stdout = red.TrimPartial(stdout)
	}
	if res.StderrTruncated {
		stderr = red.TrimPartial(stderr)
	}
	out := red.Redact(strings.TrimSpace(string(stdout)))
	errOut := red.Redact(strings.TrimSpace(string(stderr)))
	if res.TimedOut || res.ExitCode != 0 {
		detail := fmt.Sprintf("exit %d", res.ExitCode)
		if res.TimedOut {
			detail = "timed out after " + timeout.String()
		}
		if errOut != "" {
			detail += ": " + firstLine(errOut)
		}
		if jerr := e.event(job.ID, "init", ps.Name, "failed", detail); jerr != nil {
			return jerr
		}
		if err := e.lifecycle(lv, job.ID, "init", "", ps.Name+" failed · "+detail+"\n"+out+"\n"+errOut); err != nil {
			return err
		}
		pe := pdr.New(pdr.CodeRuntimeFailed, "init of %s failed: %s", ps.Name, detail)
		pe.Cause = excerpt(out+"\n"+errOut, 500)
		pe.Next = fmt.Sprintf("podaro logs %s %s · fix the module's init requests · podaro up again to resume", lv.inst.Name, ps.Name)
		return pe
	}
	if err := e.event(job.ID, "init", ps.Name, "ok", fmt.Sprintf("%d requests in %s", len(program.Requests), res.Finished.Sub(res.Started).Round(time.Millisecond))); err != nil {
		return err
	}
	if err := e.lifecycle(lv, job.ID, "init", string(state.StageInitialized), ps.Name+"\n"+out); err != nil {
		return err
	}
	return e.setStage(svc, state.StageInitialized)
}

// initHelperName names a service's init helper container. The underscore
// keeps it apart from every service container: instance and service names
// are DNS labels, which carry no underscore, so pdr-<instance>-<service>
// can never spell it — a service named init-web is not web's helper.
func initHelperName(instance, service string) string {
	return fmt.Sprintf("pdr-%s-init_%s", instance, service)
}

// setStage records a service's rung and refreshes the instance's.
func (e *Engine) setStage(svc *state.Service, stage state.Stage) error {
	svc.Stage = stage
	if err := e.putService(svc); err != nil {
		return storeErr("record "+string(stage)+" "+svc.Name, err)
	}
	return e.refreshInstanceStage(svc.Instance)
}

// connectStep proves every service's declared endpoints accept
// connections (the connected rung) — polled within a budget, since a
// product may bind its API port after its readiness page answers.
func (e *Engine) connectStep(ctx context.Context, job *state.Job, lv *labView) error {
	services, err := e.opts.Store.ListServices(lv.inst.Name)
	if err != nil {
		return storeErr("list services of "+lv.inst.Name, err)
	}
	for i := range services {
		svc := &services[i]
		if svc.Stage.Rank() >= state.StageConnected.Rank() {
			continue
		}
		if svc.Stage.Rank() < state.StageInitialized.Rank() {
			// Never healthy (no readiness declared: the ladder honestly
			// stops at alive for it, plan S4) — nothing above is claimed.
			continue
		}
		e.stage(job, "connecting "+svc.Name)
		endpoints := lab.EndpointsOf(lv.res, svc.Name)
		if err := e.connected(ctx, svc, endpoints); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if jerr := e.event(job.ID, "connected", svc.Name, "failed", err.Error()); jerr != nil {
				return jerr
			}
			pe := pdr.New(pdr.CodeRuntimeFailed, "%s is not reachable on its endpoints", svc.Name)
			pe.Cause = err.Error()
			pe.Next = fmt.Sprintf("podaro logs %s %s · podaro up again to resume", lv.inst.Name, svc.Name)
			return pe
		}
		var eps []string
		for _, ep := range endpoints {
			eps = append(eps, fmt.Sprintf("%s :%d", ep.Purpose, ep.Port))
		}
		detail := strings.Join(eps, ", ")
		if detail == "" {
			detail = "no endpoints declared"
		}
		if err := e.event(job.ID, "connected", svc.Name, "ok", detail); err != nil {
			return err
		}
		if err := e.setStage(svc, state.StageConnected); err != nil {
			return err
		}
	}
	return nil
}

// seedStep runs the standing seeds — the ones no playbook step invokes —
// and marks every service seeded. Seeds a step names are the learner's
// act and run when pressed (spec 0001 §1: running them here would turn an
// objective green at create).
func (e *Engine) seedStep(ctx context.Context, job *state.Job, lv *labView) error {
	if lv.reconcile && !lv.recreated && lv.inst.Stage.Rank() >= state.StageSeeded.Rank() && len(lv.standing) > 0 {
		// Every container restarted with its data and the lab had been
		// seeded: what the standing seeds injected is still there, and
		// injecting it twice would double it (User Manual §8: a reconcile
		// re-verifies, it does not re-seed). A resumed create that had not
		// reached seeded seeds now.
		if err := e.event(job.ID, "seeded", "", "skipped", "reconcile: containers restarted with their data; standing seeds not re-run: "+strings.Join(lv.standing, ", ")); err != nil {
			return err
		}
		return e.markAll(lv.inst.Name, state.StageSeeded)
	}
	for _, name := range lv.standing {
		e.stage(job, "seeding "+name)
		if _, err := e.runSeed(ctx, job, lv, name); err != nil {
			return err
		}
	}
	detail := "no standing seeds"
	if len(lv.standing) > 0 {
		detail = strings.Join(lv.standing, ", ")
	}
	if len(lv.actions) > 0 {
		detail += " · step actions run when pressed: " + strings.Join(lv.actions, ", ")
	}
	if err := e.event(job.ID, "seeded", "", "ok", detail); err != nil {
		return err
	}
	return e.markAll(lv.inst.Name, state.StageSeeded)
}

// markAll records an instance-level rung on every service that reached
// healthy and stands below it. A service that never became healthy (no
// readiness declared) keeps alive, and with it the instance: the ladder
// is only as high as its slowest rung, and nothing is claimed for a
// service that could not prove it (UX §5).
func (e *Engine) markAll(instance string, stage state.Stage) error {
	services, err := e.opts.Store.ListServices(instance)
	if err != nil {
		return storeErr("list services of "+instance, err)
	}
	for i := range services {
		svc := &services[i]
		if svc.Stage.Rank() < state.StageHealthy.Rank() || svc.Stage.Rank() >= stage.Rank() {
			continue
		}
		svc.Stage = stage
		if err := e.putService(svc); err != nil {
			return storeErr("record "+string(stage)+" "+svc.Name, err)
		}
	}
	return e.refreshInstanceStage(instance)
}

// demoteAll lowers every service standing above a rung back to it — the
// regression path (UX §5: a verify that finds a gate baseline red says so
// by moving the ladder back to seeded). Services below the rung are left
// where they are.
func (e *Engine) demoteAll(instance string, stage state.Stage) error {
	services, err := e.opts.Store.ListServices(instance)
	if err != nil {
		return storeErr("list services of "+instance, err)
	}
	for i := range services {
		svc := &services[i]
		if svc.Stage.Rank() <= stage.Rank() {
			continue
		}
		svc.Stage = stage
		if err := e.putService(svc); err != nil {
			return storeErr("record "+string(stage)+" "+svc.Name, err)
		}
	}
	return e.refreshInstanceStage(instance)
}

// verifyStep is create's evaluation of every checkpoint (spec 0001 §1):
// baselines gate verified and ready — a gate baseline that fails ends the
// job with PDR-E411 and the ladder at seeded; a warn baseline that fails
// is journaled and ready is still reached; objectives are recorded as
// the expected-red start, evaluated once (no retries: red is expected),
// and one that passes raises PDR-W101.
func (e *Engine) verifyStep(ctx context.Context, job *state.Job, lv *labView) error {
	e.stage(job, "verifying")
	// A reconcile re-verifies the baselines (User Manual §8) and leaves the
	// objectives — the learner's work, judged when the learner acts — as
	// they stand; a create judges everything once. A reconcile that
	// recreated a container judges the objectives once too: the data the
	// old container held is gone, so a verdict earned inside it no longer
	// describes the lab.
	var keep func(lab.FlatCheckpoint) bool
	if lv.reconcile && !lv.recreated {
		keep = baselinesOnly
	}
	// A reconcile says what it re-verified, in evidence and on the
	// ladder (plan S9; Manual §8 promises that baselines re-verify after
	// a reboot). An operator who comes back to a host that restarted
	// must be able to see that the lab was proven again rather than
	// merely found running, and which half of the board that proof
	// covers — otherwise "ready" after a reboot is a claim with no
	// record behind it.
	//
	// The two are written at different moments on purpose. The feed frame
	// is a commentary and says the re-verification is under way; the
	// journal entry is the *proof* that it happened, and evidence is
	// immutable — so it is appended once the evaluation has returned.
	// Written before, it claimed a verification that an error, a
	// cancellation or a kill would have left undone, which is the
	// opposite of what the entry is for.
	var reconciled string
	if lv.reconcile {
		reconciled = "baselines re-verified; the objectives keep their verdicts — they are the learner's work"
		if lv.recreated {
			reconciled = "baselines and objectives both re-judged: a container was recreated, so the data a verdict was earned in is gone"
		}
		if err := e.event(job.ID, "verifying", "", "ok", "reconcile: "+reconciled); err != nil {
			return err
		}
	}
	results, err := e.evaluateAll(ctx, job, lv, keep, true)
	if err != nil {
		return err
	}
	if reconciled != "" {
		if err := e.lifecycle(lv, job.ID, "reconcile", string(lv.inst.Stage), reconciled); err != nil {
			return err
		}
	}
	var gateFailed, warnFailed, greenObjectives []string
	for _, r := range results {
		cp, _ := lv.checkpoint(r.ID)
		switch cp.ResolvedClass {
		case "baseline":
			if r.Status == verify.StatusPass {
				continue
			}
			switch cp.Severity() {
			case "gate":
				gateFailed = append(gateFailed, r.ID)
			case "warn":
				warnFailed = append(warnFailed, r.ID)
			}
		case "objective":
			// PDR-W101 is a create's warning — "passed at create": an
			// objective green under a reconcile (one that recreated a
			// container re-judges them) was earned, or is red; never warned.
			if r.Status == verify.StatusPass && !lv.reconcile {
				greenObjectives = append(greenObjectives, r.ID)
			}
		}
	}
	for _, id := range greenObjectives {
		detail := fmt.Sprintf("objective %s passed at create — it verifies something the template already makes true (spec 0001 §1)", id)
		if err := e.event(job.ID, "checkpoint", id, "warn", pdr.CodeObjectiveGreenAtCreate+" "+detail); err != nil {
			return err
		}
		e.warning(lv, job.ID, pdr.CodeObjectiveGreenAtCreate, detail)
	}
	// The summary counts every row as it stands (a reconcile judged the
	// baselines only; the objectives keep their verdicts).
	all, err := e.opts.Store.ListCheckpointResults(lv.inst.Name)
	if err != nil {
		return storeErr("list checkpoint results of "+lv.inst.Name, err)
	}
	t := tally(lv.currentResults(all))
	summary := fmt.Sprintf("baseline %d/%d · objectives %d/%d", t.Baseline.Passed, t.Baseline.Total, t.Objective.Passed, t.Objective.Total)
	if lv.reconcile {
		// The counts are the same shape either way; the prefix is what
		// tells a reader which run produced them.
		summary = "reconciled · " + summary
	}
	if len(gateFailed) > 0 {
		if err := e.event(job.ID, "verified", "", "failed", summary+" · gate baselines failed: "+strings.Join(gateFailed, ", ")); err != nil {
			return err
		}
		if err := e.lifecycle(lv, job.ID, "verify", string(state.StageSeeded), summary+" · not ready: "+strings.Join(gateFailed, ", ")); err != nil {
			return err
		}
		pe := pdr.New(pdr.CodeBaselineFailed, "%s did not reach ready: baseline %s failed", lv.inst.Name, joinIDs(gateFailed))
		pe.Cause = summary + " — the containers run; the ladder stops at seeded"
		pe.Evidence = evidencePath(lv.inst.Name, "")
		pe.Next = fmt.Sprintf("podaro verify %s once the product settles · podaro logs %s <service> · podaro up again to resume", lv.inst.Name, lv.inst.Name)
		return pe
	}
	if len(warnFailed) > 0 {
		if err := e.event(job.ID, "verified", "", "warn", summary+" · warn baselines failed: "+strings.Join(warnFailed, ", ")); err != nil {
			return err
		}
	} else if err := e.event(job.ID, "verified", "", "ok", summary); err != nil {
		return err
	}
	if err := e.markAll(lv.inst.Name, state.StageVerified); err != nil {
		return err
	}
	if err := e.event(job.ID, "ready", "", "ok", summary); err != nil {
		return err
	}
	if err := e.lifecycle(lv, job.ID, "ready", string(state.StageReady), summary); err != nil {
		return err
	}
	return e.markAll(lv.inst.Name, state.StageReady)
}

func joinIDs(ids []string) string {
	if len(ids) == 1 {
		return ids[0]
	}
	return strings.Join(ids, ", ")
}

// evidencePath is the API §10 pointer of an instance's journal, or one
// entry of it.
func evidencePath(instance, id string) string {
	p := "/api/v1alpha1/instances/" + instance + "/evidence"
	if id != "" {
		p += "/" + id
	}
	return p
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func excerpt(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// writeEnvFile renders a service's environment to its 0600 file under the
// instance, rewritten on every attempt.
func (e *Engine) writeEnvFile(instance, service string, rc *renderedConfig) (string, error) {
	if len(rc.Env) == 0 {
		return "", nil
	}
	content, err := rc.envFile()
	if err != nil {
		return "", err
	}
	dir := e.envDir(instance)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	envFile := filepath.Join(dir, service+".env")
	if err := os.WriteFile(envFile, []byte(content), 0o600); err != nil {
		return "", err
	}
	_ = os.Chmod(envFile, 0o600)
	return envFile, nil
}

// secretValues loads an instance's secret values for rendering.
func (e *Engine) secretValues(instance string) (map[string]string, error) {
	values, err := e.secretStore(instance).Values()
	if err != nil {
		return nil, storeErr("read the secrets of "+instance, err)
	}
	return values, nil
}
