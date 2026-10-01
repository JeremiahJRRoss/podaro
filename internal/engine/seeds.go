// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jeremiahjrross/podaro/internal/evidence"
	"github.com/jeremiahjrross/podaro/internal/extension"
	"github.com/jeremiahjrross/podaro/internal/lab"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/seed"
	"github.com/jeremiahjrross/podaro/internal/state"
)

func cryptoRead(b []byte) (int, error) { return rand.Read(b) }

// SeedAs admits a seed job (API §7: 202 + job; seeds are idempotent by
// contract, so running one again is always allowed).
func (e *Engine) SeedAs(ctx context.Context, name, seedName string, by Actor) (*state.Job, error) {
	return e.admitFor(name, by.Gen, "seed", seedName, func(lv *labView) error {
		if _, ok := lv.res.Template.Seeds[seedName]; !ok {
			return notFoundKind(pdr.CodeSeedNotFound, "seed", seedName, "podaro lab plan lists the seeds of "+lv.inst.Template)
		}
		return nil
	}, nil)
}

// seedSteps is the seed job.
func (e *Engine) seedSteps(ctx context.Context, job *state.Job) error {
	lv, err := e.jobLab(job)
	if err != nil {
		return err
	}
	e.stage(job, "seeding "+job.Target)
	_, err = e.runSeed(ctx, job, lv, job.Target)
	return err
}

// seedSalt returns the instance's seed salt, making one the first time
// (instances from before this step have none).
func (e *Engine) seedSalt(lv *labView) (string, error) {
	if lv.inst.SeedSalt != "" {
		return lv.inst.SeedSalt, nil
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	salt := hex.EncodeToString(b[:])
	// Onto the row as it stands now, not the view read when the job began:
	// the services have advanced the instance's stage meanwhile, and
	// writing the stale view would take a running lab back to none — which
	// a restart then skips.
	cur, err := e.opts.Store.GetInstance(lv.inst.Name)
	if err != nil {
		return "", storeErr("look up instance "+lv.inst.Name, err)
	}
	cur.SeedSalt = salt
	cur.Updated = time.Now().UTC()
	if err := e.opts.Store.PutInstance(*cur); err != nil {
		return "", storeErr("record the seed salt of "+lv.inst.Name, err)
	}
	lv.inst.SeedSalt, lv.inst.Updated = salt, cur.Updated
	return salt, nil
}

// runSeed runs one named seed — a built-in generator over the instance's
// published ports, or an exec generator (an explicit `generator.exec` or
// a module alias) as a Spec 0002 container — and records the run in
// evidence. A seed that fails is the job's failure with the cause.
func (e *Engine) runSeed(ctx context.Context, job *state.Job, lv *labView, name string) (*evidence.SeedRun, error) {
	s, ok := lv.res.Template.Seeds[name]
	if !ok {
		return nil, notFoundKind(pdr.CodeSeedNotFound, "seed", name, "podaro lab plan lists the seeds")
	}
	salt, err := e.seedSalt(lv)
	if err != nil {
		return nil, err
	}
	value := seed.SeedValue(salt, name)
	run := &evidence.SeedRun{Name: name, Count: s.Count, SeedValue: value}
	// The filter is built before any generator runs: with an unreadable or
	// incomplete secret store the seed is refused (PDR-E412) before it can
	// touch the lab — a built-in generator would otherwise inject and only
	// then be refused, and a retry would inject again.
	// Checkpoints and exec seeds already refuse up front.
	red, rerr := e.redactor(lv.inst.Name)
	if rerr != nil {
		return nil, rerr
	}
	start := time.Now()
	var perr *pdr.Error
	switch {
	case s.Generator.Exec != nil:
		run.Generator, run.Kind, run.Image = "exec", "exec", s.Generator.Exec.Image
		spec := extension.Spec{Image: s.Generator.Exec.Image, Args: s.Generator.Exec.Args, Env: s.Generator.Exec.Env, Secrets: s.Generator.Exec.Secrets, Limits: s.Generator.Exec.Limits}
		perr = e.runExecSeed(ctx, lv, spec, run, s)
	default:
		if registered, _ := seed.BuiltIn(s.Generator.Name); registered {
			run.Generator, run.Kind = s.Generator.Name, "built-in"
			runner := &seed.Runner{Resolver: &instanceTarget{e: e, lv: lv}}
			var rep *seed.Report
			// The events are timestamped from *this run*, not from the
			// instance's creation. What a generator derives from the seed
			// value — which events, which values, in which order — is the
			// payload identity Spec 0002 §5 obliges it to reproduce, and
			// that is unchanged; when they were delivered is not part of
			// it.
			//
			// Anchoring at create looked like the safer reading of §5
			// until a lab asked about the window ending now: a learner who
			// presses a step's seed twenty minutes after creating the lab
			// sent events already outside a fifteen-minute window, so the
			// step's count read a false zero.
			// A step's checkpoint
			// asks about the window ending now, and the seed it presses
			// must land inside it: send, see it red, fix the cause, send
			// again, and the *new* batch is the one the window holds.
			rep, perr = runner.Run(ctx, seed.Run{Instance: lv.inst.Name, Name: name, Generator: s.Generator.Name, Count: s.Count, Params: s.Params, SeedValue: value, Epoch: time.Now().UTC()})
			if rep != nil {
				run.Sent, run.Message = rep.Sent, rep.Message
			}
		} else if owner, ok := lv.res.Composition.Generators[s.Generator.Name]; ok {
			run.Generator, run.Kind, run.Image = s.Generator.Name, "alias", owner.Exec.Image
			spec := extension.Spec{Image: owner.Exec.Image, Args: owner.Exec.Args, Env: owner.Exec.Env, Secrets: owner.Exec.Secrets, Limits: owner.Exec.Limits}
			perr = e.runExecSeed(ctx, lv, spec, run, s)
		} else {
			perr = pdr.New(pdr.CodeAdapterUnavailable, "generator %q of seed %s is neither built-in nor a composed alias", s.Generator.Name, name)
		}
	}
	run.Duration = time.Since(start).Round(time.Millisecond).String()
	run.Message = red.Redact(run.Message)
	// A generator's sent counts are arbitrary JSON (an exec generator
	// shapes them): redacted recursively before the entry is written.
	run.Sent = red.RedactValue(run.Sent)
	if perr != nil {
		pe := *perr
		pe.Message, pe.Cause = red.Redact(pe.Message), red.Redact(pe.Cause)
		run.Error = &pe
	}
	entry := evidence.Entry{Type: evidence.TypeSeed, Instance: lv.inst.Name, Authoring: lv.inst.Mode == state.ModeAuthoring, Job: job.ID, Seed: run}
	stored, err := e.journal(lv.inst.Name).Append(entry)
	if err != nil {
		return nil, storeErr("record evidence of seed "+name, err)
	}
	if perr != nil {
		if err := e.event(job.ID, "seed", name, "failed", run.Error.Code+" "+run.Error.Message+": "+run.Error.Cause); err != nil {
			return nil, err
		}
		pe := *run.Error
		if pe.Evidence == "" {
			pe.Evidence = evidencePath(lv.inst.Name, stored.ID)
		}
		return run, &pe
	}
	if err := e.event(job.ID, "seed", name, "ok", fmt.Sprintf("%s · %s", run.Duration, run.Message)); err != nil {
		return nil, err
	}
	return run, nil
}

// execSeedBudget bounds an exec seed's whole run — the image pull and the
// user resolution as well as the container — so a stalled registry cannot
// hold a job past it.
var execSeedBudget = 5 * time.Minute

// runExecSeed runs a generator container (Spec 0002, kind: seed).
func (e *Engine) runExecSeed(ctx context.Context, lv *labView, spec extension.Spec, run *evidence.SeedRun, s lab.Seed) *pdr.Error {
	// Evidence records the grants the run makes, which is the set a
	// repeated name asks for once (D211): an immutable record claiming
	// two grants where one was made would be a record of something that
	// did not happen. Assigned before the
	// run so a failure carries it too, and taken from the report once the
	// runner has one — the runner is where a grant becomes an object.
	run.Secrets = extension.Grants(spec.Secrets)
	runner, perr := e.extensionRunner(lv)
	if perr != nil {
		return perr
	}
	ctx, cancel := context.WithTimeout(ctx, execSeedBudget)
	defer cancel()
	user, perr := runner.Prepare(ctx, spec.Image)
	if perr != nil {
		return perr
	}
	var b [6]byte
	_, _ = randRead(b[:])
	input := extension.Input{Kind: "seed", RunID: "run_" + hex.EncodeToString(b[:]),
		Instance: extension.Instance{Name: lv.inst.Name, Mode: string(lv.inst.Mode), Endpoints: lv.endpoints()},
		Seed:     &extension.SeedSpec{Name: run.Name, Args: spec.Args, Count: s.Count, Params: s.Params, SeedValue: run.SeedValue}}
	if input.Seed.Args == nil {
		input.Seed.Args = []string{}
	}
	verdict, report, perr := runner.Run(ctx, spec, user, input, execSeedBudget)
	if perr != nil {
		if report != nil && report.Stderr != "" && perr.Cause == "" {
			perr.Cause = excerpt(report.Stderr, 500)
		}
		return perr
	}
	if report != nil {
		run.Secrets = report.Secrets
	}
	run.Sent, run.Message = verdict.Sent, verdict.Message
	return nil
}
