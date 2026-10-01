// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jeremiahjrross/podaro/internal/evidence"
	"github.com/jeremiahjrross/podaro/internal/extension"
	"github.com/jeremiahjrross/podaro/internal/lab"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
	"github.com/jeremiahjrross/podaro/internal/verify"
)

// evaluateConcurrency bounds how many checkpoints run at once.
const evaluateConcurrency = 4

// evaluator wires the checkpoint engine for one instance: adapters reach
// the lab through its published ports; exec checkpoints run through the
// extension runner on the internal network.
func (e *Engine) evaluator(lv *labView) *verify.Evaluator {
	target := &instanceTarget{e: e, lv: lv}
	ev := verify.New(target, e.execHook(lv))
	return ev
}

// extensionRunner builds the Spec 0002 runner for an instance — or
// refuses, when the redaction filter its output passes through cannot be
// built (PDR-E412).
func (e *Engine) extensionRunner(lv *labView) (*extension.Runner, *pdr.Error) {
	red, perr := e.redactor(lv.inst.Name)
	if perr != nil {
		return nil, perr
	}
	return &extension.Runner{
		Runtime: e.opts.Runtime, Instance: lv.inst.Name, Network: internalNetworkName(lv.inst.Name),
		Labels:  map[string]string{runtime.LabelTemplate: lv.inst.Template},
		Secrets: e.secretStore(lv.inst.Name), Redactor: red, EnvDir: e.envDir(lv.inst.Name),
		Logf: e.opts.Logf,
	}, nil
}

// endpoints lists the instance's declared endpoints for an extension.
func (lv *labView) endpoints() []extension.Endpoint {
	var out []extension.Endpoint
	for _, ps := range lv.plan.Services {
		for _, ep := range ps.Endpoints {
			out = append(out, extension.Endpoint{Service: ps.Name, Purpose: ep.Purpose, Scheme: ep.Scheme, Host: ps.Name, Port: ep.Port})
		}
	}
	return out
}

// execHook judges an exec checkpoint — or a module alias, which validate
// resolved to exec — through the runner. An alias runs exactly what its
// module declared (spec 0003 §10: sugar for adapter: exec with the
// declared image); a checkpoint's open params are an exec spec only under
// adapter: exec, so no alias param can select another image.
func (e *Engine) execHook(lv *labView) verify.ExecFunc {
	return func(ctx context.Context, cp lab.FlatCheckpoint, timeout time.Duration) verify.Result {
		var spec extension.Spec
		switch {
		case cp.Exec != nil:
			spec = extension.Spec{Image: cp.Exec.Image, Args: cp.Exec.Args, Env: cp.Exec.Env, Secrets: cp.Exec.Secrets, Limits: cp.Exec.Limits}
		case cp.Adapter == "exec":
			// Read and refused before anything is pulled or run: a key the
			// spec does not carry would otherwise be skipped and the
			// extension run without its authored configuration.
			s, err := extension.SpecFromParams(cp.Params)
			if err != nil {
				pe := pdr.New(pdr.CodeCheckpointError, "exec checkpoint %s: %v", cp.ID, err)
				pe.Cause = "the exec adapter reads params image, args, env, secrets and limits (spec 0001 §3, Spec 0002 §2); a parameter it does not read would be skipped, and the extension pulled and run without it"
				pe.Next = "fix the checkpoint's params"
				return verify.Result{Status: verify.StatusError, Error: pe, Message: pe.Message}
			}
			spec = s
		}
		if spec.Image == "" {
			return verify.Result{Status: verify.StatusError, Error: pdr.New(pdr.CodeCheckpointError, "exec checkpoint %s names no image", cp.ID)}
		}
		runner, perr := e.extensionRunner(lv)
		if perr != nil {
			return verify.Result{Status: verify.StatusError, Error: perr, Message: perr.Message}
		}
		// What evidence keeps about an exec run is known before the run:
		// the image the checkpoint named and the grants it asked for
		// (Spec 0002 §2). A pull that fails, or an image that would run
		// as root, is still an attempt made under those two facts, and an
		// entry that omits them says less about the failure than the
		// checkpoint already knew. The
		// grants are the set, as everywhere else (D211).
		capture := func() map[string]any {
			return map[string]any{"image": spec.Image, "secrets": granted(extension.Grants(spec.Secrets))}
		}
		user, perr := runner.Prepare(ctx, spec.Image)
		if perr != nil {
			return verify.Result{Status: verify.StatusError, Error: perr, Message: perr.Message, Capture: capture()}
		}
		var b [6]byte
		_, _ = randRead(b[:])
		input := extension.Input{Kind: "checkpoint", RunID: "run_" + fmt.Sprintf("%x", b),
			Instance:   extension.Instance{Name: lv.inst.Name, Mode: string(lv.inst.Mode), Endpoints: lv.endpoints()},
			Checkpoint: &extension.CheckpointSpec{ID: cp.ID, Args: spec.Args, Env: spec.Env, Expect: cp.Expect}}
		if input.Checkpoint.Args == nil {
			input.Checkpoint.Args = []string{}
		}
		verdict, report, perr := runner.Run(ctx, spec, user, input, timeout)
		if perr != nil {
			res := verify.Result{Status: verify.StatusError, Error: perr, Message: perr.Message}
			res.Capture = capture()
			if report != nil {
				res.Capture["exit_code"] = report.ExitCode
				res.Capture["secrets"] = granted(report.Secrets)
				if report.Stderr != "" {
					res.Capture["stderr"] = report.Stderr
				}
			}
			return res
		}
		res := verify.Result{Status: verdict.Status, Observed: verdict.Observed, Expected: cp.Expect, Message: verdict.Message}
		// The adapter's capture arrives first and the engine's keys are
		// written over it, never the other way round: `evidence.capture`
		// is arbitrary JSON under the contract, so an adapter — faulty or
		// hostile — could otherwise make immutable evidence claim an
		// image digest and a grant set the run never used. Those two are
		// the engine's own first-hand facts.
		// A collision is not silent: the names it tried are recorded
		// beside them.
		res.Capture = map[string]any{}
		var claimed []string
		for k, v := range verdict.Evidence.Capture {
			if slices.Contains(reservedCapture, k) {
				claimed = append(claimed, k)
				continue
			}
			res.Capture[k] = v
		}
		for k, v := range capture() {
			res.Capture[k] = v
		}
		res.Capture["secrets"] = granted(report.Secrets)
		if len(claimed) > 0 {
			sort.Strings(claimed)
			res.Capture["reserved_keys_ignored"] = claimed
		}
		return res
	}
}

// reservedCapture names the evidence-capture keys the engine states
// itself: the image the run used, the grants it made, and the record of
// an adapter having tried to write either. An adapter's own keys are
// kept as they are — only these three are the engine's.
var reservedCapture = []string{"image", "reserved_keys_ignored", "secrets"}

func granted(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// evaluateAll runs the instance's checkpoints — every one, or those a
// filter keeps — bounded in parallel, recording each result in the
// results table and the evidence journal. objectivesOnce evaluates
// objectives without retries (create and reset: red is expected).
func (e *Engine) evaluateAll(ctx context.Context, job *state.Job, lv *labView, keep func(lab.FlatCheckpoint) bool, objectivesOnce bool) ([]state.CheckpointResult, error) {
	// Nothing is evaluated for an instance whose results could not be
	// filtered: the refusal comes before any adapter runs (PDR-E412,
	// round 21); record applies it again to each result.
	if _, perr := e.redactor(lv.inst.Name); perr != nil {
		return nil, perr
	}
	ev := e.evaluator(lv)
	var selected []lab.FlatCheckpoint
	for _, cp := range lv.checkpoints {
		if keep == nil || keep(cp) {
			selected = append(selected, cp)
		}
	}
	prior, err := e.opts.Store.ListCheckpointResults(lv.inst.Name)
	if err != nil {
		return nil, storeErr("list checkpoint results of "+lv.inst.Name, err)
	}
	if beforeEvaluate != nil {
		beforeEvaluate(lv.inst.Name)
	}
	type outcome struct {
		cp  lab.FlatCheckpoint
		res verify.Result
		// seq is the ticket this evaluation took when it actually began —
		// after its turn at the semaphore, not when the job did:
		// freshness is judged per evaluation
		// (see record).
		seq uint64
		// kept is the attested row that stands for an attest checkpoint:
		// nothing was evaluated or recorded for it (standingAttestation).
		kept *state.CheckpointResult
	}
	outcomes := make([]outcome, len(selected))
	// Admission in authored order: a checkpoint takes its slot before its
	// goroutine starts, so with more checkpoints than slots the later ones
	// begin — and take their start instant — only when a slot frees.
	sem := make(chan struct{}, evaluateConcurrency)
	var wg sync.WaitGroup
	for i, cp := range selected {
		if row, ok := e.standingAttestation(cp, prior); ok {
			outcomes[i] = outcome{cp: cp, kept: &row}
			continue
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(i int, cp lab.FlatCheckpoint) {
			defer wg.Done()
			defer func() { <-sem }()
			seq := e.evalTicket()
			run := cp
			if objectivesOnce && cp.ResolvedClass == "objective" {
				run.Retries = &lab.Retries{Attempts: 1}
			}
			outcomes[i] = outcome{cp: cp, res: ev.Evaluate(ctx, run), seq: seq}
		}(i, cp)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if beforeJobRecord != nil {
		beforeJobRecord(lv.inst.Name)
	}
	var results []state.CheckpointResult
	for _, o := range outcomes {
		if o.kept != nil {
			if err := e.event(job.ID, "checkpoint", o.cp.ID, o.kept.Status, o.cp.ResolvedClass+" · a human's confirmation stands until reset"); err != nil {
				return nil, err
			}
			results = append(results, *o.kept)
			continue
		}
		rec, err := e.record(lv, o.cp, o.res, job.ID, o.seq)
		if err != nil {
			return nil, err
		}
		r := rec.row
		detail := r.Message
		if r.Error != nil {
			detail = r.Error.Code + " " + r.Error.Message
			if r.Error.Cause != "" {
				detail += ": " + r.Error.Cause
			}
		}
		if rec.attested {
			// A human confirmed the checkpoint while this job ran: the
			// confirmation stands, this observation stays in evidence only.
			detail += " · a human's confirmation stands until reset"
		} else if rec.superseded {
			// This job's observation was overtaken by a later evaluation's
			// result; the job decides on what stands.
			detail += fmt.Sprintf(" · superseded: a later evaluation's %s stands", rec.latest.Status)
		}
		if err := e.event(job.ID, "checkpoint", o.cp.ID, r.Status, fmt.Sprintf("%s · %s · %s", o.cp.ResolvedClass, r.Duration, detail)); err != nil {
			return nil, err
		}
		results = append(results, rec.latest)
	}
	return results, nil
}

// standingAttestation returns the attested row that stands for an attest
// checkpoint under its current definition. A human's confirmation is never
// re-judged by a machine: a verify, a create's re-verify and a run keep
// it, and only reset clears it (spec 0001 §3: attested is never upgraded to a machine pass — nor, as review round 17 found, downgraded to "awaiting" by one).
func (e *Engine) standingAttestation(cp lab.FlatCheckpoint, rows []state.CheckpointResult) (state.CheckpointResult, bool) {
	if cp.Adapter != "attest" {
		return state.CheckpointResult{}, false
	}
	digest := lab.DefinitionDigest(cp)
	for _, r := range rows {
		if r.ID == cp.ID && r.Status == verify.StatusAttested && r.Definition == digest {
			return r, true
		}
	}
	return state.CheckpointResult{}, false
}

// recorded is what a record produced: this evaluation's row — in evidence
// always — and the row that stands as the latest result after the call:
// the same row, or the fresher one that stood (superseded).
type recorded struct {
	// attested: the row that stands is a human's confirmation this
	// machine evaluation did not replace (D73).
	attested   bool
	row        state.CheckpointResult
	latest     state.CheckpointResult
	superseded bool
	// standing reports that latest is a row the store holds for the
	// checkpoint — a superseded record with nothing standing (a reset
	// cleared the results and its re-create recorded none yet) leaves
	// latest as the superseded row itself, which is no answer.
	standing bool
}

// record turns an evaluation into an evidence entry and, unless a fresher
// evaluation's result already stands, the instance's latest result — text
// redaction-filtered, observed and expected as JSON. The row's Evidence
// field points at the entry.
func (e *Engine) record(lv *labView, cp lab.FlatCheckpoint, res verify.Result, job string, seq uint64) (recorded, error) {
	red, perr := e.redactor(lv.inst.Name)
	if perr != nil {
		return recorded{}, perr
	}
	now := time.Now().UTC()
	row := state.CheckpointResult{Instance: lv.inst.Name, ID: cp.ID, Class: cp.ResolvedClass, Adapter: cp.Adapter, Status: res.Status, At: now, Duration: res.Duration.Round(time.Millisecond).String(), Job: job, Message: red.Redact(res.Message), Definition: lab.DefinitionDigest(cp)}
	if res.Status == verify.StatusFail {
		row.Hint = cp.Hint
	}
	if res.Status == verify.StatusError && res.Error != nil {
		pe := *res.Error
		pe.Message, pe.Cause, pe.Next = red.Redact(pe.Message), red.Redact(pe.Cause), red.Redact(pe.Next)
		row.Error = &pe
	} else {
		if res.Observed != nil {
			raw, err := json.Marshal(res.Observed)
			if err == nil {
				row.Observed = red.RedactBytes(raw)
			}
		}
		if res.Expected != nil {
			raw, err := json.Marshal(res.Expected)
			if err == nil {
				row.Expected = red.RedactBytes(raw)
			}
		}
	}
	entry := evidence.Entry{Type: evidence.TypeCheckpoint, Instance: lv.inst.Name, At: now, Authoring: lv.inst.Mode == state.ModeAuthoring, Job: job}
	rowCopy := row
	if len(res.Capture) > 0 {
		// An extension's capture is arbitrary JSON: redacted recursively
		// as a value, then once more as bytes — nothing an adapter can
		// shape escapes the filter before it reaches evidence.
		capture, _ := red.RedactValue(res.Capture).(map[string]any)
		raw, _ := json.Marshal(capture)
		rowCopy.Observed = mergeCapture(rowCopy.Observed, red.RedactBytes(raw))
	}
	entry.Checkpoint = &rowCopy
	// Under the instance guard (guard.go): the instance is confirmed
	// present, and destroy's removal cannot interleave with the append and
	// the row — a run that outlived its instance records nothing.
	out := recorded{}
	err := e.withInstance(lv.inst, func() error {
		if job == "" {
			// A synchronous run re-checks under the lock: a destroy or reset
			// admitted since the run began owns the lab now, and an
			// observation of it is not recorded.
			// A job's own records are the job's — it holds the slot.
			if err := e.refuseWhileRebuilding(lv.inst.Name); err != nil {
				return err
			}
		}
		stored, err := e.journal(lv.inst.Name).Append(entry)
		if err != nil {
			return storeErr("record evidence of checkpoint "+cp.ID, err)
		}
		row.Evidence = evidencePath(lv.inst.Name, stored.ID)
		out.row = row
		// Freshness is judged by the ticket the evaluation took when it
		// began, never by record time
		// and never by a wall clock, which a host correction can move
		// backwards (round 69): an evaluation that began before the one
		// whose result stands is the older observation, whatever the order
		// the two recorded in. The older stays in evidence — it happened —
		// but does not become the latest result.
		key := lv.inst.Name + "\x00" + cp.ID
		e.evalMu.Lock()
		last, seen := e.lastEval[key]
		e.evalMu.Unlock()
		// A human's confirmation is never the older observation within
		// its generation: an attestation whose record a concurrent machine
		// run passed on the way still stands, since an attestation stands
		// until reset (D73) and a machine evaluation cannot outrank it by
		// starting later. Until reset: an
		// evaluation or attestation begun before the last reset cleared
		// the results belongs to the generation that reset ended, and
		// stays in evidence only.
		superseded := e.preReset(lv.inst.Name, seq) || (seen && seq < last && res.Status != verify.StatusAttested)
		// A machine evaluation never replaces a standing attestation (D73):
		// an attest checkpoint whose latest row is a human's confirmation
		// for this definition keeps it whatever the order of the two — the
		// confirmation may have landed after the job read its rows and
		// before this evaluation began. The evaluation stays in evidence.
		if !superseded && cp.Adapter == "attest" && res.Status != verify.StatusAttested {
			prior, err := e.opts.Store.ListCheckpointResults(lv.inst.Name)
			if err != nil {
				return storeErr("list checkpoint results of "+lv.inst.Name, err)
			}
			if att, ok := e.standingAttestation(cp, prior); ok {
				out.superseded, out.attested, out.latest = true, true, att
				e.opts.Logf("%s · checkpoint %s: a human's confirmation stands; this evaluation stays in evidence only (%s)", lv.inst.Name, cp.ID, row.Evidence)
				return nil
			}
		}
		if superseded {
			out.superseded = true
			out.latest = row
			prior, err := e.opts.Store.ListCheckpointResults(lv.inst.Name)
			if err != nil {
				return storeErr("list checkpoint results of "+lv.inst.Name, err)
			}
			for _, p := range prior {
				if p.ID == cp.ID {
					out.latest, out.standing = p, true
				}
			}
			e.opts.Logf("%s · checkpoint %s: an evaluation begun earlier (#%d) stands; this one began at #%d and stays in evidence only (%s)", lv.inst.Name, cp.ID, last, seq, row.Evidence)
			return nil
		}
		if err := e.opts.Store.PutCheckpointResult(row); err != nil {
			return storeErr("record checkpoint "+cp.ID, err)
		}
		// Only a persisted result advances the mark:
		// a write the store refused leaves an older evaluation
		// free to land, so a transient fault never pins a stale row.
		e.evalMu.Lock()
		if e.lastEval == nil {
			e.lastEval = map[string]uint64{}
		}
		if e.lastEval[key] <= seq { // the mark never moves back: an attestation recorded past a later machine run keeps the later ticket
			e.lastEval[key] = seq
		}
		e.evalMu.Unlock()
		out.latest, out.standing = row, true
		return nil
	})
	return out, err
}

// beforeEvaluate is a test seam: called by evaluateAll after it read the
// rows and before any evaluation begins, so a test can land an attestation
// in that window. Nil in production.
var beforeEvaluate func(instance string)

// beforeRecord and beforeJobRecord are test seams: called by RunCheckpoint
// between the evaluation and its record, and by a job's evaluateAll
// between the evaluations and their records, so a test can hold a run at
// the moment another write could pass it. Nil in production.
var (
	beforeRecord func(instance string)
	// beforeStandingAttestation is a test seam: called by RunCheckpoint in
	// the window between its first rebuild check and the guarded read of a
	// standing attestation, so a test can admit a reset there (round 68).
	beforeStandingAttestation func(instance string)
	beforeJobRecord           func(instance string)
	// beforeAttestRecord is called by Attest between its guards and its
	// record, so a test can hold an attestation while a reset completes.
	beforeAttestRecord func(instance string)
)

// mergeCapture adds an exec verdict's capture beside the observed JSON
// in the evidence entry: {"observed": …, "capture": …} when both exist.
func mergeCapture(observed, capture json.RawMessage) json.RawMessage {
	if len(observed) == 0 {
		raw, _ := json.Marshal(map[string]json.RawMessage{"capture": capture})
		return raw
	}
	raw, _ := json.Marshal(map[string]json.RawMessage{"observed": observed, "capture": capture})
	return raw
}

var randRead = func(b []byte) (int, error) { return cryptoRead(b) }

// --- the read and run surfaces (API §8) --------------------------------------

// CheckpointView is one row of GET /instances/{name}/checkpoints.
type CheckpointView struct {
	ID       string                  `json:"id"`
	Class    string                  `json:"class"`
	Adapter  string                  `json:"adapter"`
	Severity string                  `json:"severity"`
	Source   string                  `json:"source"`
	Playbook string                  `json:"playbook,omitempty"`
	Step     string                  `json:"step,omitempty"`
	Steps    []string                `json:"steps,omitempty"`
	Expect   map[string]any          `json:"expect,omitempty"`
	Hint     string                  `json:"hint,omitempty"`
	Result   *state.CheckpointResult `json:"result"`
}

// Checkpoints lists an instance's checkpoints with their latest results.
func (e *Engine) Checkpoints(name string, by Actor) (ret []CheckpointView, err error) {
	lv, err := e.instanceViewFor(name, by.Gen)
	if err != nil {
		return nil, err
	}
	defer func() { err = e.confirmed(lv, err) }()
	results, err := e.opts.Store.ListCheckpointResults(name)
	if err != nil {
		return nil, storeErr("list checkpoint results of "+name, err)
	}
	// The rows as they stand for the current definitions: an edited
	// checkpoint shows pending until it is judged again, never an old
	// verdict beside a new expectation (currentResults).
	latest := map[string]state.CheckpointResult{}
	for _, r := range lv.currentResults(results) {
		latest[r.ID] = r
	}
	out := make([]CheckpointView, 0, len(lv.checkpoints))
	for _, cp := range lv.checkpoints {
		v := CheckpointView{ID: cp.ID, Class: cp.ResolvedClass, Adapter: cp.Adapter, Severity: cp.Severity(), Source: cp.Source, Playbook: cp.Playbook, Step: cp.Step, Steps: cp.Steps, Expect: cp.Expect, Hint: cp.Hint}
		if r, ok := latest[cp.ID]; ok && r.Status != "" {
			rr := r
			v.Result = &rr
		}
		out = append(out, v)
	}
	return out, nil
}

// RunCheckpoint evaluates one checkpoint synchronously with its full
// retries (API §8: 200 whether it passes or fails). Allowed beside any
// job but a destroy: it changes no lab state, it appends evidence — under
// the instance guard, so it never appends to an instance destroy removed.
func (e *Engine) RunCheckpoint(ctx context.Context, name, id string, by Actor) (*state.CheckpointResult, error) {
	lv, err := e.instanceViewFor(name, by.Gen)
	if err != nil {
		return nil, err
	}
	if err := e.refuseWhileRebuilding(name); err != nil {
		return nil, err
	}
	cp, ok := lv.checkpoint(id)
	if !ok {
		return nil, notFoundKind(pdr.CodeCheckpointNotFound, "checkpoint", id, "GET /instances/"+name+"/checkpoints")
	}
	if cp.Adapter == "attest" {
		if beforeStandingAttestation != nil {
			beforeStandingAttestation(name)
		}
		// The standing attestation short-circuits the adapter, so it must
		// be read under the instance guard with the rebuild check beside
		// it — the one `record` performs for every other answer. Without
		// that, a reset admitted between the check above and this read
		// would have the run answer 200 with a confirmation the reset is
		// about to clear, which API §8 says is refused while a reset owns
		// the lab.
		var standing *state.CheckpointResult
		if err := e.withInstance(lv.inst, func() error {
			if err := e.refuseWhileRebuilding(lv.inst.Name); err != nil {
				return err
			}
			rows, err := e.opts.Store.ListCheckpointResults(name)
			if err != nil {
				return storeErr("list checkpoint results of "+name, err)
			}
			if row, ok := e.standingAttestation(cp, rows); ok {
				held := row
				standing = &held
			}
			return nil
		}); err != nil {
			return nil, err
		}
		if standing != nil {
			return standing, nil
		}
	}
	if _, perr := e.redactor(name); perr != nil {
		return nil, perr // refused before the adapter runs (PDR-E412)
	}
	seq := e.evalTicket()
	res := e.evaluator(lv).Evaluate(ctx, cp)
	if beforeRecord != nil {
		beforeRecord(name)
	}
	rec, err := e.record(lv, cp, res, "", seq)
	if err != nil {
		return nil, err
	}
	e.opts.Logf("%s · checkpoint %s %s · %s", name, cp.ID, rec.row.Status, rec.row.Message)
	return &rec.row, nil
}

// Attest records a human confirmation of an attest checkpoint (API §8):
// the result is attested — ◇, never a machine pass — with who confirmed.
func (e *Engine) Attest(ctx context.Context, name, id, note string, by Actor) (*state.CheckpointResult, error) {
	// The attestation's ticket is taken at entry, before any guard: a
	// request descheduled between the guard and its record while a reset
	// ran to completion began before that reset, and is judged so.
	// A ticket rather than an instant, so a
	// clock correction cannot move it across the reset (round 69).
	seq := e.evalTicket()
	lv, err := e.instanceViewFor(name, by.Gen)
	if err != nil {
		return nil, err
	}
	if err := e.refuseWhileRebuilding(name); err != nil {
		return nil, err
	}
	cp, ok := lv.checkpoint(id)
	if !ok {
		return nil, notFoundKind(pdr.CodeCheckpointNotFound, "checkpoint", id, "GET /instances/"+name+"/checkpoints")
	}
	if cp.Adapter != "attest" {
		pe := pdr.New(pdr.CodeAttestRefused, "checkpoint %s is judged by its %s adapter, not by attestation", id, cp.Adapter)
		pe.Next = "POST /instances/" + name + "/checkpoints/" + id + "/run"
		return nil, pe
	}
	// The definition is read as the adapter reads it: a prompt of the
	// wrong shape, a key the adapter does not read, an expectation — a
	// confirmation of a condition never shown is not recorded.
	if _, bad := verify.AttestPrompt(cp); bad != nil {
		return nil, bad.Error
	}
	actor := by.Subject
	if actor == "" {
		actor = by.Mechanism
	}
	msg := "attested by " + actor
	if strings.TrimSpace(note) != "" {
		msg += ": " + strings.TrimSpace(note)
	}
	res := verify.Result{Status: verify.StatusAttested, Observed: map[string]any{"attested": true, "by": actor}, Expected: map[string]any{"attested": true}, Message: msg}
	if beforeAttestRecord != nil {
		beforeAttestRecord(name)
	}
	rec, err := e.record(lv, cp, res, "", seq)
	if err != nil {
		return nil, err
	}
	if rec.superseded {
		if !rec.standing {
			// The confirmation is in evidence, but the reset that outran
			// it cleared the generation it belonged to and its re-create
			// has recorded nothing yet — the checkpoint is pending, and an
			// attested answer would claim what does not stand.
			pe := pdr.New(pdr.CodeInstanceBusy, "checkpoint %s of %s was reset while the attestation was in flight; the confirmation is kept in evidence only", id, name)
			pe.Cause = "the reset cleared the results the confirmation belonged to, and nothing stands for the checkpoint yet"
			pe.Evidence = rec.row.Evidence
			pe.Next = "podaro status " + name + " · attest again once the instance is ready"
			return nil, pe
		}
		// The confirmation is in evidence, but a reset that outran it
		// cleared the generation it belonged to: the standing result is
		// the honest answer.
		return &rec.latest, nil
	}
	return &rec.row, nil
}

// --- the verify job (API §7: the pre-flight) ---------------------------------

// VerifyAs admits a verify job: every checkpoint (or a playbook's
// objectives beside every baseline), by class; only baselines feed the
// ladder.
func (e *Engine) VerifyAs(ctx context.Context, name, playbook string, by Actor) (*state.Job, error) {
	return e.admitFor(name, by.Gen, "verify", playbook, func(lv *labView) error {
		if playbook != "" && lab.PlaybookNamed(lv.res, playbook) == nil {
			return notFoundKind(pdr.CodePlaybookNotFound, "playbook", playbook, "GET /instances/"+name+"/playbooks")
		}
		return nil
	}, nil)
}

// admit reserves the instance's exclusive slot for a job of kind with a
// target, after a check the caller supplies against the resolved lab,
// and launches it. audit, when set, is recorded before the job exists
// (API §2.5: a record the stream refuses stops the act).
func (e *Engine) admit(name, kind, target string, check func(*labView) error, audit *state.Audit) (*state.Job, error) {
	return e.admitFor(name, nil, kind, target, check, audit)
}

// admitFor is admit for a caller entitled to one generation of this
// name; the comparison is against the instance this call resolved, under
// the same lock that will reserve the slot.
func (e *Engine) admitFor(name string, want *int64, kind, target string, check func(*labView) error, audit *state.Audit) (*state.Job, error) {
	e.jobMu.Lock()
	defer e.jobMu.Unlock()
	inst, err := e.lookup(name)
	if err != nil {
		return nil, err
	}
	if inst == nil {
		return nil, e.notFound(name)
	}
	if want != nil && inst.AuditFrom != *want {
		return nil, e.notFound(name)
	}
	if retiredTemplate(inst) {
		// Before anything is recorded — no audit row, no job: a reset
		// admits without loading the lab, and its job would otherwise be
		// the first to find out (the reconciliation plan's R3).
		return nil, e.unsupported(inst)
	}
	if inst.Stage == state.StageNone {
		pe := pdr.New(pdr.CodeInstanceBusy, "instance %q has not been created yet", name)
		pe.Cause = "its create job never reached alive"
		pe.Next = "podaro up again to resume the create · podaro status " + name
		return nil, pe
	}
	if check != nil {
		lv, err := e.loadLab(inst)
		if err != nil {
			return nil, err
		}
		if err := check(lv); err != nil {
			return nil, err
		}
	}
	active, err := e.activeJob(name)
	if err != nil {
		return nil, err
	}
	if active != nil {
		return nil, e.busy(name, active)
	}
	jobID, err := e.freshJobID()
	if err != nil {
		return nil, err
	}
	job := state.Job{ID: jobID, Kind: kind, Instance: name, Gen: inst.AuditFrom, State: state.JobQueued, Stage: "queued", Started: time.Now().UTC(), Target: target}
	if audit != nil {
		a := *audit
		a.At = job.Started
		a.Detail = strings.TrimSpace(a.Detail + " · job " + job.ID)
		if err := e.opts.Store.AppendAudit(a); err != nil {
			return nil, storeErr("audit the "+kind+" of "+name, err)
		}
	}
	if err := e.opts.Store.PutJob(job); err != nil {
		return nil, storeErr("record job", err)
	}
	e.launch(job)
	return &job, nil
}

// verifySteps is the verify job: full retries everywhere (it is the
// pre-flight), the ladder moved by baselines alone.
func (e *Engine) verifySteps(ctx context.Context, job *state.Job) error {
	var keep func(lab.FlatCheckpoint) bool
	if job.Target != "" {
		// A verify scoped to one playbook: its baselines and that
		// playbook's objectives.
		keep = func(cp lab.FlatCheckpoint) bool {
			if cp.ResolvedClass == "baseline" {
				return true
			}
			for _, s := range cp.Steps {
				if strings.HasPrefix(s, job.Target+"/") {
					return true
				}
			}
			return false
		}
	}
	return e.verifyWith(ctx, job, keep)
}

// baselinesOnly keeps the baselines: what a reconcile re-verifies (User
// Manual §8) and what a resumed seed judges after its seed (restored).
func baselinesOnly(cp lab.FlatCheckpoint) bool { return cp.ResolvedClass == "baseline" }

// verifyWith is the verify job's walk over the checkpoints keep selects
// (nil: all), with the verify's own rules: full retries, a gate baseline
// found red moves the ladder back to seeded, one found green again
// restores ready, and the job succeeds either way.
func (e *Engine) verifyWith(ctx context.Context, job *state.Job, keep func(lab.FlatCheckpoint) bool) error {
	lv, err := e.jobLab(job)
	if err != nil {
		return err
	}
	if err := e.ensureResultRows(lv); err != nil {
		return err
	}
	e.stage(job, "verifying")
	results, err := e.evaluateAll(ctx, job, lv, keep, false)
	if err != nil {
		return err
	}
	var gateFailed []string
	for _, r := range results {
		cp, _ := lv.checkpoint(r.ID)
		if cp.ResolvedClass == "baseline" && cp.Severity() == "gate" && r.Status != verify.StatusPass {
			gateFailed = append(gateFailed, r.ID)
		}
	}
	all, err := e.opts.Store.ListCheckpointResults(lv.inst.Name)
	if err != nil {
		return storeErr("list checkpoint results of "+lv.inst.Name, err)
	}
	t := tally(all)
	summary := fmt.Sprintf("baseline %d/%d · objectives %d/%d", t.Baseline.Passed, t.Baseline.Total, t.Objective.Passed, t.Objective.Total)
	if len(gateFailed) > 0 {
		// A regression: the ladder falls back to seeded and says so (UX §5).
		if err := e.event(job.ID, "verified", "", "failed", summary+" · gate baselines failed: "+strings.Join(gateFailed, ", ")); err != nil {
			return err
		}
		if err := e.lifecycle(lv, job.ID, "verify", string(state.StageSeeded), summary+" · regression: "+strings.Join(gateFailed, ", ")); err != nil {
			return err
		}
		if lv.inst.Stage.Rank() > state.StageSeeded.Rank() {
			if err := e.demoteAll(lv.inst.Name, state.StageSeeded); err != nil {
				return err
			}
		}
		return nil
	}
	if err := e.event(job.ID, "verified", "", "ok", summary); err != nil {
		return err
	}
	if err := e.lifecycle(lv, job.ID, "verify", string(state.StageReady), summary); err != nil {
		return err
	}
	if lv.inst.Stage.Rank() >= state.StageSeeded.Rank() {
		if err := e.markAll(lv.inst.Name, state.StageVerified); err != nil {
			return err
		}
		return e.markAll(lv.inst.Name, state.StageReady)
	}
	return nil
}

// jobLab resolves a job's instance and lab; an instance that is gone is
// the not-found envelope (the job fails, naming it).
func (e *Engine) jobLab(job *state.Job) (*labView, error) {
	inst, err := e.opts.Store.GetInstance(job.Instance)
	if errors.Is(err, state.ErrNotFound) {
		return nil, e.notFound(job.Instance)
	}
	if err != nil {
		return nil, storeErr("look up instance "+job.Instance, err)
	}
	return e.loadLab(inst)
}

// sortedResults orders results by class then id (baselines first).
func sortedResults(results []state.CheckpointResult) []state.CheckpointResult {
	out := append([]state.CheckpointResult(nil), results...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Class != out[j].Class {
			return out[i].Class == "baseline"
		}
		return out[i].ID < out[j].ID
	})
	return out
}
