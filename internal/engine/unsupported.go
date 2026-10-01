// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"fmt"
	"time"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/evidence"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// Installed state an earlier build left, handled without destroying it
// (the reconciliation plan's R3; the reconciliation §4.2). The owner
// retired a template on 2026-09-23 together with the adapters,
// generators and modules it used, and no release carries them. An
// instance an earlier build created from it is *unsupported*: this
// release keeps its containers, data, secrets and evidence exactly as
// they are and never operates it on its own initiative — Start neither
// reconciles it nor resumes its jobs, nothing repairs, restarts or stops
// it — and every operation that would run the lab is refused
// (PDR-E215). What still works is what reads the record: status, the
// evidence, the HTML and JUnit reports — and destroy, the operator's act,
// which removes what the instance's labels name and nothing else.
//
// Which templates are retired is the embedded retirement manifest's to
// say (podaro.Retirement(); the plan's Q-R5): nothing here spells a name.

// unsupportedReason is what the mark records (state migration 16) and
// what status shows after "unsupported · ".
const unsupportedReason = "retired template"

// unsupportedDetail is the evidence entry and log line's statement.
const unsupportedDetail = "unsupported by this release: retired template; not reconciled"

// retiredTemplate reports whether the instance was created from a
// template the retirement manifest lists.
func retiredTemplate(inst *state.Instance) bool {
	return inst != nil && podaro.Retirement().Template(inst.Template)
}

// unsupported is the refusal an operation on such an instance gets.
func (e *Engine) unsupported(inst *state.Instance) *pdr.Error {
	pe := pdr.New(pdr.CodeInstanceUnsupported, "instance %s is unsupported by this release: its template %s was retired by the owner on %s", inst.Name, inst.Template, podaro.Retirement().RetiredOn)
	pe.Cause = "this release carries none of the adapters, generators or modules that template used, and does not run the lab · podaro explain " + pdr.CodeInstanceUnsupported
	pe.Next = "podaro status " + inst.Name + " · its evidence and reports still read · podaro destroy " + inst.Name + " when you no longer need it"
	return pe
}

// reportUnsupported is Start's whole treatment of an unsupported
// instance: one PDR-W103 line in the log for this start, and — the first
// time a start finds it — one lifecycle entry in its evidence and the
// mark that keeps the entry to one. Nothing touches its containers, its
// rows or its files. A journal or a mark that cannot be written is
// logged and tried again at the next start: the engine serves the other
// instances either way.
func (e *Engine) reportUnsupported(inst state.Instance) {
	e.opts.Logf("%s %s: unsupported by this release (template %s is retired); not reconciled — its containers are left as they are · podaro explain %s",
		pdr.CodeRetiredPresent, inst.Name, inst.Template, pdr.CodeRetiredPresent)
	marked, err := e.opts.Store.Unsupported(inst.Name)
	if err != nil {
		e.opts.Logf("%s: the unsupported mark could not be read: %v", inst.Name, err)
		return
	}
	if marked != "" {
		return
	}
	entry := evidence.Entry{Type: evidence.TypeLifecycle, Instance: inst.Name, Authoring: inst.Mode == state.ModeAuthoring,
		Lifecycle: &evidence.Lifecycle{Event: "unsupported", Stage: string(inst.Stage), Code: pdr.CodeRetiredPresent, Detail: unsupportedDetail}}
	if _, err := e.journal(inst.Name).Append(entry); err != nil {
		e.opts.Logf("%s: evidence: %v", inst.Name, err)
		return
	}
	if err := e.opts.Store.MarkUnsupported(inst.Name, unsupportedReason); err != nil {
		e.opts.Logf("%s: the unsupported mark could not be recorded: %v", inst.Name, err)
	}
}

// declineJob records, instead of resuming it, an active job an earlier
// engine left for an unsupported instance: resuming a create, seed,
// verify, reset or reconcile would walk the retired lab. A destroy is
// never declined — it is the operator's act, and it is resumed. The
// record is written before anything is launched, like every other write
// of Start.
func (e *Engine) declineJob(j state.Job, inst *state.Instance) error {
	now := time.Now().UTC()
	pe := e.unsupported(inst)
	pe.Message = fmt.Sprintf("%s job %s was not resumed: %s", j.Kind, j.ID, pe.Message)
	j.State, j.Stage, j.Finished, j.Error = state.JobFailed, "failed", &now, pe
	if err := e.opts.Store.PutJob(j); err != nil {
		return storeErr("record job "+j.ID, err)
	}
	e.opts.Logf("%s job %s for %s not resumed: %s", j.Kind, j.ID, j.Instance, unsupportedDetail)
	return e.event(j.ID, "job", "", "failed", "not resumed: "+unsupportedDetail)
}

// recordViewFor resolves an instance for the reads that need its record
// and not its lab — the evidence, the HTML and JUnit reports. For an
// unsupported instance the view carries the instance alone: its plan
// cannot be made by this release, and those reads do not need one.
// Every other instance resolves exactly as instanceViewFor does.
func (e *Engine) recordViewFor(name string, want *int64) (*labView, error) {
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
		return &labView{inst: inst, want: want, unsupported: true}, nil
	}
	lv, err := e.loadLab(inst)
	if lv != nil {
		lv.want = want
	}
	return lv, err
}
