// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jeremiahjrross/podaro/internal/lab"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// Playbooks and progress (API §8; spec 0001 §5–§8). The data is
// mode-neutral: Guided, Presenter, and Author are manners the client
// applies (UX §8).

// PlaybookSummary is one row of GET /instances/{name}/playbooks.
type PlaybookSummary struct {
	Name        string   `json:"name"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Modes       []string `json:"modes"`
	Gating      string   `json:"gating"`
	Steps       int      `json:"steps"`
	Objectives  int      `json:"objectives"`
	// FirstStep is where this playbook's walk begins. Progress that has
	// never been written reads back with CurrentStep set to exactly this
	// (see Progress), so it is the one fact that tells a saved position
	// from the default one — and the console's start-here card is the
	// caller that needs it.
	FirstStep string `json:"first_step,omitempty"`
}

// PlaybookView is GET /instances/{name}/playbooks/{id}: the ordered steps
// with their narrative, context, actions, checkpoint reference, notes,
// hints, and solution — everything a rail renders, in every mode.
type PlaybookView struct {
	PlaybookSummary
	StepList []StepView `json:"step_list"`
}

// StepView is one step.
type StepView struct {
	ID         string          `json:"id"`
	Title      string          `json:"title"`
	Context    string          `json:"context"`
	Duration   string          `json:"duration,omitempty"`
	Auto       bool            `json:"auto,omitempty"`
	Body       string          `json:"body"`
	Notes      string          `json:"notes,omitempty"`
	Actions    []ActionView    `json:"actions,omitempty"`
	Checkpoint *StepCheckpoint `json:"checkpoint,omitempty"`
	Solution   string          `json:"solution,omitempty"`
}

// ActionView is a seed or reveal button.
type ActionView struct {
	Seed   string `json:"seed,omitempty"`
	Reveal string `json:"reveal,omitempty"`
	// Label is the button's name (UX §6: it names its exact payload).
	Label string `json:"label"`
}

// StepCheckpoint references the step's checkpoint by id with its class
// and adapter; the result is read from the checkpoints surface.
type StepCheckpoint struct {
	ID      string `json:"id"`
	Class   string `json:"class"`
	Adapter string `json:"adapter"`
	Hint    string `json:"hint,omitempty"`
}

func summarize(pb *lab.Playbook, lv *labView) PlaybookSummary {
	modes := pb.Metadata.Modes
	if len(modes) == 0 {
		modes = []string{"guided", "presenter", "repro"}
	}
	gating := pb.Metadata.Gating
	if gating == "" {
		gating = "soft"
	}
	objectives := 0
	for _, st := range pb.Steps {
		if cp := stepCheckpoint(st, lv); cp != nil && cp.Class == "objective" {
			objectives++
		}
	}
	first := ""
	if len(pb.Steps) > 0 {
		first = pb.Steps[0].ID
	}
	return PlaybookSummary{Name: pb.Metadata.Name, Title: pb.Metadata.Title, Description: strings.TrimSpace(pb.Metadata.Description), Modes: modes, Gating: gating, Steps: len(pb.Steps), Objectives: objectives, FirstStep: first}
}

func stepCheckpoint(st lab.Step, lv *labView) *StepCheckpoint {
	if st.Checkpoint == nil {
		return nil
	}
	id := st.Checkpoint.ID
	if st.Checkpoint.Ref != "" {
		id = st.Checkpoint.Ref
	}
	cp, ok := lv.checkpoint(id)
	if !ok {
		return nil
	}
	return &StepCheckpoint{ID: cp.ID, Class: cp.ResolvedClass, Adapter: cp.Adapter, Hint: cp.Hint}
}

// Playbooks lists an instance's playbooks.
func (e *Engine) Playbooks(name string, by Actor) (ret []PlaybookSummary, err error) {
	lv, err := e.instanceViewFor(name, by.Gen)
	if err != nil {
		return nil, err
	}
	defer func() { err = e.confirmed(lv, err) }()
	out := []PlaybookSummary{}
	for _, lp := range lv.res.Playbooks {
		out = append(out, summarize(lp.Playbook, lv))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Playbook returns one playbook in full.
func (e *Engine) Playbook(name, playbook string, by Actor) (ret *PlaybookView, err error) {
	lv, err := e.instanceViewFor(name, by.Gen)
	if err != nil {
		return nil, err
	}
	defer func() { err = e.confirmed(lv, err) }()
	pb := lab.PlaybookNamed(lv.res, playbook)
	if pb == nil {
		return nil, notFoundKind(pdr.CodePlaybookNotFound, "playbook", playbook, "GET /instances/"+name+"/playbooks")
	}
	v := &PlaybookView{PlaybookSummary: summarize(pb, lv), StepList: []StepView{}}
	for _, st := range pb.Steps {
		sv := StepView{ID: st.ID, Title: st.Title, Context: st.Context, Duration: st.Duration, Auto: st.Auto, Body: st.Body, Notes: st.Notes, Solution: st.Solution}
		if sv.Context == "" {
			sv.Context = "overview"
		}
		for _, a := range st.Actions {
			switch {
			case a.Seed != "":
				label := "Send " + a.Seed
				if s, ok := lv.res.Template.Seeds[a.Seed]; ok && s.Count > 0 {
					label = fmt.Sprintf("Send %s · %d", a.Seed, s.Count)
					if s.Generator.Name == "http-requests" {
						label += " requests"
					} else {
						label += " events"
					}
				}
				sv.Actions = append(sv.Actions, ActionView{Seed: a.Seed, Label: label})
			case a.Reveal != "":
				sv.Actions = append(sv.Actions, ActionView{Reveal: a.Reveal, Label: "Reveal " + a.Reveal})
			}
		}
		sv.Checkpoint = stepCheckpoint(st, lv)
		v.StepList = append(v.StepList, sv)
	}
	return v, nil
}

// Progress returns a playbook's recorded position as the current playbook
// stands: a step it no longer has is dropped, a current step it no longer
// has falls to the first step, and a pass, fail or attested its
// checkpoint's current result does not back — no result, another status,
// a definition since changed — reads as pending: exactly what PutProgress
// would refuse to write now. Nothing is
// written; the stored row stays what was last recorded. None recorded is
// an empty position at the first step.
func (e *Engine) Progress(name, playbook string, by Actor) (ret *state.Progress, err error) {
	lv, err := e.instanceViewFor(name, by.Gen)
	if err != nil {
		return nil, err
	}
	defer func() { err = e.confirmed(lv, err) }()
	pb := lab.PlaybookNamed(lv.res, playbook)
	if pb == nil {
		return nil, notFoundKind(pdr.CodePlaybookNotFound, "playbook", playbook, "GET /instances/"+name+"/playbooks")
	}
	p, err := e.opts.Store.GetProgress(name, playbook)
	if errors.Is(err, state.ErrNotFound) {
		p = &state.Progress{Instance: name, Playbook: playbook, Steps: map[string]state.StepProgress{}}
		if len(pb.Steps) > 0 {
			p.CurrentStep = pb.Steps[0].ID
		}
		return p, nil
	}
	if err != nil {
		return nil, storeErr("read the progress of "+name+"/"+playbook, err)
	}
	rows, err := e.opts.Store.ListCheckpointResults(name)
	if err != nil {
		return nil, storeErr("list checkpoint results of "+name, err)
	}
	return lv.currentProgress(pb, *p, rows), nil
}

// currentProgress is the read-side twin of PutProgress's validation (see
// Progress): the recorded position reconciled with the playbook's steps
// and the checkpoint results as they stand now (currentResults).
func (lv *labView) currentProgress(pb *lab.Playbook, p state.Progress, rows []state.CheckpointResult) *state.Progress {
	steps := map[string]lab.Step{}
	for _, st := range pb.Steps {
		steps[st.ID] = st
	}
	latest := map[string]state.CheckpointResult{}
	for _, r := range lv.currentResults(rows) {
		latest[r.ID] = r
	}
	out := state.Progress{Instance: p.Instance, Playbook: p.Playbook, CurrentStep: p.CurrentStep, Steps: map[string]state.StepProgress{}, Updated: p.Updated}
	if _, ok := steps[out.CurrentStep]; !ok {
		out.CurrentStep = ""
		if len(pb.Steps) > 0 {
			out.CurrentStep = pb.Steps[0].ID
		}
	}
	for id, sp := range p.Steps {
		st, ok := steps[id]
		if !ok {
			continue
		}
		if sp.Status != "skipped" {
			cp := stepCheckpoint(st, lv)
			if cp == nil || latest[cp.ID].Status != sp.Status {
				continue
			}
		}
		out.Steps[id] = sp
	}
	return &out
}

// PutProgress replaces a playbook's position (API §8, PUT): the current
// step must be one of the playbook's; every step status is pass, fail,
// attested, or skipped; and a pass, fail, or attested must be backed by
// the step's checkpoint's latest result — the console may never write a
// pass without a result behind it (spec 0001 §8).
func (e *Engine) PutProgress(name, playbook string, p state.Progress, by Actor) (ret *state.Progress, err error) {
	lv, err := e.instanceViewFor(name, by.Gen)
	if err != nil {
		return nil, err
	}
	defer func() { err = e.confirmed(lv, err) }()
	pb := lab.PlaybookNamed(lv.res, playbook)
	if pb == nil {
		return nil, notFoundKind(pdr.CodePlaybookNotFound, "playbook", playbook, "GET /instances/"+name+"/playbooks")
	}
	steps := map[string]lab.Step{}
	for _, st := range pb.Steps {
		steps[st.ID] = st
	}
	refuse := func(format string, args ...any) error {
		pe := pdr.New(pdr.CodeProgressRefused, format, args...)
		pe.Next = "run the step's checkpoint (POST …/checkpoints/<id>/run) or attest it, then write the status its result supports"
		return pe
	}
	if p.CurrentStep != "" {
		if _, ok := steps[p.CurrentStep]; !ok {
			return nil, refuse("current_step %q is not a step of playbook %s", p.CurrentStep, playbook)
		}
	}
	if beforeProgressWrite != nil {
		beforeProgressWrite(name)
	}
	var stored state.Progress
	// Under the instance guard (guard.go): the supporting results are read
	// and the claimed statuses judged inside the same locked section that
	// writes the progress, so a result recorded meanwhile is seen and a
	// stale validation never lands — and
	// never a row for an instance destroy removed.
	err = e.withInstance(lv.inst, func() error {
		// Not while the lab is being rebuilt or taken down (PDR-E201): a
		// reset clears the results this write would be judged against.
		if err := e.refuseWhileRebuilding(name); err != nil {
			return err
		}
		results, err := e.opts.Store.ListCheckpointResults(name)
		if err != nil {
			return storeErr("list checkpoint results of "+name, err)
		}
		latest := map[string]state.CheckpointResult{}
		for _, r := range results {
			latest[r.ID] = r
		}
		now := time.Now().UTC()
		clean := map[string]state.StepProgress{}
		for id, sp := range p.Steps {
			st, ok := steps[id]
			if !ok {
				return refuse("step %q is not a step of playbook %s", id, playbook)
			}
			switch sp.Status {
			case "skipped":
			case "pass", "fail", "attested":
				cp := stepCheckpoint(st, lv)
				if cp == nil {
					return refuse("step %s has no checkpoint: only skipped can be recorded for it", id)
				}
				r, ok := latest[cp.ID]
				if !ok || r.Status != sp.Status {
					got := "no result"
					if ok && r.Status != "" {
						got = r.Status
					}
					return refuse("step %s claims %s but its checkpoint %s's latest result is %s", id, sp.Status, cp.ID, got)
				}
				// The result must have been judged by the checkpoint as it
				// is now: a definition edited since (an authoring instance)
				// or a result from before definitions were recorded cannot
				// back a claim.
				if fc, ok := lv.checkpoint(cp.ID); ok && r.Definition != lab.DefinitionDigest(fc) {
					return refuse("step %s claims %s but its checkpoint %s changed since that result was recorded — run it again", id, sp.Status, cp.ID)
				}
			default:
				return refuse("step %s status %q is not pass, fail, attested, or skipped", id, sp.Status)
			}
			at := sp.At
			if at.IsZero() {
				at = now
			}
			clean[id] = state.StepProgress{Status: sp.Status, At: at.UTC()}
		}
		stored = state.Progress{Instance: name, Playbook: playbook, CurrentStep: p.CurrentStep, Steps: clean, Updated: now}
		if duringProgressWrite != nil {
			duringProgressWrite(name)
		}
		return e.opts.Store.PutProgress(stored)
	})
	if err != nil {
		if pe := (*pdr.Error)(nil); errors.As(err, &pe) {
			return nil, err
		}
		return nil, storeErr("record the progress of "+name+"/"+playbook, err)
	}
	return &stored, nil
}

// beforeProgressWrite and duringProgressWrite are test seams: called by
// PutProgress after its shape checks and before the locked validation and
// write, and inside the locked section after the validation and before
// the write, so a test can interleave another write at either point. Nil
// in production.
var (
	beforeProgressWrite func(instance string)
	duringProgressWrite func(instance string)
)
