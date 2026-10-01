// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/evidence"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// The S7 surfaces: the playbook rail, the evidence scoreboard, the
// credential list, the reset dialog and the start-here card.
//
// The binding rule (ADR-0003) holds as it does for the S6 fragments:
// every field a template reads is a field the JSON twin marshals. Where a
// fragment needs more than one twin — the rail reads a playbook, its
// progress and its checkpoints, three endpoints the console already
// fetches — the wrapper below carries those values unchanged and adds
// only *presentation* state (which mode is rendering, which step is
// open). That is the same licence ShellData already takes for page
// chrome: a mode is a manner the client applies, never data (UX §8, and
// the engine says so at internal/engine/progress.go).

// Mode is a render manner (UX §8), not a property of any instance.
const (
	ModeGuided    = "guided"
	ModePresenter = "presenter"
	ModeAuthor    = "author"
)

// RailData is what the rail renders: the playbook twin, the progress
// twin, the checkpoint twins, and the manner to render them in.
type RailData struct {
	Instance string
	Mode     string
	Playbook engine.PlaybookView
	Progress *state.Progress
	// Results is the checkpoint list keyed by id — a projection of the
	// GET …/checkpoints twin, never a source of its own.
	Results map[string]engine.CheckpointView
	// Open is the step the rail has focused; empty means the recorded
	// current step.
	Open string
	CSRF string
}

// Glyph and StatusWord are the other two thirds of UX §4's pairing:
// "every status pairs colour + glyph + word", and §9 makes it a rule
// that status is never colour alone. The spine's dots are the collapsed
// rail's only rendering of a verdict, and they were one shape in four
// colours, hidden from assistive technology — so a colour-blind reader
// could not tell a pass from a failure and a screen reader was told
// nothing at all. The mapping is the
// one the result line and the scoreboard already use; there is not a
// second one here.
func (s RailStep) Glyph() Glyph { return glyph(statusToken(s.Result)) }

// StatusWord is that pairing's word.
func (s RailStep) StatusWord() string { return statusWord(s.Result) }

// SpineLabel is what the collapsed rail says: the learner's position and
// the step they are on, in the words the open rail uses for both (UX §6:
// "Collapsed rail shows a slim progress spine … with the current step
// title"). A rail with no steps says so rather than rendering an empty
// label — there is nothing to be in the middle of.
func (d RailData) SpineLabel() string {
	steps := d.Steps()
	if len(steps) == 0 {
		return "No steps"
	}
	cur := steps[0]
	for _, st := range steps {
		if st.Current {
			cur = st
			break
		}
	}
	return cur.Position + " · " + cur.Title
}

// ProgressBody is the progress twin as the console will send it back
// when the learner moves or verifies: `PUT …/progress` replaces the
// record whole (engine.PutProgress), so a client that sent only the new
// position would erase the statuses already earned. The rail therefore
// carries what it was given, and the page changes one field of it.
//
// The binding rule holds (ADR-0003): this is the `GET …/progress` twin,
// marshalled, and nothing else.
func (d RailData) ProgressBody() string {
	body := struct {
		CurrentStep string                        `json:"current_step"`
		Steps       map[string]state.StepProgress `json:"steps"`
	}{Steps: map[string]state.StepProgress{}}
	if d.Progress != nil {
		body.CurrentStep = d.Progress.CurrentStep
		for id, sp := range d.Progress.Steps {
			body.Steps[id] = sp
		}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		// A body that cannot be marshalled is no body: the page keeps
		// working and simply does not save the position, which is a
		// convenience, not the lab.
		return ""
	}
	return string(raw)
}

// PlaybookID is what the progress endpoint is addressed by: the
// playbook's name, which is its id in the API (`GET …/playbooks/{id}`).
// A rail with no playbook has nothing to save against, and the page's
// script leaves it alone.
func (d RailData) PlaybookID() string { return d.Playbook.Name }

// Steps pairs each step with what the rail needs to draw it, so the
// template stays a template.
type RailStep struct {
	engine.StepView
	Index      int
	Position   string
	Current    bool
	Result     *state.CheckpointResult
	Checkpoint *engine.CheckpointView
	// Status is the step's verify state (UX §6 Verify state machine):
	// idle, pass, fail, attested, error, or running.
	Status string
	// Light is the Presenter confidence light: ready, hollow, warn.
	Light string
}

// Attest reports that this step's checkpoint is a human's confirmation
// rather than a machine's judgement (spec 0001 §4). The control it needs
// is a different endpoint, not a different label: `…/run` on an attest
// checkpoint records a failed evaluation saying it awaits confirmation,
// and only `POST …/attest` produces the attested result.
func (s RailStep) Attest() bool {
	return s.Checkpoint != nil && s.Checkpoint.Adapter == "attest"
}

// Runs reports whether this step's one auto control has anything to
// press. `auto: true` with neither actions nor a checkpoint is
// schema-valid and has nothing to run, and rendering "Run this step" for
// it is a control whose whole behaviour is to do nothing — the same
// shape as the inert button of round 5, found reading that fix
// (self-review). Such a step falls back to the ordinary anatomy, which
// for a step with no actions is no action bar at all.
func (s RailStep) Runs() bool {
	// A checkpoint counts only if the control may actually post it. An
	// attest checkpoint may not (AutoAction), so an auto step whose only
	// work is an attestation has nothing for the one control to do — and
	// rendering it anyway is the round-5 dead control again, made by the
	// round-8 fix (self-review of it). Such a step falls back to the
	// ordinary anatomy, where "I confirm this" is the way through.
	return s.Auto && (len(s.Actions) > 0 || (s.Checkpoint != nil && !s.Attest()))
}

// AutoAction is the verification an auto step's one control posts after
// the actions — and it is empty for an attest checkpoint.
//
// `Action` resolves an attest checkpoint to `…/attest`, so anything that
// posts it on its own records a human's confirmation with no human, and
// an immutable evidence entry behind it. Round 3 closed that door for
// the Presenter light's timer (`Rechecks`); round 6's one control walked
// through the other one. A human's claim is earned once, by a human, or
// it is not a human's claim — so the control runs the step's actions and
// stops, and the step keeps its own "I confirm this", which is the only
// thing that may attest.
func (s RailStep) AutoAction(instance, playbook string) string {
	if s.Attest() {
		return ""
	}
	return s.Action(instance, playbook)
}

// ActionList names what an auto step's one control performs, in the
// playbook's order, as `kind:name` pairs for the page to read.
//
// Spec 0001 defines that control as *all* of the step's actions followed
// by its verification. It collected only the seeds, and the template
// suppresses the per-action controls when the one control is shown — so
// a declared `reveal` had no execution path at all: not run by the
// button, and given no button of its own.
func (s RailStep) ActionList() string {
	var out []string
	for _, a := range s.Actions {
		switch {
		case a.Seed != "":
			out = append(out, "seed:"+a.Seed)
		case a.Reveal != "":
			out = append(out, "reveal:"+a.Reveal)
		}
	}
	return strings.Join(out, ",")
}

// RevealsInline reports whether this step's one control will reveal a
// credential, and therefore needs somewhere on the card to put it.
func (s RailStep) RevealsInline() bool {
	if !s.Runs() {
		return false
	}
	for _, a := range s.Actions {
		if a.Reveal != "" {
			return true
		}
	}
	return false
}

// Rechecks reports whether Presenter may re-run this step's checkpoint
// on its own. A machine checkpoint may: that is what a confidence light
// *is*, and one that is only remembered is a claim about the lab as it
// was. An attest checkpoint may not, and this is the whole reason the
// distinction is here: `Action` resolves an attest step to `…/attest`,
// so a timer pointed at it would record a human's confirmation — and an
// immutable evidence entry — every twenty seconds with nobody
// confirming anything. A human's claim
// is earned once, by a human, or it is not a human's claim.
func (s RailStep) Rechecks() bool { return s.Checkpoint != nil && !s.Attest() }

// OffersVerify reports whether this step shows a checkpoint control of
// its own. It does not when the one control already owns the checkpoint:
// a Guided auto step showed both, and pressing the second skipped the
// declared actions and judged the lab as it was — the opposite of spec
// 0001's one-click contract.
//
// An attest step always shows it, because the one control deliberately
// does not post an attestation (AutoAction), so the human's own control
// is the only way through.
func (s RailStep) OffersVerify() bool {
	if s.Checkpoint == nil {
		return false
	}
	return !s.Runs() || s.Attest()
}

// Action is where this step's Verify control posts: the attest endpoint
// for an attest checkpoint, the run endpoint for every other, each
// carrying the step id so the result fragment comes back with the id the
// button already targets.
// Action is the request this step's checkpoint control posts. It names
// the playbook as well as the step, because the answer has to know which
// steps are on the page: a checkpoint's `steps` are qualified
// `playbook/step`, and only this playbook's have regions here.
func (s RailStep) Action(instance, playbook string) string {
	if s.Checkpoint == nil {
		return ""
	}
	verb := "run"
	if s.Attest() {
		verb = "attest"
	}
	return "/api/v1alpha1/instances/" + instance + "/checkpoints/" + s.Checkpoint.ID + "/" + verb +
		"?step=" + s.ID + "&playbook=" + playbook
}

// Steps builds the rail's rows.
func (d RailData) Steps() []RailStep {
	open := d.Open
	if open == "" && d.Progress != nil {
		open = d.Progress.CurrentStep
	}
	out := make([]RailStep, 0, len(d.Playbook.StepList))
	for i, s := range d.Playbook.StepList {
		rs := RailStep{StepView: s, Index: i + 1}
		rs.Position = "Step " + itoa(i+1) + " of " + itoa(len(d.Playbook.StepList))
		rs.Current = s.ID == open
		// A step that declares a checkpoint always offers to verify it.
		// The checkpoints twin adds the expectation and the latest
		// result when it has one; without it the step still knows its
		// checkpoint's id, class, adapter and hint — the playbook twin
		// carries all four — so Verify is never missing merely because
		// nothing has been judged yet.
		if s.Checkpoint != nil {
			c := engine.CheckpointView{ID: s.Checkpoint.ID, Class: s.Checkpoint.Class, Adapter: s.Checkpoint.Adapter, Hint: s.Checkpoint.Hint}
			if cv, ok := d.Results[s.Checkpoint.ID]; ok {
				c = cv
				if c.Hint == "" {
					c.Hint = s.Checkpoint.Hint
				}
				rs.Result = cv.Result
			}
			rs.Checkpoint = &c
		}
		rs.Status = stepStatus(rs.Result)
		rs.Light = confidence(rs.Result)
		out = append(out, rs)
	}
	return out
}

// Presenter says whether the rail is in Presenter manners: notes visible,
// no gating, and — the hard rule — nothing that can interrupt (UX §8).
func (d RailData) Presenter() bool { return d.Mode == ModePresenter }

// Guided says whether the rail is in Guided manners.
func (d RailData) Guided() bool { return d.Mode == "" || d.Mode == ModeGuided }

// Author says whether the rail is in Author preview (UX §8): the manner
// an authoring instance reads its own playbook in. Notes are visible,
// the checkpoint control reads "Test checkpoint", and an auto step's
// actions are listed under its one control — seeing what that control
// will do is the point of a preview.
//
// The manner has existed as a name since S7 (railMode accepted it) and
// as behaviour nowhere: round 6 added the link to it, and a link to a
// manner that is not implemented is worse than no link, so this is the
// manner the link now promises (self-review of that fix).
//
// What it is not: the authoring workbench. An editable source path and
// captured-evidence detail (UX §8's other two claims) belong to the
// workbench the roadmap defers, and are not pretended here.
func (d RailData) Author() bool { return d.Mode == ModeAuthor }

// ShowNotes reports whether this rail shows the author's presenter
// notes: Presenter does, Author preview does, Guided must not (UX §8).
func (d RailData) ShowNotes() bool { return d.Presenter() || d.Author() }

// stepStatus maps a recorded result to the Verify button's resting state.
// A step never claims more than the engine judged: no result is idle, not
// a pass (invariant 3, and UX §12's founding sin).
func stepStatus(r *state.CheckpointResult) string {
	if r == nil || r.Status == "" {
		return "idle"
	}
	return r.Status
}

// confidence is the Presenter light (UX §6): green when the step's
// checkpoint currently passes, hollow when unknown, amber on a regression
// — a failure the presenter has not been told about any louder way.
func confidence(r *state.CheckpointResult) string {
	switch stepStatus(r) {
	case "pass":
		return "ready"
	case "attested":
		return "attest"
	case "fail", "error":
		return "warn"
	default:
		return "pending"
	}
}

// EvidenceData is the Evidence tab: the checkpoint scoreboard beside the
// journal, with the report download (UX §6).
type EvidenceData struct {
	Instance    string
	Checkpoints []engine.CheckpointView
	// Filter is the chip in force: "", baseline, objective, fail, attest.
	Filter string
}

// JournalData is the evidence journal: GET …/evidence rendered, the twin
// that actually carries the entries. It is its own fragment because the
// scoreboard's twin (…/checkpoints) does not hold them, and a fragment
// may render only what its JSON twin contains (ADR-0003). While the two
// shared one fragment the journal was never filled in by any handler,
// so the Evidence tab showed the latest verdict of each checkpoint and
// none of the runs, seeds, milestones or reveals behind them.
type JournalData struct {
	Instance string
	Entries  []evidence.Entry
}

// Rows applies the filter chip to the scoreboard.
func (d EvidenceData) Rows() []engine.CheckpointView {
	if d.Filter == "" || d.Filter == "all" {
		return d.Checkpoints
	}
	out := []engine.CheckpointView{}
	for _, c := range d.Checkpoints {
		switch d.Filter {
		case "baseline", "objective":
			if c.Class == d.Filter {
				out = append(out, c)
			}
		case "fail":
			if c.Result != nil && (c.Result.Status == "fail" || c.Result.Status == "error") {
				out = append(out, c)
			}
		case "attest":
			if c.Result != nil && c.Result.Status == "attested" {
				out = append(out, c)
			}
		}
	}
	return out
}

// SecretsData is the credential list. Values are structurally absent —
// the twin has none, so the DOM cannot have any before a reveal (UX §6,
// threat model B8).
type SecretsData struct {
	Instance string
	Secrets  []engine.SecretView
	CSRF     string
}

// RevealData is one revealed value and how long it stands.
type RevealData struct {
	Instance string
	Name     string
	Value    string
	// RemaskAfter is the twin's remask_after, verbatim.
	RemaskAfter string
	// Seconds is RemaskAfter as a whole number for the countdown.
	Seconds int
	// CSRF lets the fragment carry its own way back: when the value
	// re-masks, the control that revealed it returns in its place, and
	// that control posts.
	CSRF string
}

// ResetData is the two-column dialog (UX §6): what a reset destroys and
// what survives, computed for this instance by the engine.
type ResetData struct {
	Instance string
	Plan     *engine.ResetPlan
	CSRF     string
}

// StartHere is the Overview's one card (UX §6): exactly one, always
// present, and never a bare spinner — provisioning teaches while it
// waits (Journey §5).
type StartHere struct {
	// State is provisioning, ready, resume, failed or complete.
	State string
	// Headline is the card's one line.
	Headline string
	// Body is the sentence under it: what is happening now, or the lab's
	// story to read while it happens.
	Body string
	// Action is the button, when there is one to offer.
	Action     string
	ActionHRef string
	// Evidence is the completion card's own link. UX §8 asks a finished
	// Guided playbook for "a factual line + evidence link", and the
	// evidence is a tab on this page rather than a rail fragment, so it
	// is not the htmx action Action/ActionHRef render.
	Evidence string
	// Playbook is the playbook the action opens.
	Playbook string
}

// InstanceLive is what the console's live region receives: the ladder
// and the parts of the page the same event changes, so one read keeps
// them all true rather than leaving two of them behind.
type InstanceLive struct {
	Instance  engine.InstanceView
	StartHere StartHere
}

// Tabs is the strip as this instance now stands — a projection of the
// same twin, so the words the tabs carry are refreshed with the ladder
// rather than left at whatever the page was first painted with.
func (d InstanceLive) Tabs() []Tab { return TabsFor(d.Instance) }

// StartHereFor computes the card from the instance twin and its
// playbooks — a projection of both, no new facts.
func StartHereFor(v engine.InstanceView, pbs []engine.PlaybookSummary, p *state.Progress) StartHere {
	first := engine.PlaybookSummary{}
	if len(pbs) > 0 {
		first = pbs[0]
	}
	switch {
	case v.Error != nil:
		return StartHere{State: "failed", Headline: "This lab stopped before it was ready",
			Body: v.Error.Message + " — the error below says what to do next."}
	case v.Ladder.Stage != "ready":
		body := "Podaro is bringing the services up and will not say ready until its baseline checkpoints pass."
		if first.Description != "" {
			body = "While you wait: " + first.Description
		}
		return StartHere{State: "provisioning", Headline: "Setting up — " + v.Ladder.Label, Body: body}
	// A finished playbook is not a playbook to resume. `State` has
	// declared `complete` since round 4 and nothing ever returned it, so
	// a learner who walked every step was told to resume the lab they had
	// just finished — while UX §8 asks Guided for a factual completion
	// line and its evidence link, and the manual promises the attendee
	// exactly that ("Finishing produces your completion evidence in the
	// Evidence tab"). A comment that says what the code does not do.
	//
	// Guided, for the reason round 27 gated Resume: a completion read out
	// of the progress record is a claim about that record, and UX §8
	// keeps a persisted one for Guided alone.
	case finished(first, p) && Declares(first, ModeGuided):
		return StartHere{State: "complete",
			Headline: "Finished: " + first.Title,
			Body:     "Every step is recorded — " + tally(p) + ". Your completion evidence is in the Evidence tab.",
			Evidence: "Your evidence", Playbook: first.Name}
	// Resume is a Guided claim. "Your progress is kept on the instance"
	// is true of Guided alone: UX §8 makes Presenter progress
	// per-rehearsal and discardable, and Author preview's `n/a`. So a
	// playbook with stored progress that this console can only open in
	// one of those gets the Begin card into that manner, not a Resume
	// card that promises what the manner does not keep.
	//
	// I wrote the rule in round 26 — "a card that reads Resume must not
	// open into Author preview" — and applied it to which manner the
	// card *prefers*, not to which card the manner *earns*. The
	// Presenter fallback had been making the same false promise since
	// round 5.
	case started(first, p) && Declares(first, ModeGuided) && openHRef(v.Name, first, v.Mode) != "":
		return StartHere{State: "resume", Headline: "Resume at " + p.CurrentStep,
			Body:   "Your progress is kept on the instance.",
			Action: "Resume", ActionHRef: openHRef(v.Name, first, v.Mode), Playbook: first.Name}
	case first.Name != "" && openHRef(v.Name, first, v.Mode) != "":
		return StartHere{State: "ready", Headline: "Begin: " + first.Title,
			Body:   first.Description,
			Action: "Begin", ActionHRef: openHRef(v.Name, first, v.Mode), Playbook: first.Name}
	case first.Name != "":
		// The playbook exists and declares no manner this console opens
		// — repro-only, say. The card said Begin and pointed at nothing,
		// which htmx fetches as the current page into the rail: the
		// chooser's dead anchor, one level up, and missed when the
		// chooser's was fixed.
		return StartHere{State: "ready", Headline: "This lab is ready",
			Body: first.Title + " runs in " + join(first.Modes) + ", which this console does not open; the CLI runs it."}
	default:
		return StartHere{State: "ready", Headline: "This lab is ready", Body: "It ships no playbook; the product tabs are yours to explore."}
	}
}

// PlaybooksData is the rail's chooser: the playbooks a lab ships and the
// instance they belong to, so each row can offer to open itself. Without
// the instance the rows were headings with no way in, and the only link
// on the page opened the first playbook in Guided — so a lab's second
// playbook, and the Presenter mode Manual §3 documents, could not be
// reached from the console at all.
type PlaybooksData struct {
	Instance string
	// Mode is the instance's mode, not a playbook's manner: Author
	// preview belongs to an authoring instance and to no other, and the
	// engine enforces that, so offering the link on a delivery instance
	// would be offering a refusal.
	Mode      string
	Playbooks []engine.PlaybookSummary
}

// Rows pairs each playbook with the links that open it — one per manner
// the playbook declares, and no others.
//
// The Open link opens the rail in Guided, because that is the endpoint's
// default. Rendering it unconditionally offered Guided for a playbook
// whose metadata.modes does not list it — a presenter-only demo script
// is the obvious case, and spec 0001 allows it — and the engine served
// the manner rather than refusing, so the console was the thing in the
// wrong. A summary that declares no
// manners at all reads back with all three (see engine.summarize), so
// the common case is unchanged.
func (d PlaybooksData) Rows() []PlaybookRow {
	out := make([]PlaybookRow, 0, len(d.Playbooks))
	for _, pb := range d.Playbooks {
		href := railHref(d.Instance, pb.Name)
		row := PlaybookRow{PlaybookSummary: pb}
		if Declares(pb, ModeGuided) {
			row.HRef = href
		}
		if Declares(pb, ModePresenter) {
			row.PresenterHRef = href + "?mode=presenter"
		}
		// Author preview is the authoring instance's own surface (UX §8),
		// which railMode has always accepted and nothing ever linked to.
		// It is not a manner a playbook declares — it is a manner the
		// instance is in — so it is not gated on metadata.modes.
		if d.Mode == "authoring" {
			row.AuthorHRef = href + "?mode=author"
		}
		out = append(out, row)
	}
	return out
}

// declares reports whether a playbook offers this manner.
//
// Exported because the render path consults it too: the chooser hiding a
// link is not a rule, and `?mode=presenter` served a manner the playbook
// never declared until the same predicate decided that as well.
//
// A summary that lists no manners at all offers every one, which is the
// engine's own rule: metadata.modes is optional and summarize fills in
// guided, presenter and repro when a playbook omits it. Reading an empty
// list as "none" instead would take the links away from exactly the
// playbooks that asked for no restriction (found when round 7's
// start-here guard turned round 4's Resume case red — its fixture, like
// any summary built by hand, declares no modes).
func Declares(pb engine.PlaybookSummary, mode string) bool {
	if len(pb.Modes) == 0 {
		return true
	}
	for _, m := range pb.Modes {
		if m == mode {
			return true
		}
	}
	return false
}

// openHRef is the way in the start-here card offers: the playbook's
// Guided rail when it has one, its Presenter rail when Guided is not a
// manner it declares, and — on an authoring instance — Author preview
// when it declares neither. Same rule as the chooser's rows, one level
// up: the card was offering Begin into a manner a presenter-only
// playbook does not have, and then saying the console does not open a
// playbook the chooser on the same page offers a link to.
//
// Author preview is not a manner a playbook declares; it is a manner the
// instance is in (round 6), so the mode is what admits it. It is the
// *fallback* rather than the preference, because UX §8 gives Author
// preview free navigation and no persisted progress: a card that reads
// "Resume at <step>" must not open into a manner where progress is n/a.
// Where the playbook declares a manner the console opens, the card keeps
// it and the chooser's Author link, beside it on the same page, is the
// way into the preview (which asked for the preference; this is the half of it §8 allows).
func openHRef(instance string, pb engine.PlaybookSummary, instanceMode string) string {
	href := railHref(instance, pb.Name)
	switch {
	case href == "":
		return ""
	case Declares(pb, ModeGuided):
		return href
	case Declares(pb, ModePresenter):
		return href + "?mode=presenter"
	case instanceMode == "authoring":
		return href + "?mode=author"
	default:
		return ""
	}
}

// PlaybookRow is one playbook and the way in.
type PlaybookRow struct {
	engine.PlaybookSummary
	HRef string
	// PresenterHRef is set only where the playbook declares the mode: a
	// link to a mode a playbook does not offer is a link to a refusal.
	PresenterHRef string
	// AuthorHRef is set only on an authoring instance — Author preview
	// is the instance's manner, not the playbook's.
	AuthorHRef string
}

func railHref(instance, playbook string) string {
	if playbook == "" {
		return ""
	}
	return "/api/v1alpha1/instances/" + instance + "/playbooks/" + playbook
}

// started reports whether this learner is mid-lab, which is the whole of
// the difference between Resume and Begin.
//
// Progress that was never written still reads back — Engine.Progress
// synthesises a record sitting on the playbook's first step — so the
// presence of a position proves nothing. Two things do: a position that
// has moved off that first step, or a step that has earned a verdict.
//
// The verdict half alone was the round-3 rule, and it was wrong for the
// shipped first-dashboard playbook, whose first step declares no
// checkpoint: a learner who walked from it to the next step and came
// back the next morning was told to Begin, while the instance held the
// position they had left.
func started(first engine.PlaybookSummary, p *state.Progress) bool {
	if p == nil || p.CurrentStep == "" {
		return false
	}
	if first.FirstStep != "" && p.CurrentStep != first.FirstStep {
		return true
	}
	return countDone(p) > 0
}

// finished reports that every step of this playbook carries a recorded
// outcome. Gating is soft (UX §8), so "finished" means walked, never
// passed — a lab can be finished with red in it, and the tally below is
// how the card says so instead of implying otherwise.
func finished(first engine.PlaybookSummary, p *state.Progress) bool {
	return p != nil && first.Steps > 0 && countDone(p) >= first.Steps
}

// tally counts the recorded outcomes in the words the result lines use.
// It is the engine's own record, read back — never a verdict of the
// card's own (UX §12: nothing claims a success the engine has not
// verified). The words come from `statusWord`, which is the vocabulary
// the rail, the scoreboard and the spine all use; there is not a second
// one.
func tally(p *state.Progress) string {
	counts := map[string]int{}
	for _, s := range p.Steps {
		if s.Status == "" || s.Status == "pending" {
			continue
		}
		counts[s.Status]++
	}
	parts := []string{}
	for _, status := range []string{"pass", "attested", "fail", "error", "skipped"} {
		n := counts[status]
		if n == 0 {
			continue
		}
		word := statusWord(&state.CheckpointResult{Status: status})
		if status == "skipped" {
			// The engine's own meaning: a step with no checkpoint, which
			// `PutProgress` records as skipped and nothing else. Saying
			// "not verified yet" of a narrative step would imply work the
			// learner left undone.
			word = "with nothing to verify"
		}
		parts = append(parts, strconv.Itoa(n)+" "+word)
	}
	if len(parts) == 0 {
		return "nothing judged"
	}
	return strings.Join(parts, ", ")
}

func countDone(p *state.Progress) int {
	n := 0
	for _, s := range p.Steps {
		if s.Status != "" && s.Status != "pending" {
			n++
		}
	}
	return n
}

// TabsFor builds the tab strip: Overview first, Evidence last, products
// between in ladder order (UX §6). A product that cannot be framed gets
// the Open ↗ card, never a broken iframe.
func TabsFor(v engine.InstanceView) []Tab {
	tabs := []Tab{{ID: "overview", Label: "Overview", Kind: "overview"}}
	for _, s := range v.Services {
		if s.URL == "" {
			continue
		}
		t := Tab{ID: s.Name, Label: s.Name, Kind: "iframe", URL: s.URL, Stage: s.Stage, Word: s.Word}
		switch s.Embed {
		case "newtab":
			t.Kind = "newtab"
			t.Reason = "This product refuses to be framed; it opens in its own tab."
		case "api-only", "none":
			continue
		}
		tabs = append(tabs, t)
	}
	return append(tabs, Tab{ID: "evidence", Label: "Evidence", Kind: "evidence"})
}

// Tab is one entry of the strip.
type Tab struct {
	ID     string
	Label  string
	Kind   string // overview, iframe, newtab, evidence
	URL    string
	Stage  string
	Word   string
	Reason string
}

// itoa avoids pulling strconv into the template funcs for two uses.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// seconds renders a Go duration string as whole seconds for the reveal
// countdown; it reads the twin's own remask_after rather than a constant.
func seconds(d string) int {
	v, err := time.ParseDuration(strings.TrimSpace(d))
	if err != nil {
		return 0
	}
	return int(v.Seconds())
}

// LabData is the instance page: everything the lab surface draws at once
// — the ladder, the one start-here card, the tab strip and its panels,
// and the rail's region. Each field is a twin the console could fetch on
// its own; assembling them server-side is what spares the first paint a
// round trip per region (UX §11: first paint under a second on a LAN).
type LabData struct {
	Instance  engine.InstanceView
	StartHere StartHere
	Tabs      []Tab
	Playbooks []engine.PlaybookSummary
	// Rail is the opened playbook, when one is. A page with none renders
	// the rail's region empty rather than absent, so the region a later
	// fragment swaps into is already in the document.
	Rail *RailData
	CSRF string
}

// PlaybooksData is the chooser this page's rail shows when no playbook
// is open.
func (d LabData) PlaybooksData() PlaybooksData {
	return PlaybooksData{Instance: d.Instance.Name, Mode: d.Instance.Mode, Playbooks: d.Playbooks}
}

// Authoring says whether the instance wears the authoring chip (UX §6:
// a quiet fact in the status bar, never chromatic — it is not an alarm).
func (d LabData) Authoring() bool { return d.Instance.Mode == "authoring" }
