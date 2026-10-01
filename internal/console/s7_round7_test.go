// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// The chooser's dead anchor, one level up and missed when the chooser's
// was fixed. `openHRef` returns "" for a first playbook the console
// cannot open, and the card set Action anyway — so the primary
// start-here control rendered `href=""` and `hx-get=""`, which htmx
// fetches as the current page into the rail.
func TestTheStartHereCardOffersNoActionItCannotPerform(t *testing.T) {
	v := engine.InstanceView{Name: "pii-lab", Ladder: engine.LadderView{Stage: "ready", Label: "ready"}}
	repro := []engine.PlaybookSummary{{Name: "repro-only", Title: "Repro only", Modes: []string{"repro"}, FirstStep: "one"}}

	card := StartHereFor(v, repro, nil)
	if card.Action != "" || card.ActionHRef != "" {
		t.Errorf("the card offers %q → %q for a playbook this console cannot open", card.Action, card.ActionHRef)
	}
	if card.Headline == "" || card.Body == "" {
		t.Errorf("the card says nothing instead: %+v", card)
	}

	// Same for the Resume branch: a learner mid-lab in a playbook the
	// console cannot open is still not offered a link to nowhere.
	p := &state.Progress{Instance: "pii-lab", Playbook: "repro-only", CurrentStep: "two",
		Steps: map[string]state.StepProgress{}}
	if resume := StartHereFor(v, repro, p); resume.ActionHRef == "" && resume.Action != "" {
		t.Errorf("the Resume branch offers %q with no href", resume.Action)
	}

	// And the template never emits an empty href even if a caller sets
	// one half without the other.
	r, _ := New()
	got, err := r.Fragment(FragmentStartHere, StartHere{State: "ready", Headline: "Ready", Body: "b", Action: "Begin"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), `href=""`) || strings.Contains(string(got), `hx-get=""`) {
		t.Errorf("the start-here card renders a link to nowhere:\n%s", got)
	}
}

// A checkpoint request that answers with an error envelope is swapped
// like any other response (the page's htmx config swaps every code, so
// an error is shown rather than swallowed). With outerHTML that replaced
// `#result-<step>` with a panel carrying no such id, and the Verify
// button beside it then pointed at nothing: once the transient condition
// cleared — a reset holding the exclusive slot, say — the step could not
// be retried without reopening the rail.
func TestAFailedRequestLeavesTheVerifyTargetStanding(t *testing.T) {
	r, _ := New()
	pb := fixturePlaybook()
	got, err := r.Fragment(FragmentRail, RailData{Instance: "pii-lab", Mode: ModeGuided,
		Playbook: pb, Results: map[string]engine.CheckpointView{}, CSRF: "csrf-token"})
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	// The id belongs to a wrapper the swap goes *inside*, so whatever
	// comes back — a result or an error — the target survives it.
	if !strings.Contains(html, `<div class="result-region" id="result-mask-them">`) {
		t.Errorf("the result id is not on a wrapper the swap can go inside:\n%s",
			around(html, `result-mask-them`, 260))
	}
	// And the line inside it does not also carry the id, or a swap would
	// leave two elements answering to the same one.
	if strings.Contains(html, `<p class="result status-idle" id="result-mask-them"`) {
		t.Errorf("the result line still owns the id as well as its wrapper")
	}
	if !strings.Contains(html, `hx-target="#result-mask-them" hx-swap="innerHTML"`) {
		t.Errorf("Verify still replaces its own target instead of filling it:\n%s", around(html, `class="verify"`, 600))
	}
}

// Checkpoints live on the template and a playbook's steps reference
// them, so two steps can name the same one — CheckpointView.Steps is the
// engine saying which. Verifying from one step updated only that step's
// result, so one rail could show two different verdicts for the same
// checkpoint at the same time.
func TestOneVerdictReachesEveryStepThatSharesTheCheckpoint(t *testing.T) {
	// Qualified `playbook/step`, which is the shape lab.instance builds
	// and the engine returns. This fixture said bare ids when it was
	// written, so the round-7 fix it "proved" was inert — every swap was
	// aimed at an id no page has (round 9 found it).
	cp := &engine.CheckpointView{ID: "no-ssn-in-index", Class: "objective", Adapter: "http",
		Steps: []string{"pii-redaction/mask-them", "pii-redaction/check-again", "pii-redaction/confirm"}}
	res := &state.CheckpointResult{ID: "no-ssn-in-index", Class: "objective", Status: "fail", At: at(2), Duration: "1.4s"}

	line := NewResultLine("pii-lab", "pii-redaction", "mask-them", res, cp)
	if got := line.Also; len(got) != 2 || got[0] != "check-again" || got[1] != "confirm" {
		t.Errorf("the verdict names %v as the other steps sharing it; want [check-again confirm]", got)
	}

	r, _ := New()
	got, err := r.Fragment(FragmentResult, line)
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	for _, other := range []string{"check-again", "confirm"} {
		want := `id="result-` + other + `" hx-swap-oob="innerHTML"`
		if !strings.Contains(html, want) {
			t.Errorf("the verdict does not reach step %q (%s):\n%s", other, want, html)
		}
	}
	// The step that asked for it is not also swapped out of band — that
	// is the response body itself, and doing both would swap it twice.
	if strings.Contains(html, `id="result-mask-them" hx-swap-oob`) {
		t.Errorf("the asking step is swapped twice:\n%s", html)
	}
	// A checkpoint only one step names carries no out-of-band swaps.
	solo := NewResultLine("pii-lab", "pii-redaction", "mask-them", res,
		&engine.CheckpointView{ID: "no-ssn-in-index", Steps: []string{"pii-redaction/mask-them"}})
	if out, _ := r.Fragment(FragmentResult, solo); strings.Contains(string(out), "hx-swap-oob") {
		t.Errorf("a checkpoint with one step swaps something out of band:\n%s", out)
	}
}
