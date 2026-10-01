// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// `StartHere.State` has declared `complete` since round 4 and nothing
// ever returned it. A learner who walked every step was told to resume
// the lab they had just finished, while UX §8 asks Guided for a factual
// completion line and its evidence link, and the manual promises the
// attendee exactly that. A comment that said what the code did not do.
func TestAFinishedPlaybookIsNotAPlaybookToResume(t *testing.T) {
	ready := engine.LadderView{Stage: "ready", Label: "ready"}
	v := engine.InstanceView{Name: "pii-lab", Mode: "delivery", Ladder: ready}
	pbs := []engine.PlaybookSummary{{Name: "pii-redaction", Title: "PII Redaction",
		Modes: []string{"guided"}, Steps: 3, FirstStep: "one"}}

	// Two of three walked: still mid-lab.
	part := &state.Progress{Instance: "pii-lab", Playbook: "pii-redaction", CurrentStep: "three",
		Steps: map[string]state.StepProgress{"one": {Status: "pass"}, "two": {Status: "fail"}}}
	if got := StartHereFor(v, pbs, part); got.State != "resume" {
		t.Fatalf("a lab with a step left is not mid-lab: %+v", got)
	}

	// All three: finished. Gating is soft, so a finished lab may hold a
	// failure — the card says what is recorded and claims nothing more.
	done := &state.Progress{Instance: "pii-lab", Playbook: "pii-redaction", CurrentStep: "three",
		Steps: map[string]state.StepProgress{
			"one": {Status: "pass"}, "two": {Status: "fail"}, "three": {Status: "attested"}}}
	card := StartHereFor(v, pbs, done)
	if card.State != "complete" {
		t.Fatalf("a walked playbook still says %q: %+v", card.State, card)
	}
	if !strings.Contains(card.Headline, "PII Redaction") {
		t.Errorf("the completion line does not name the playbook: %q", card.Headline)
	}
	for _, part := range []string{"1 passed", "1 self-verified", "1 failed"} {
		if !strings.Contains(card.Body, part) {
			t.Errorf("the completion line does not record %q: %q", part, card.Body)
		}
	}
	for _, claim := range []string{"passed the lab", "Well done", "Congratulations", "complete!"} {
		if strings.Contains(card.Body, claim) {
			t.Errorf("the completion line claims %q, which the engine did not judge: %q", claim, card.Body)
		}
	}
	if card.Evidence == "" {
		t.Errorf("UX §8 asks a finished playbook for its evidence link: %+v", card)
	}
	if card.Action != "" {
		t.Errorf("the completion card offers a rail action as well: %+v", card)
	}

	// And the link is the control that selects the tab, not a fetch into
	// the rail — the evidence is a panel on this page.
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.Fragment(FragmentStartHere, card)
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	if !strings.Contains(html, `data-tab-link="evidence"`) || !strings.Contains(html, `href="#panel-evidence"`) {
		t.Errorf("the evidence link does not select the Evidence tab:\n%s", html)
	}
	if strings.Contains(html, `hx-target="#rail"`) {
		t.Errorf("the completion card fetches something into the rail:\n%s", html)
	}

	// A presenter-only playbook keeps round 27's rule: its progress is
	// per-rehearsal and discardable (UX §8), so nothing is read out of it.
	demo := []engine.PlaybookSummary{{Name: "demo", Title: "Demo", Modes: []string{"presenter"}, Steps: 3, FirstStep: "one"}}
	if got := StartHereFor(v, demo, done); got.State == "complete" {
		t.Errorf("a presenter-only playbook reports completion from a discardable record: %+v", got)
	}
}
