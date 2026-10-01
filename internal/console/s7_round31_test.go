// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// Round 30's completion card could not appear for either shipped
// playbook. A step with no checkpoint has nothing to verify, so nothing
// was ever recorded for it — `first-dashboard` has four steps and two
// checkpoints — and the count never reached the total.
//
// The engine already had the answer and said so in its own refusal:
// "step X has no checkpoint: only skipped can be recorded for it".
// `PutProgress` has taken `skipped` since S6; the console never wrote
// it. So the tally has to say what that means, in words that do not
// imply work left undone.
func TestAWalkedStepWithNothingToVerifyCounts(t *testing.T) {
	ready := engine.LadderView{Stage: "ready", Label: "ready"}
	v := engine.InstanceView{Name: "lab", Mode: "delivery", Ladder: ready}
	// The shape of the shipped playbook: four steps, two checkpoints.
	pbs := []engine.PlaybookSummary{{Name: "first-dashboard", Title: "Your First Verified Dashboard",
		Modes: []string{"guided"}, Steps: 4, FirstStep: "meet-the-stack"}}
	walked := &state.Progress{Instance: "lab", Playbook: "first-dashboard", CurrentStep: "leave-with-receipts",
		Steps: map[string]state.StepProgress{
			"meet-the-stack":      {Status: "skipped"},
			"drive-real-traffic":  {Status: "pass"},
			"build-a-dashboard":   {Status: "fail"},
			"leave-with-receipts": {Status: "skipped"},
		}}
	card := StartHereFor(v, pbs, walked)
	if card.State != "complete" {
		t.Fatalf("a playbook whose narrative steps are walked still says %q: %+v", card.State, card)
	}
	if !strings.Contains(card.Body, "2 with nothing to verify") {
		t.Errorf("the tally does not say what a walked narrative step is: %q", card.Body)
	}
	if strings.Contains(card.Body, "not verified yet") {
		t.Errorf("the tally implies work the learner left undone: %q", card.Body)
	}
	for _, want := range []string{"1 passed", "1 failed"} {
		if !strings.Contains(card.Body, want) {
			t.Errorf("the tally lost %q: %q", want, card.Body)
		}
	}

	// One narrative step not yet reached is not a finished playbook.
	short := &state.Progress{Instance: "lab", Playbook: "first-dashboard", CurrentStep: "build-a-dashboard",
		Steps: map[string]state.StepProgress{
			"meet-the-stack":     {Status: "skipped"},
			"drive-real-traffic": {Status: "pass"},
			"build-a-dashboard":  {Status: "fail"},
		}}
	if got := StartHereFor(v, pbs, short); got.State == "complete" {
		t.Errorf("a playbook with a step still unwalked reports completion: %+v", got)
	}

	// And the rail tells the page which steps have something to verify,
	// because the page cannot tell from a control's absence — that has
	// several causes and this has one.
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	data := RailData{Instance: "lab", Mode: ModeGuided,
		Playbook: engine.PlaybookView{
			PlaybookSummary: engine.PlaybookSummary{Name: "p", Title: "P", Steps: 2},
			StepList: []engine.StepView{
				{ID: "read-this", Title: "Read this", Body: "words"},
				{ID: "do-this", Title: "Do this", Body: "words", Checkpoint: &engine.StepCheckpoint{ID: "judged", Class: "objective", Adapter: "http"}},
			}},
		Results: map[string]engine.CheckpointView{"judged": {ID: "judged", Class: "objective", Adapter: "http"}},
	}
	out, err := r.Fragment(FragmentRail, data)
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	if !strings.Contains(html, `data-step="do-this" data-checkpoint="judged"`) {
		t.Errorf("a step with a checkpoint does not name it:\n%s", html)
	}
	if strings.Contains(html, `data-step="read-this" data-checkpoint`) {
		t.Errorf("a step with nothing to verify claims a checkpoint:\n%s", html)
	}
}
