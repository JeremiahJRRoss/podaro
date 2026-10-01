// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/engine"
)

// The round-3 integrity bug, back through a different door. There it was
// the Presenter light's timer: `RailStep.Action` resolves an attest
// checkpoint to `…/attest`, so anything that posts it on its own records
// a human's confirmation with no human. `Rechecks` closed that door for
// the timer; round 6's one control walked through the other one, posting
// the same endpoint after an auto step's actions.
//
// A human's claim is earned once, by a human, or it is not a human's
// claim. The one control runs the actions and stops; the step keeps its
// own "I confirm this", which is the only thing that may attest.
func TestAnAutoStepNeverAttestsOnTheLearnersBehalf(t *testing.T) {
	r, _ := New()
	pb := fixturePlaybook()
	var attestStep string
	for i := range pb.StepList {
		if pb.StepList[i].Checkpoint != nil && pb.StepList[i].Checkpoint.Adapter == "attest" {
			pb.StepList[i].Auto = true
			pb.StepList[i].Actions = []engine.ActionView{{Seed: "events", Label: "Send"}}
			attestStep = pb.StepList[i].ID
		}
	}
	if attestStep == "" {
		t.Fatal("the fixture playbook declares no attest checkpoint")
	}
	got, err := r.Fragment(FragmentRail, RailData{Instance: "pii-lab", Mode: ModeGuided,
		Playbook: pb, Results: map[string]engine.CheckpointView{}, CSRF: "csrf-token"})
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	// The button element itself, and nothing after it: the verify block
	// below it carries the human's own attest control, which is exactly
	// the thing that *may* post there.
	control := around(html, `class="button primary run-step"`, 500)
	if control == "" {
		t.Fatalf("the auto step lost its one control:\n%s", html)
	}
	if end := strings.Index(control, "</button>"); end >= 0 {
		control = control[:end]
	} else {
		t.Fatalf("the one control's markup does not close inside the window:\n%s", control)
	}
	if strings.Contains(control, "/attest") {
		t.Errorf("the one control posts a human's confirmation on its own:\n%s", control)
	}
	if !strings.Contains(control, `data-action=""`) {
		t.Errorf("the one control still carries a verification to post:\n%s", control)
	}
	// The actions still run, and the human's control is still there.
	if !strings.Contains(control, `data-actions="seed:events"`) {
		t.Errorf("the one control stopped running the step's actions:\n%s", control)
	}
	if !strings.Contains(html, "I confirm this") {
		t.Errorf("the step lost the control only a human may press:\n%s", html)
	}
}

// Spec 0001 line 80: `duration` is "advisory pacing · presenter-visible
// only". Every step in both shipped playbooks declares one, the value
// reached RailStep, and no template ever rendered it — so a presenter
// pacing a walkthrough lost the timing its author wrote for them.
func TestPresenterSeesTheAuthoredPacing(t *testing.T) {
	r, _ := New()
	pb := fixturePlaybook()
	pb.StepList[0].Duration = "3m"
	frag := func(mode string) string {
		got, err := r.Fragment(FragmentRail, RailData{Instance: "pii-lab", Mode: mode,
			Playbook: pb, Results: map[string]engine.CheckpointView{}, CSRF: "csrf-token"})
		if err != nil {
			t.Fatal(err)
		}
		return string(got)
	}
	if !strings.Contains(frag(ModePresenter), "3m") {
		t.Errorf("Presenter does not show the authored pacing")
	}
	// "presenter-visible only" is the spec's own words: a learner is not
	// shown a clock they are being measured against.
	if strings.Contains(frag(ModeGuided), ">3m<") {
		t.Errorf("Guided shows the pacing spec 0001 makes presenter-visible only")
	}
	// Author preview reads the playbook as its author wrote it, notes
	// and pacing together.
	if !strings.Contains(frag(ModeAuthor), "3m") {
		t.Errorf("Author preview does not show the authored pacing")
	}
}

// Self-review of the round-8 fix. Making AutoAction empty for an attest
// checkpoint left `Runs` unchanged — and `Runs` says the one control has
// something to do when the step has a checkpoint, *any* checkpoint. So
// an auto step whose only work is an attest checkpoint now renders "Run
// this step" with no action and no actions: a control whose whole
// behaviour is to do nothing, which is the round-5 finding again, made
// by the round-8 fix.
func TestAnAutoAttestStepWithNoActionsOffersNoDeadControl(t *testing.T) {
	r, _ := New()
	pb := fixturePlaybook()
	var id string
	for i := range pb.StepList {
		if pb.StepList[i].Checkpoint != nil && pb.StepList[i].Checkpoint.Adapter == "attest" {
			pb.StepList[i].Auto = true
			pb.StepList[i].Actions = nil
			id = pb.StepList[i].ID
		}
	}
	if id == "" {
		t.Fatal("the fixture playbook declares no attest checkpoint")
	}
	got, err := r.Fragment(FragmentRail, RailData{Instance: "pii-lab", Mode: ModeGuided,
		Playbook: pb, Results: map[string]engine.CheckpointView{}, CSRF: "csrf-token"})
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	if strings.Contains(html, "run-step") {
		t.Errorf("an auto attest step with no actions still offers a control that does nothing:\n%s",
			around(html, `id="step-`+id, 900))
	}
	// The human's control is still the way the step is completed.
	if !strings.Contains(html, "I confirm this") {
		t.Errorf("the step lost the control only a human may press")
	}
}
