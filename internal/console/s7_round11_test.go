// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/engine"
)

// Round 9 gave a standalone seed press a receipt, and `receipt()` writes
// it into `.actions .auto-reveals` — a region only the *auto* branch of
// the template renders. A real non-auto seed step has no such element,
// so every receipt, success and refusal alike, was dropped on the floor.
// The fix was inert for the control it was written for.
//
// The browser check did not catch it because it synthesised the region
// itself: it proved the handler writes a receipt, never that the page
// has anywhere to put one. That is round 7's mistake again — a test
// built on a shape the shipped template does not produce — so this one
// asserts the shipped template, and the walk keeps proving the handler.
func TestAStandaloneSeedStepHasSomewhereToPutItsReceipt(t *testing.T) {
	r, _ := New()
	pb := fixturePlaybook() // send-events declares a seed and is not auto
	got, err := r.Fragment(FragmentRail, RailData{Instance: "pii-lab", Mode: ModeGuided,
		Playbook: pb, Results: map[string]engine.CheckpointView{}, CSRF: "csrf-token"})
	if err != nil {
		t.Fatal(err)
	}
	step := oneStep(string(got), "send-events")
	if step == "" {
		t.Fatal("no seed step in the fixture rail")
	}
	if !strings.Contains(step, "seed-button") {
		t.Fatalf("the fixture step no longer renders a standalone seed:\n%s", step)
	}
	if !strings.Contains(step, `class="action-output"`) {
		t.Errorf("a standalone seed has nowhere to report what it did:\n%s", step)
	}

	// And the auto branch has one too — it is where a revealed value
	// lands, and both now use the same region under the same name,
	// because "auto-reveals" stopped being true the moment a plain seed
	// wrote to it.
	pb2 := fixturePlaybook()
	for i := range pb2.StepList {
		if len(pb2.StepList[i].Actions) > 0 {
			pb2.StepList[i].Auto = true
		}
	}
	auto, _ := r.Fragment(FragmentRail, RailData{Instance: "pii-lab", Mode: ModeGuided,
		Playbook: pb2, Results: map[string]engine.CheckpointView{}, CSRF: "csrf-token"})
	if !strings.Contains(oneStep(string(auto), "send-events"), `class="action-output"`) {
		t.Errorf("an auto step lost the region its reveals land in")
	}
	if strings.Contains(string(auto), "auto-reveals") {
		t.Errorf("the old region name survives somewhere; the two paths must share one")
	}
}
