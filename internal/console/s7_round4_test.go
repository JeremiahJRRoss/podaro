// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// Review round 4, the console's three findings.

// A Presenter re-check swapped the result line and sent the title light
// out of band, and left the quiet status paragraph beside them saying
// what it said when the rail opened. So a checkpoint that regressed
// mid-demo showed an amber light, a failed result, and a line reading
// "<checkpoint> · pass" between them — the stale green the re-check
// exists to prevent, wearing different clothes.
func TestAPresenterRecheckRefreshesTheQuietStatusLineToo(t *testing.T) {
	r, _ := New()
	cp := &engine.CheckpointView{ID: "traffic-observed", Class: "objective", Adapter: "http"}
	failed := &state.CheckpointResult{ID: "traffic-observed", Class: "objective", Status: "fail", At: at(2), Duration: "1.4s"}
	got, err := r.Fragment(FragmentResult, NewPresenterResultLine("intro", "first-dashboard", "drive-real-traffic", failed, cp))
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	// The light already comes along out of band (round 3).
	if !strings.Contains(html, `id="light-drive-real-traffic" hx-swap-oob="true"`) {
		t.Fatalf("the light is not swapped out of band:\n%s", html)
	}
	// The quiet line must come with it, and must carry the new verdict.
	i := strings.Index(html, `id="quiet-drive-real-traffic"`)
	if i < 0 {
		t.Fatalf("the quiet status line is not refreshed with the verdict:\n%s", html)
	}
	line := html[i:min(len(html), i+220)]
	if !strings.Contains(line, `hx-swap-oob="true"`) {
		t.Errorf("the quiet line is in the response but not swapped out of band:\n%s", line)
	}
	if !strings.Contains(line, "traffic-observed") || !strings.Contains(line, "fail") {
		t.Errorf("the quiet line does not read the checkpoint and its new verdict:\n%s", line)
	}
	if strings.Contains(line, "pass") {
		t.Errorf("the quiet line still says pass after a failing re-check:\n%s", line)
	}
}

// Guided's rail could only be walked from the keyboard: `[` and `]` were
// the only code that moved `current`, so a pointer or touch user could
// read every card but never advance the position that is saved on the
// instance. UX §8's Guided row names the control that was missing —
// "soft: red persists, Next stays enabled".
func TestTheRailCanBeWalkedWithAPointer(t *testing.T) {
	r, _ := New()
	got, err := r.Fragment(FragmentRail, RailData{Instance: "intro", Mode: ModeGuided,
		Playbook: fixturePlaybook(), Results: map[string]engine.CheckpointView{}, CSRF: "csrf-token"})
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	for _, want := range []string{`class="button step-nav" type="button" data-step-move="-1"`, `data-step-move="1"`} {
		if !strings.Contains(html, want) {
			t.Errorf("the rail has no pointer control matching %q — a mouse user cannot advance:\n%s", want, html)
		}
	}
	// Soft gating: the control is never disabled, whatever a step's
	// result was (UX §8).
	if strings.Contains(html, `step-nav" type="button" disabled`) {
		t.Errorf("a step-nav control is disabled; UX §8 says Next stays enabled")
	}
}

// The start-here card offered "Begin" to a learner who had already
// walked into the lab. Resume was guarded on some step having a terminal
// status, but the first step of the shipped first-dashboard playbook
// declares no checkpoint: advancing off it and reloading left the count
// at zero, so the card sent the learner back to the beginning and hid
// the position the instance had faithfully saved.
func TestResumeIsOfferedWhenTheSavedStepHasMovedOn(t *testing.T) {
	v := engine.InstanceView{Name: "intro", Ladder: engine.LadderView{Stage: "ready", Label: "ready"}}
	pbs := []engine.PlaybookSummary{{Name: "first-dashboard", Title: "Your first dashboard", Steps: 4, FirstStep: "meet-the-stack"}}

	moved := &state.Progress{Instance: "intro", Playbook: "first-dashboard", CurrentStep: "drive-real-traffic",
		Steps: map[string]state.StepProgress{}}
	if got := StartHereFor(v, pbs, moved); got.State != "resume" {
		t.Errorf("a learner two steps in is offered %q (%q); want resume", got.State, got.Action)
	}

	// And the guard it replaces still holds: an untouched instance sits
	// on the playbook's own first step, and that is not a resume.
	fresh := &state.Progress{Instance: "intro", Playbook: "first-dashboard", CurrentStep: "meet-the-stack",
		Steps: map[string]state.StepProgress{}}
	if got := StartHereFor(v, pbs, fresh); got.State != "ready" {
		t.Errorf("an untouched lab offers %q; want ready (Begin)", got.State)
	}

	// A verdict earned on the first step is a start too, even though the
	// position has not moved.
	judged := &state.Progress{Instance: "intro", Playbook: "first-dashboard", CurrentStep: "meet-the-stack",
		Steps: map[string]state.StepProgress{"meet-the-stack": {Status: "pass"}}}
	if got := StartHereFor(v, pbs, judged); got.State != "resume" {
		t.Errorf("a lab with a judged step offers %q; want resume", got.State)
	}
}
