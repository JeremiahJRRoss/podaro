// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// UX §6: "Collapsed rail shows a slim progress spine (seven-ish dots)
// with the current step title." Round 6 made `r` collapse the rail on
// the desktop layout, which it had not done at all, and collapsed it to
// `display: none` — an absent rail rather than a collapsed one. The
// learner lost every trace of their position, and there was no visible
// control to bring it back.
//
// The spine is the template's, rendered always and shown by the
// stylesheet when the rail is closed, so it survives a swap and needs no
// second render. It is also the way back, which is why it is a button.
func TestTheCollapsedRailKeepsItsProgressSpine(t *testing.T) {
	r, _ := New()
	pb := fixturePlaybook()
	prog := &state.Progress{Instance: "pii-lab", Playbook: "pii-redaction", CurrentStep: "mask-them",
		Steps: map[string]state.StepProgress{"send-events": {Status: "pass"}}}
	rail, err := r.Fragment(FragmentRail, RailData{Instance: "pii-lab", Mode: ModeGuided,
		Playbook: pb, Progress: prog, Results: map[string]engine.CheckpointView{}, CSRF: "t"})
	if err != nil {
		t.Fatal(err)
	}
	html := string(rail)
	tag := openTag(html, `class="rail-spine"`)
	if tag == "" {
		t.Fatalf("the rail renders no progress spine to collapse to:\n%s", html)
	}
	// A button, because it is the way back into the rail it replaces.
	if !strings.HasPrefix(tag, "<button") {
		t.Errorf("the spine is not a control, so a closed rail cannot be reopened from it: %s", tag)
	}
	if !strings.Contains(tag, "data-rail-toggle") {
		t.Errorf("the spine does not say it toggles the rail: %s", tag)
	}
	// One dot per step, and the current step's position and title — the
	// two things UX §6 names.
	// `spine-dot ` with the space: `spine-dots` is the container, and
	// counting the prefix counted it as a fourth step.
	dots := strings.Count(html, `class="spine-dot `)
	if want := len(pb.StepList); dots != want {
		t.Errorf("the spine shows %d dots for %d steps", dots, want)
	}
	label := RailData{Instance: "pii-lab", Mode: ModeGuided, Playbook: pb, Progress: prog,
		Results: map[string]engine.CheckpointView{}}.SpineLabel()
	if !strings.Contains(label, "Step 2 of") {
		t.Errorf("the spine's label does not carry the learner's position: %q", label)
	}
	if !strings.Contains(html, label) {
		t.Errorf("the spine does not show its own label %q:\n%s", label, html)
	}
	// No `aria-label`: one would *replace* the name the button's contents
	// compose, and the dots' words — added in round 23 for exactly this
	// purpose — would be announced by nothing.
	// This assertion used to require that label, which is how
	// the fix and the thing it broke shipped together.
	if strings.Contains(tag, "aria-label=") {
		t.Errorf("the spine overrides the name its contents compose, so its verdicts are announced by nothing: %s", tag)
	}
	spine := section(html, `class="rail-spine"`)
	if spine == "" {
		spine = html
	}
	for _, part := range []string{"Open the playbook rail", label} {
		if !strings.Contains(spine, part) {
			t.Errorf("the spine's accessible name does not carry %q:\n%s", part, spine)
		}
	}
	// This test used to require the dot group to be `aria-hidden`, on the
	// reasoning that the dots were decoration because the position and
	// title were in the label. That reasoning was wrong and I wrote it:
	// the dots are the collapsed rail's *only* rendering of each step's
	// verdict, so hiding them told a screen reader nothing and leaving
	// them one shape in four colours told a colour-blind reader nothing
	// either — against UX §4's colour+glyph+word pairing and §9's rule
	// that status is never colour alone.
	//
	// The rule is now what those sections say: each dot carries a glyph
	// *and* a word, and only the glyph — decoration beside the word — is
	// hidden.
	if strings.Contains(html, `class="spine-dots" aria-hidden="true"`) {
		t.Errorf("the dots are hidden from assistive technology, so a collapsed rail states no verdicts:\n%s", html)
	}
	if !strings.Contains(html, `class="spine-glyph" aria-hidden="true"`) {
		t.Errorf("a dot's glyph is not marked decorative beside its word:\n%s", html)
	}
	if n := strings.Count(html, `class="sr-only spine-word"`); n != len(pb.StepList) {
		t.Errorf("%d dots carry a word for %d steps; status may not be colour alone (UX §9)", n, len(pb.StepList))
	}
}
