// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/engine"
)

// Self-review of the round-6 fixes.
//
// Round 6 gave an authoring instance a link to Author preview, because
// railMode had always accepted the manner and nothing ever linked to it.
// Reading that fix back: the rail does nothing with the manner. Notes
// are gated on Presenter, so Author preview *hid* them — the one thing
// UX §8's Author column says outright. And rail.html's own comment,
// written at round 3, claims "the actions are still listed below in
// Author preview, where seeing them is the point", which was never true:
// the actions are suppressed for an auto step in every manner.
//
// A link to a manner that is not implemented is worse than no link. This
// implements the manner the link now promises.
func TestAuthorPreviewShowsWhatTheDocumentSaysItShows(t *testing.T) {
	r, _ := New()
	pb := fixturePlaybook()
	// A prefix with nothing html/template escapes: the fixture's second
	// note carries an apostrophe, and matching on it would fail for the
	// escaping rather than for the manner under test.
	note := "Say out loud that nothing is redacted yet"
	for i := range pb.StepList {
		if len(pb.StepList[i].Actions) > 0 {
			pb.StepList[i].Auto = true
		}
	}
	frag := func(mode string) string {
		got, err := r.Fragment(FragmentRail, RailData{Instance: "pii-lab", Mode: mode,
			Playbook: pb, Results: map[string]engine.CheckpointView{}, CSRF: "csrf-token"})
		if err != nil {
			t.Fatal(err)
		}
		return string(got)
	}
	author, guided, presenter := frag(ModeAuthor), frag(ModeGuided), frag(ModePresenter)

	// Notes: hidden in Guided, visible in Presenter and in Author (UX §8).
	if !strings.Contains(author, note) {
		t.Errorf("Author preview hides the notes UX §8 says it shows")
	}
	if strings.Contains(guided, note) {
		t.Errorf("Guided leaked a presenter note")
	}
	if !strings.Contains(presenter, note) {
		t.Errorf("Presenter lost its notes")
	}

	// Verify reads "Test checkpoint" in Author (UX §8), and the ordinary
	// word everywhere else.
	if !strings.Contains(author, "Test checkpoint") {
		t.Errorf("Author preview does not offer Test checkpoint:\n%s", around(author, `class="verify"`, 700))
	}
	if strings.Contains(guided, "Test checkpoint") {
		t.Errorf("Guided borrowed Author's label")
	}

	// The actions are listed in Author preview even for an auto step —
	// seeing what the one control will do is the point of the preview,
	// and rail.html has claimed it since round 3.
	// The per-action control, which round 9 gave its own class when the
	// standalone seed stopped being a bare hx-post.
	seed := `class="button primary seed-button"`
	if !strings.Contains(author, seed) {
		t.Errorf("Author preview does not list an auto step's actions:\n%s", around(author, `class="actions"`, 900))
	}
	if strings.Contains(guided, seed) {
		t.Errorf("Guided renders an auto step's actions separately as well as its one control")
	}
	// Author preview keeps the one control too: it previews the step as
	// a learner meets it, and then shows the work behind it.
	if !strings.Contains(author, "run-step") {
		t.Errorf("Author preview dropped the one control the learner will press")
	}
}
