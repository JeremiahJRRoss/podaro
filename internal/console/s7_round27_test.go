// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// "Resume at <step> — your progress is kept on the instance" is a Guided
// claim. UX §8 makes Presenter progress per-rehearsal and discardable,
// and Author preview's `n/a`. The card took *any* way in as a resumable
// one, so a playbook with stored progress that this console can open
// only in one of those promised what the manner does not keep.
//
// I wrote the rule in round 26 — "a card that reads Resume must not open
// into Author preview" — and applied it to which manner the card
// prefers, not to which card the manner earns. The Presenter fallback
// had been making the same promise since round 5.
func TestResumeIsOnlyOfferedIntoTheMannerThatKeepsProgress(t *testing.T) {
	ready := engine.LadderView{Stage: "ready", Label: "ready"}
	progress := func(pb string) *state.Progress {
		return &state.Progress{Instance: "pii-lab", Playbook: pb, CurrentStep: "two",
			Steps: map[string]state.StepProgress{"one": {Status: "pass"}}}
	}

	// Guided: the claim is true, and the card still makes it.
	guided := []engine.PlaybookSummary{{Name: "pii-redaction", Title: "PII", Modes: []string{"guided"}, FirstStep: "one"}}
	delivery := engine.InstanceView{Name: "pii-lab", Mode: "delivery", Ladder: ready}
	if got := StartHereFor(delivery, guided, progress("pii-redaction")); got.State != "resume" {
		t.Errorf("a started Guided playbook lost its Resume card: %+v", got)
	}

	// Presenter-only, and Author preview on an authoring instance: both
	// are ways in, and neither keeps progress. The card offers the way in
	// and stops claiming the progress.
	for _, c := range []struct {
		what string
		v    engine.InstanceView
		pbs  []engine.PlaybookSummary
		want string
	}{
		{"presenter-only", delivery,
			[]engine.PlaybookSummary{{Name: "demo", Title: "Demo", Modes: []string{"presenter"}, FirstStep: "one"}},
			"?mode=presenter"},
		{"repro-only on an authoring instance", engine.InstanceView{Name: "pii-lab", Mode: "authoring", Ladder: ready},
			[]engine.PlaybookSummary{{Name: "repro-only", Title: "Repro only", Modes: []string{"repro"}, FirstStep: "one"}},
			"?mode=author"},
	} {
		got := StartHereFor(c.v, c.pbs, progress(c.pbs[0].Name))
		if got.State == "resume" {
			t.Errorf("%s: the card promises kept progress into a manner that discards it: %+v", c.what, got)
		}
		if strings.Contains(got.Body, "progress is kept") {
			t.Errorf("%s: the card still claims the progress: %q", c.what, got.Body)
		}
		// The way in is not lost with the claim.
		if !strings.HasSuffix(got.ActionHRef, c.want) {
			t.Errorf("%s: the card offers %q, want a link ending %q", c.what, got.ActionHRef, c.want)
		}
	}
}
