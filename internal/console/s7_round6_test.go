// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/engine"
)

// Review round 6 — five findings about controls the console
// advertises and does not deliver. (The sixth, the dead Open anchor, is
// covered by TestARowWithNoMannerToOfferSaysSoRatherThanLinkingNowhere,
// written in self-review of the round-5 fix that caused it.)

// Spec 0001 defines an auto step's one control as all of the step's
// actions followed by its verification. SeedList collected only the
// seeds, and the template suppresses the per-action controls when the
// one control is shown — so a declared `reveal` had no execution path at
// all: not run by the button, and no button of its own.
func TestAnAutoStepRunsEveryActionItDeclaresNotOnlyItsSeeds(t *testing.T) {
	pb := fixturePlaybook()
	pb.StepList[0].Auto = true
	pb.StepList[0].Actions = []engine.ActionView{
		{Seed: "events", Label: "Send events"},
		{Reveal: "beta-admin", Label: "Reveal beta credentials"},
		{Seed: "more-events", Label: "Send more"},
	}
	d := RailData{Instance: "pii-lab", Mode: ModeGuided, Playbook: pb,
		Results: map[string]engine.CheckpointView{}, CSRF: "csrf-token"}
	step := d.Steps()[0]
	got := step.ActionList()
	want := "seed:events,reveal:beta-admin,seed:more-events"
	if got != want {
		t.Errorf("the one control's action list is %q, want %q — order is the playbook's, and a reveal is an action", got, want)
	}

	r, _ := New()
	frag, err := r.Fragment(FragmentRail, d)
	if err != nil {
		t.Fatal(err)
	}
	html := string(frag)
	if !strings.Contains(html, `data-actions="seed:events,reveal:beta-admin,seed:more-events"`) {
		t.Errorf("the auto control does not carry its actions:\n%s", html[:min(len(html), 1600)])
	}
	// A revealed value needs somewhere to land: the per-action controls
	// are suppressed, so the step carries the region the reveal lands in.
	// Round 11 renamed this region and gave it to the standalone seed as
	// well: "auto-reveals" stopped being true the moment a plain seed's
	// receipt was written into it. Same assertion, new name.
	if !strings.Contains(html, `class="action-output"`) {
		t.Errorf("an auto step with a reveal has nowhere to put the value:\n%s", html[:min(len(html), 1600)])
	}
}

// Author preview is a documented manner (UX §8) that railMode accepts
// and nothing linked to: the chooser dropped the instance's mode on the
// way in, so an authoring instance could reach its own preview only by
// typing an API URL.
func TestAnAuthoringInstanceIsOfferedItsAuthorPreview(t *testing.T) {
	pbs := []engine.PlaybookSummary{{Name: "pii-redaction", Title: "PII", Modes: []string{"guided", "presenter"}}}

	authoring := PlaybooksData{Instance: "pii-lab", Mode: "authoring", Playbooks: pbs}
	row := authoring.Rows()[0]
	if row.AuthorHRef == "" {
		t.Errorf("an authoring instance is not offered Author preview")
	}
	if !strings.Contains(row.AuthorHRef, "mode=author") {
		t.Errorf("the Author link does not ask for Author manners: %q", row.AuthorHRef)
	}

	// A delivery instance has no authoring machinery, and the mode is
	// engine-enforced — offering the link would be offering a refusal.
	delivery := PlaybooksData{Instance: "pii-lab", Mode: "delivery", Playbooks: pbs}
	if got := delivery.Rows()[0].AuthorHRef; got != "" {
		t.Errorf("a delivery instance is offered Author preview: %q", got)
	}

	r, _ := New()
	frag, _ := r.Fragment(FragmentPlaybooks, authoring)
	if !strings.Contains(string(frag), "mode=author") {
		t.Errorf("the chooser does not render the Author link:\n%s", frag)
	}
}

// UX §9 advertises `?` as "shows this map". The key flipped a property
// no template read, and the keymap fragment was defined and rendered
// nowhere, so the shortcut did nothing on every lab page.
func TestTheKeyboardMapIsOnThePageForItsShortcutToShow(t *testing.T) {
	r, _ := New()
	views := fixtureInstances()
	got, err := r.Fragment(FragmentLab, LabData{Instance: views[0], Tabs: TabsFor(views[0])})
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	if !strings.Contains(html, `id="keymap-region"`) {
		t.Errorf("the lab page carries no keyboard map for `?` to show:\n%s", html[max(0, len(html)-900):])
	}
	if !strings.Contains(html, "previous step") || !strings.Contains(html, "toggle the rail") {
		t.Errorf("the keyboard map on the page is not the map")
	}
	// It starts hidden — `?` shows it, and a page that opens with a
	// panel nobody asked for is the interruption Presenter forbids.
	if got := around(html, `id="keymap-region"`, 120); got == "" {
		t.Errorf("the keyboard map region is absent, so nothing to hide")
	} else if !strings.Contains(got, "hidden") {
		t.Errorf("the keyboard map is not hidden until asked for:\n%s", got)
	}
}

// The Evidence panel refreshed from the unfiltered checkpoints URL, so
// the next event replaced a learner's chosen filter with All. The thing
// that knows the filter is the fragment, so the fragment is what
// refreshes.
func TestTheEvidenceFilterSurvivesALiveRefresh(t *testing.T) {
	r, _ := New()
	frag, err := r.Fragment(FragmentEvidence, EvidenceData{Instance: "pii-lab",
		Checkpoints: fixtureScoreboard(), Filter: "fail"})
	if err != nil {
		t.Fatal(err)
	}
	html := string(frag)
	if !strings.Contains(html, `hx-get="/api/v1alpha1/instances/pii-lab/checkpoints?filter=fail"`) {
		t.Errorf("the filtered scoreboard does not re-read itself with its filter:\n%s", html[:min(len(html), 900)])
	}
	for _, ev := range []string{"sse:checkpoint from:body", "sse:job from:body", "sse:audit from:body"} {
		if !strings.Contains(html, ev) {
			t.Errorf("the scoreboard does not keep up with %q", ev)
		}
	}

	// And the panel around it no longer re-reads on the feed, or it
	// would swap the filtered fragment away on the same event.
	surface, _ := r.Fragment(FragmentLab, func() LabData {
		views := fixtureInstances()
		return LabData{Instance: views[0], Tabs: TabsFor(views[0])}
	}())
	panel := around(string(surface), `id="panel-evidence"`, 400)
	if panel == "" {
		t.Fatalf("no evidence panel on the lab surface")
	}
	if strings.Contains(panel, "sse:checkpoint") {
		t.Errorf("the panel still re-reads on the feed and will drop the filter:\n%s", panel)
	}
	if !strings.Contains(panel, "revealed once") {
		t.Errorf("the panel no longer loads the scoreboard when its tab is first shown:\n%s", panel)
	}
}

// around returns up to n bytes of html starting at needle, or "" when the
// needle is absent. A test that slices from strings.Index without
// checking for -1 does not fail — it panics, and a panic takes the whole
// test binary down with it, so every test after it in the file silently
// does not run. That is how a red proof comes back reading three of four
// when the fourth never started (found proving round 6 red).
func around(html, needle string, n int) string {
	i := strings.Index(html, needle)
	if i < 0 {
		return ""
	}
	return html[i:min(len(html), i+n)]
}
