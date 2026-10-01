// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// Round 7 gave a verdict out-of-band swaps for the other steps sharing
// its checkpoint, and the swaps went nowhere: CheckpointView.Steps holds
// *qualified* ids — `playbook/step`, built in lab.instance — and the
// rail's regions are `result-<bare step id>`. So every target read
// `result-pii-redaction/mask-them` and matched no element on the page.
//
// The fix was inert, and the test that "proved" it passed because its
// fixture used bare ids the engine never produces. This one uses the
// shape the engine actually returns.
func TestTheSharedVerdictAddressesTheStepsAsThePageNamesThem(t *testing.T) {
	cp := &engine.CheckpointView{ID: "no-ssn-in-index", Class: "objective", Adapter: "http",
		Steps: []string{
			"pii-redaction/mask-them",
			"pii-redaction/check-again",
			"other-playbook/also-mask", // a second playbook shares the checkpoint
		}}
	res := &state.CheckpointResult{ID: "no-ssn-in-index", Class: "objective", Status: "fail", At: at(2), Duration: "1.4s"}

	line := NewResultLine("pii-lab", "pii-redaction", "mask-them", res, cp)
	if got := line.Also; len(got) != 1 || got[0] != "check-again" {
		t.Fatalf("the verdict reaches %v; want [check-again] — bare, and only this playbook's", got)
	}

	r, _ := New()
	got, err := r.Fragment(FragmentResult, line)
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	if !strings.Contains(html, `id="result-check-again" hx-swap-oob="innerHTML"`) {
		t.Errorf("the verdict does not reach the other step in this playbook:\n%s", html)
	}
	// A step in a playbook this rail is not showing has no element here,
	// and a swap aimed at one is a swap aimed at nothing.
	if strings.Contains(html, "also-mask") {
		t.Errorf("the verdict is aimed at another playbook's step:\n%s", html)
	}
	// And no qualified id ever reaches an id attribute.
	if strings.Contains(html, `id="result-pii-redaction/`) {
		t.Errorf("a qualified id was used as a DOM id:\n%s", html)
	}
}

// The verify and attest controls carry the playbook they are being
// pressed in, because that is what tells the answer which steps are on
// the page to update.
func TestTheVerifyControlNamesItsPlaybook(t *testing.T) {
	r, _ := New()
	got, err := r.Fragment(FragmentRail, RailData{Instance: "pii-lab", Mode: ModeGuided,
		Playbook: fixturePlaybook(), Results: map[string]engine.CheckpointView{}, CSRF: "csrf-token"})
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	if !strings.Contains(html, "?step=mask-them&amp;playbook=pii-redaction") {
		t.Errorf("the verify control does not name its playbook:\n%s", around(html, `class="verify"`, 600))
	}
}

// A phone hides the product panels (UX §10 degrades honestly to Overview
// plus rail) and left their tab buttons on the strip. Pressing one hid
// Overview, revealed a panel, and CSS hid that panel too — a blank area
// where a product should be. A tab that cannot show anything is not
// offered.
func TestAPhoneIsNotOfferedTabsItCannotShow(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "console", "assets", "console.css"))
	if err != nil {
		t.Fatal(err)
	}
	css := string(raw)
	// The stylesheet has more than one phone breakpoint, so anchoring on
	// the first `@media (max-width: 768px)` reads a block this rule is
	// not in. The block under test is the one that hides the panels.
	i := strings.Index(css, ".panel-iframe, .panel-newtab { display: none; }")
	if i < 0 {
		t.Fatal("the phone layout no longer hides the product panels")
	}
	open := strings.LastIndex(css[:i], "@media")
	if open < 0 || !strings.HasPrefix(css[open:], "@media (max-width: 768px)") {
		t.Fatalf("the panel rule is not under the phone breakpoint: %q", css[max(0, open):i])
	}
	end := strings.Index(css[i:], "\n}")
	if end < 0 {
		t.Fatal("the phone block does not close")
	}
	block := css[open : i+end]
	for _, kind := range []string{`data-kind="iframe"`, `data-kind="newtab"`} {
		if !strings.Contains(block, kind) {
			t.Errorf("the phone layout hides the %s panel and keeps its tab:\n%s", kind, block)
		}
	}
}

// Review round 10: `Runs` decides the one control renders, and the verify
// block rendered unconditionally on `.Checkpoint` — so a Guided auto
// step with a machine checkpoint showed both "Run this step" and a
// separate Verify. Pressing the second skips the declared actions and
// judges the lab as it was, which is the opposite of spec 0001's
// one-click contract.
//
// The same predicate/accessor drift as rounds 5, 8 and 8b, in its fourth
// place: whoever owns the checkpoint is the only one who may offer to
// run it.
func TestAnAutoStepOffersOneControlNotTwo(t *testing.T) {
	r, _ := New()
	pb := fixturePlaybook()
	for i := range pb.StepList {
		if len(pb.StepList[i].Actions) > 0 {
			pb.StepList[i].Auto = true
		}
	}
	got, err := r.Fragment(FragmentRail, RailData{Instance: "pii-lab", Mode: ModeGuided,
		Playbook: pb, Results: map[string]engine.CheckpointView{}, CSRF: "csrf-token"})
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	// This step's own markup, not a fixed window: a window wide enough
	// to hold a step is wide enough to reach the next one, and the
	// assertion would then be about somebody else's controls (the round-8
	// mistake, which is why this is spelled out).
	step := oneStep(html, "mask-them")
	if step == "" {
		t.Fatal("no auto step in the fixture rail")
	}
	if !strings.Contains(step, "run-step") {
		t.Fatalf("the auto step lost its one control:\n%s", step)
	}
	if strings.Contains(step, "verify-button") {
		t.Errorf("an auto step offers a second control that skips its actions:\n%s", step)
	}
	// An attest step keeps its human control, because the one control
	// deliberately does not post it (round 8).
	attest := oneStep(html, "confirm")
	if !strings.Contains(attest, "I confirm this") {
		t.Errorf("an attest step lost the control only a human may press:\n%s", attest)
	}
	// And an ordinary step is untouched.
	if !strings.Contains(html, "verify-button") {
		t.Errorf("no step offers Verify at all any more")
	}
}

// oneStep returns the markup of exactly one step's <li>, so an assertion
// about a step cannot accidentally be about the one after it.
func oneStep(html, id string) string {
	i := strings.Index(html, `id="step-`+id+`"`)
	if i < 0 {
		return ""
	}
	rest := html[i:]
	if j := strings.Index(rest, "</li>"); j >= 0 {
		return rest[:j]
	}
	return rest
}
