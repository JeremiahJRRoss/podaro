// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/engine"
)

// Spec 0001 line 91 declares `solution` markdown, and both shipped
// playbooks write it as markdown — bold function names, inline-code
// pipeline names, and paragraph breaks between the moves. The
// step body one line above goes through the safe renderer and the
// solution did not, so the "Show me" a stuck learner opens showed them
// the asterisks and ran the authored paragraphs together. The one place
// in the rail where the writing is trying hardest to help.
func TestTheShowMeSolutionIsRenderedAsTheMarkdownItIsDeclaredToBe(t *testing.T) {
	r, _ := New()
	pb := fixturePlaybook()
	pb.StepList[0].Solution = "In the leader: **Routing** → the `dc-wbsrv` route.\n\nThat pair is the fork."
	got, err := r.Fragment(FragmentRail, RailData{Instance: "pii-lab", Mode: ModeGuided,
		Playbook: pb, Results: map[string]engine.CheckpointView{}, CSRF: "csrf-token"})
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	i := strings.Index(html, `class="solution"`)
	if i < 0 {
		t.Fatalf("no solution disclosure:\n%s", html)
	}
	block := html[i:min(len(html), i+700)]
	if strings.Contains(block, "**Routing**") {
		t.Errorf("the solution shows its markdown delimiters instead of rendering them:\n%s", block)
	}
	if !strings.Contains(block, "<strong>Routing</strong>") {
		t.Errorf("the solution does not render bold:\n%s", block)
	}
	if !strings.Contains(block, "<code>dc-wbsrv</code>") {
		t.Errorf("the solution does not render inline code:\n%s", block)
	}
	// The renderer is the safe one: a solution is authored text, and it
	// may not become markup in the console any more than a hint may.
	pb.StepList[0].Solution = "Try <script>alert(1)</script> first."
	got, _ = r.Fragment(FragmentRail, RailData{Instance: "pii-lab", Mode: ModeGuided,
		Playbook: pb, Results: map[string]engine.CheckpointView{}, CSRF: "csrf-token"})
	if strings.Contains(string(got), "<script>alert(1)</script>") {
		t.Errorf("a solution's raw markup reached the page")
	}
}

// The chooser offered "Open" on every playbook, and that link opens the
// rail in Guided. A playbook whose metadata.modes omits `guided` — which
// spec 0001 allows, and a presenter-only demo script is the obvious case
// — was therefore offered a manner it does not declare, and the engine
// rendered it, because the endpoint's default is Guided.
func TestTheChooserOffersOnlyTheModesAPlaybookDeclares(t *testing.T) {
	d := PlaybooksData{Instance: "pii-lab", Playbooks: []engine.PlaybookSummary{
		{Name: "both", Title: "Both", Modes: []string{"guided", "presenter"}},
		{Name: "presenter-only", Title: "Presenter only", Modes: []string{"presenter"}},
		{Name: "repro-only", Title: "Repro only", Modes: []string{"repro"}},
	}}
	rows := d.Rows()
	by := map[string]PlaybookRow{}
	for _, r := range rows {
		by[r.Name] = r
	}
	if by["both"].HRef == "" || by["both"].PresenterHRef == "" {
		t.Errorf("a playbook declaring both manners lost one: %+v", by["both"])
	}
	if by["presenter-only"].HRef != "" {
		t.Errorf("a presenter-only playbook is offered Guided: %q", by["presenter-only"].HRef)
	}
	if by["presenter-only"].PresenterHRef == "" {
		t.Errorf("a presenter-only playbook is offered nothing at all")
	}
	if by["repro-only"].HRef != "" {
		t.Errorf("a repro-only playbook is offered Guided: %q", by["repro-only"].HRef)
	}
}

// The Evidence panel re-reads on checkpoint and job events. The journal
// it now carries also holds audit entries — a reveal, a join — and the
// feed emits `audit` for exactly those. A credential revealed while the
// panel was open left the journal saying it had not happened.
// Round 6 moved the triggers from the panel to the scoreboard fragment
// inside it — the fragment is what knows which filter chip is in force,
// and refreshing from the panel threw that away. The requirement is
// unchanged and so is this test's job: the Evidence surface must re-read
// on `audit`, wherever the triggers live. It asks the fragment now.
func TestTheEvidencePanelListensForTheAuditEventsItsJournalShows(t *testing.T) {
	r, _ := New()
	got, err := r.Fragment(FragmentEvidence, EvidenceData{Instance: "pii-lab", Checkpoints: fixtureScoreboard()})
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	for _, want := range []string{"sse:checkpoint from:body", "sse:job from:body", "sse:audit from:body"} {
		if !strings.Contains(html, want) {
			t.Errorf("the Evidence scoreboard does not re-read on %q:\n%s", want, html[:min(len(html), 700)])
		}
	}
	// And the journal beneath it, which is what the audit event is for,
	// comes along: the fragment re-reads itself whole.
	if !strings.Contains(html, `class="journal-region"`) {
		t.Errorf("a refreshed scoreboard leaves the journal behind:\n%s", html)
	}
}

// Self-review of the round-5 fixes, before the reviewer saw them.
//
// Making HRef conditional stopped the chooser offering Guided for a
// playbook that does not declare it — and the template rendered the Open
// anchor unconditionally, so a repro-only row went from a link to the
// wrong manner to a link to nothing at all: `href=""`, which htmx would
// have fetched as the current page into the rail. A fix that trades a
// wrong answer for a broken one is not a fix.
func TestARowWithNoMannerToOfferSaysSoRatherThanLinkingNowhere(t *testing.T) {
	r, _ := New()
	got, err := r.Fragment(FragmentPlaybooks, PlaybooksData{Instance: "pii-lab",
		Playbooks: []engine.PlaybookSummary{
			{Name: "repro-only", Title: "Repro only", Modes: []string{"repro"}},
			{Name: "both", Title: "Both", Modes: []string{"guided", "presenter"}},
		}})
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	if strings.Contains(html, `href=""`) || strings.Contains(html, `hx-get=""`) {
		t.Errorf("a row renders a link to nowhere:\n%s", html)
	}
	// The row still exists and still says what it is — it just cannot be
	// opened from here, and says that instead of pretending.
	if !strings.Contains(html, "Repro only") {
		t.Errorf("the repro-only playbook vanished from the chooser:\n%s", html)
	}
	if !strings.Contains(html, "no manner this console opens") {
		t.Errorf("the row does not say why it offers no way in:\n%s", html)
	}
	// And the ordinary row is untouched.
	if !strings.Contains(html, `/playbooks/both"`) || !strings.Contains(html, "mode=presenter") {
		t.Errorf("a playbook declaring both manners lost a link:\n%s", html)
	}
}

// The same class one more time: `auto: true` with neither actions nor a
// checkpoint is schema-valid and has nothing to run, and the rail
// rendered "Run this step" for it anyway — a control whose whole
// behaviour is to do nothing.
func TestTheAutoControlIsRenderedOnlyWhenThereIsSomethingToRun(t *testing.T) {
	r, _ := New()
	pb := fixturePlaybook()
	pb.StepList[0].Auto = true
	pb.StepList[0].Actions = nil
	pb.StepList[0].Checkpoint = nil
	got, err := r.Fragment(FragmentRail, RailData{Instance: "pii-lab", Mode: ModeGuided,
		Playbook: pb, Results: map[string]engine.CheckpointView{}, CSRF: "csrf-token"})
	if err != nil {
		t.Fatal(err)
	}
	first := string(got)
	if i := strings.Index(first, `id="step-`); i >= 0 {
		if j := strings.Index(first[i+1:], `id="step-`); j >= 0 {
			first = first[i : i+1+j]
		}
	}
	if strings.Contains(first, "run-step") {
		t.Errorf("a step with no actions and no checkpoint still offers Run this step:\n%s", first)
	}
	// An auto step that does have actions keeps its one control.
	pb2 := fixturePlaybook()
	pb2.StepList[0].Auto = true
	got2, _ := r.Fragment(FragmentRail, RailData{Instance: "pii-lab", Mode: ModeGuided,
		Playbook: pb2, Results: map[string]engine.CheckpointView{}, CSRF: "csrf-token"})
	if !strings.Contains(string(got2), "run-step") {
		t.Errorf("an auto step with actions lost its control")
	}
}
