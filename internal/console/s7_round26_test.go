// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// Round 7 taught the start-here card not to offer a way in it does not
// have. It learned the rule from the chooser's two links and not from
// the chooser's three: an authoring instance's rows carry Author preview
// for every playbook, declared manners or not, because the manner
// belongs to the *instance* (round 6). So on an authoring instance the
// card said "this console does not open it" about a playbook the chooser
// beside it was offering to open.
func TestTheStartHereCardOffersAuthorPreviewWhereTheChooserDoes(t *testing.T) {
	repro := []engine.PlaybookSummary{{Name: "repro-only", Title: "Repro only", Modes: []string{"repro"}, FirstStep: "one"}}
	ready := engine.LadderView{Stage: "ready", Label: "ready"}

	authoring := engine.InstanceView{Name: "pii-lab", Mode: "authoring", Ladder: ready}
	card := StartHereFor(authoring, repro, nil)
	// The chooser's own answer, on the same page, for the same playbook.
	rows := PlaybooksData{Instance: authoring.Name, Mode: authoring.Mode, Playbooks: repro}.Rows()
	if len(rows) != 1 || rows[0].AuthorHRef == "" {
		t.Fatalf("this case needs the chooser to offer Author preview, got %+v", rows)
	}
	if card.ActionHRef != rows[0].AuthorHRef {
		t.Errorf("the card offers %q → %q while the chooser on the same page offers %q",
			card.Action, card.ActionHRef, rows[0].AuthorHRef)
	}
	if strings.Contains(card.Body, "does not open") {
		t.Errorf("the card says the console cannot open what it just linked to: %q", card.Body)
	}

	// A delivery instance has no Author preview — the engine refuses the
	// manner there (railMode), so the card's honest answer is the one
	// round 7 wrote.
	delivery := engine.InstanceView{Name: "pii-lab", Mode: "delivery", Ladder: ready}
	if got := StartHereFor(delivery, repro, nil); got.Action != "" || got.ActionHRef != "" {
		t.Errorf("a delivery instance was offered %q → %q into a manner it cannot render", got.Action, got.ActionHRef)
	}

	// And a playbook that declares a manner this console opens keeps it,
	// on an authoring instance too: UX §8 gives Author preview free
	// navigation and no persisted progress, so the Resume card must not
	// open into it.
	guided := []engine.PlaybookSummary{{Name: "pii-redaction", Title: "PII", Modes: []string{"guided"}, FirstStep: "one"}}
	p := &state.Progress{Instance: "pii-lab", Playbook: "pii-redaction", CurrentStep: "two",
		Steps: map[string]state.StepProgress{}}
	resume := StartHereFor(authoring, guided, p)
	if resume.State != "resume" || strings.Contains(resume.ActionHRef, "mode=author") {
		t.Errorf("the resume card opens into Author preview, where §8 says progress is n/a: %+v", resume)
	}
}

// An instance-bound session (API §2.4) is an attendee's: below read, and
// reset is one of the things structurally absent from its grant. The
// shell rendered the Reset control on the strength of "there is an
// instance", so the one control an attendee is certain to be refused was
// the one advertised in their status bar — and this console swaps every
// response, so the 403 lands in the playbook rail.
func TestTheShellAdvertisesNothingAnInstanceSessionIsRefused(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	view := &engine.InstanceView{Name: "pii-lab", Mode: "delivery",
		Ladder: engine.LadderView{Stage: "ready", Label: "ready", Condensed: "●●●"}}
	shell := func(s *SessionView) string {
		var b strings.Builder
		if err := r.Page(&b, ShellData{Title: "t", Version: "0.1.0", Assets: "0123456789ab", HomeURL: "https://lab.example.com",
			Instance: view, Session: s}); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}

	attendee := shell(&SessionView{Subject: "alice", CSRF: "c", Instance: "pii-lab"})
	for _, refused := range []string{"reset-plan", `id="system"`, "https://lab.example.com/"} {
		if strings.Contains(attendee, refused) {
			t.Errorf("the shell offers %q to a session bound to one instance:\n%s", refused, attendee)
		}
	}
	// It is not an empty shell: the lab's own surfaces stay.
	for _, kept := range []string{"instance-name", "panel-evidence", "Sign out", "podaro v0.1.0"} {
		if !strings.Contains(attendee, kept) {
			t.Errorf("the attendee's shell lost %q:\n%s", kept, attendee)
		}
	}

	operator := shell(&SessionView{Subject: "jross", CSRF: "c"})
	for _, want := range []string{"reset-plan", `id="system"`, `href="https://lab.example.com/"`} {
		if !strings.Contains(operator, want) {
			t.Errorf("the operator's shell lost %q:\n%s", want, operator)
		}
	}
}
