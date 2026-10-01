// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"bytes"
	"encoding/json"
	"html/template"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/evidence"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// Plan S7: a golden for every UX §6 component, in each state its written
// anatomy names. The fixtures are the API's own types, so the binding
// rule (ADR-0003) holds by construction here as it does for S6.

func at(min int) time.Time {
	return time.Date(2026, 9, 3, 14, min, 0, 0, time.UTC)
}

func fixturePlaybook() engine.PlaybookView {
	return engine.PlaybookView{
		PlaybookSummary: engine.PlaybookSummary{
			Name: "pii-redaction", Title: "PII Redaction", Description: "Stop social security numbers reaching the index.",
			Modes: []string{"guided", "presenter"}, Gating: "soft", Steps: 3, Objectives: 2,
		},
		StepList: []engine.StepView{
			{
				ID: "send-events", Title: "Send events with PII", Context: "beta", Duration: "2m",
				Body:    "Send a batch of web-server events. Some carry a social security number in _raw.",
				Notes:   "Say out loud that nothing is redacted yet — that is the point.",
				Actions: []engine.ActionView{{Seed: "events", Label: "Send events · 500 events, 40% with PII"}},
			},
			{
				ID: "mask-them", Title: "Mask the numbers", Context: "beta", Auto: false,
				Body:       "Add a Mask function to the pipeline so ssn=… becomes pii-redacted.",
				Notes:      "The Mask function lives under the pipeline's function list.",
				Actions:    []engine.ActionView{{Reveal: "beta-admin", Label: "Reveal beta credentials"}},
				Checkpoint: &engine.StepCheckpoint{ID: "no-ssn-in-index", Class: "objective", Adapter: "http", Hint: "Check the mask pattern matches ssn= followed by nine digits."},
				Solution:   "In the pipeline add Mask, matching ssn=\\d{3}-\\d{2}-\\d{4}, replacing with pii-redacted.",
			},
			{
				ID: "confirm", Title: "Confirm the routes are understood", Context: "overview",
				Body:       "Say in your own words where the events now go.",
				Checkpoint: &engine.StepCheckpoint{ID: "routes-understood", Class: "objective", Adapter: "attest"},
			},
		},
	}
}

func fixtureCheckpoints() map[string]engine.CheckpointView {
	pass := &state.CheckpointResult{ID: "no-ssn-in-index", Class: "objective", Adapter: "http", Status: "pass",
		At: at(2), Duration: "1.4s", Message: `queried gamma: 0 events matched "ssn=" — verified`, Evidence: "/api/v1alpha1/instances/pii-lab/evidence/ev_01M1"}
	att := &state.CheckpointResult{ID: "routes-understood", Class: "objective", Adapter: "attest", Status: "attested", At: at(4), Duration: "0s"}
	return map[string]engine.CheckpointView{
		"no-ssn-in-index":   {ID: "no-ssn-in-index", Class: "objective", Adapter: "http", Expect: map[string]any{"count": float64(0)}, Hint: "Check the mask pattern matches ssn= followed by nine digits.", Result: pass},
		"routes-understood": {ID: "routes-understood", Class: "objective", Adapter: "attest", Result: att},
	}
}

func fixtureScoreboard() []engine.CheckpointView {
	return []engine.CheckpointView{
		{ID: "alpha-ready", Class: "baseline", Adapter: "http", Expect: map[string]any{"status": float64(200)},
			Result: &state.CheckpointResult{ID: "alpha-ready", Class: "baseline", Status: "pass", At: at(0), Duration: "120ms", Message: "GET http://alpha:9200/ → 200"}},
		{ID: "no-ssn-in-index", Class: "objective", Adapter: "http", Expect: map[string]any{"count": float64(0)}, Hint: "Check the mask pattern.",
			Result: &state.CheckpointResult{ID: "no-ssn-in-index", Class: "objective", Status: "fail", At: at(2), Duration: "1.4s", Message: `queried gamma: 37 events matched "ssn=" — not verified`, Hint: "Check the mask pattern."}},
		{ID: "routes-understood", Class: "objective", Adapter: "attest",
			Result: &state.CheckpointResult{ID: "routes-understood", Class: "objective", Status: "attested", At: at(4), Duration: "0s"}},
		{ID: "never-run", Class: "objective", Adapter: "http", Expect: map[string]any{"status": float64(200)}},
	}
}

func TestS7FragmentGoldens(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	pb := fixturePlaybook()
	cps := fixtureCheckpoints()
	prog := &state.Progress{Instance: "pii-lab", Playbook: "pii-redaction", CurrentStep: "mask-them",
		Steps: map[string]state.StepProgress{"send-events": {Status: "done", At: at(1)}}, Updated: at(2)}
	entries := []evidence.Entry{
		{ID: "ev_01M1", At: at(0), Type: evidence.TypeLifecycle, Instance: "pii-lab", Lifecycle: &evidence.Lifecycle{Event: "stage", Stage: "ready"}},
		{ID: "ev_01M2", At: at(1), Type: evidence.TypeSeed, Instance: "pii-lab", Seed: &evidence.SeedRun{Name: "events", Generator: "web-logs", Kind: "builtin", Count: 500, SeedValue: "x", Duration: "2.1s", Message: "500 events sent, 200 with PII"}},
		{ID: "ev_01M3", At: at(2), Type: evidence.TypeAudit, Instance: "pii-lab", Audit: &state.Audit{Seq: 7, At: at(2), Action: "reveal", Detail: "beta-admin", Actor: "jross", Mechanism: "session"}},
	}
	cases := []struct {
		name string
		frag string
		data any
	}{
		{"rail-guided", FragmentRail, RailData{Instance: "pii-lab", Mode: ModeGuided, Playbook: pb, Progress: prog, Results: cps, CSRF: "csrf-token"}},
		{"rail-presenter", FragmentRail, RailData{Instance: "pii-lab", Mode: ModePresenter, Playbook: pb, Progress: prog, Results: cps, CSRF: "csrf-token"}},
		{"rail-fresh", FragmentRail, RailData{Instance: "pii-lab", Mode: ModeGuided, Playbook: pb, Results: map[string]engine.CheckpointView{}, CSRF: "csrf-token"}},
		{"playbooks", FragmentPlaybooks, PlaybooksData{Instance: "pii-lab", Playbooks: []engine.PlaybookSummary{pb.PlaybookSummary}}},
		{"playbooks-empty", FragmentPlaybooks, PlaybooksData{Instance: "pii-lab", Playbooks: []engine.PlaybookSummary{}}},
		{"evidence", FragmentEvidence, EvidenceData{Instance: "pii-lab", Checkpoints: fixtureScoreboard()}},
		{"journal", FragmentJournal, JournalData{Instance: "pii-lab", Entries: entries}},
		{"journal-empty", FragmentJournal, JournalData{Instance: "pii-lab"}},
		{"evidence-objective", FragmentEvidence, EvidenceData{Instance: "pii-lab", Checkpoints: fixtureScoreboard(), Filter: "objective"}},
		{"evidence-fail", FragmentEvidence, EvidenceData{Instance: "pii-lab", Checkpoints: fixtureScoreboard(), Filter: "fail"}},
		{"secrets", FragmentSecrets, SecretsData{Instance: "pii-lab", CSRF: "csrf-token", Secrets: []engine.SecretView{
			{Name: "beta-admin", Kind: "password", DeclaredBy: []string{"beta"}, Reveals: 2, Generated: "password"},
			{Name: "gamma-token", Kind: "token", DeclaredBy: []string{"gamma", "beta"}},
		}}},
		{"secrets-empty", FragmentSecrets, SecretsData{Instance: "my-lab", CSRF: "csrf-token"}},
		{"reveal", FragmentReveal, RevealData{Instance: "pii-lab", Name: "beta-admin", Value: "correct-horse-battery-staple", RemaskAfter: "30s", Seconds: 30}},
		{"resetplan", FragmentResetPlan, ResetData{Instance: "pii-lab", CSRF: "csrf-token", Plan: &engine.ResetPlan{
			Destroyed: []string{"container gamma and the data inside it", "container beta and the data inside it", "2 objective results", "playbook progress"},
			Survives:  []string{"the instance and its hostnames", "its credentials", "its evidence journal"}}}},
		{"starthere-provisioning", FragmentStartHere, StartHere{State: "provisioning", Headline: "Setting up — initializing", Body: "While you wait: Stop social security numbers reaching the index."}},
		{"starthere-ready", FragmentStartHere, StartHere{State: "ready", Headline: "Begin: PII Redaction", Body: "Stop social security numbers reaching the index.", Action: "Begin", ActionHRef: "/api/v1alpha1/instances/pii-lab/playbooks/pii-redaction", Playbook: "pii-redaction"}},
		{"starthere-failed", FragmentStartHere, StartHere{State: "failed", Headline: "This lab stopped before it was ready", Body: "pull failed — the error below says what to do next."}},
		{"tabs", FragmentTabs, TabsFor(engine.InstanceView{Name: "pii-lab", Services: []engine.ServiceView{
			{Name: "beta", Stage: "healthy", Word: "ready", Embed: "iframe", URL: "https://beta-pii-lab.lab.example.com:8443"},
			{Name: "gamma", Stage: "healthy", Word: "ready", Embed: "newtab", URL: "https://gamma-pii-lab.lab.example.com:8443"},
			{Name: "alpha", Stage: "healthy", Word: "ready", Embed: "api-only", URL: "https://alpha-pii-lab.lab.example.com:8443"},
		}})},
		{"keymap", FragmentKeymap, nil},
		{"result-pass", FragmentResult, resultLine("pii-lab", "pii-redaction", "mask-them", cps["no-ssn-in-index"].Result, ptr(cps["no-ssn-in-index"]))},
		{"result-idle", FragmentResult, resultLine("pii-lab", "pii-redaction", "mask-them", nil, ptr(cps["no-ssn-in-index"]))},
		{"result-fail", FragmentResult, resultLine("pii-lab", "pii-redaction", "mask-them",
			&state.CheckpointResult{ID: "no-ssn-in-index", Status: "fail", At: at(2), Duration: "1.4s", Message: `queried gamma: 37 events matched "ssn=" — not verified`},
			ptr(cps["no-ssn-in-index"]))},
		{"result-attested", FragmentResult, resultLine("pii-lab", "pii-redaction", "confirm", cps["routes-understood"].Result, ptr(cps["routes-understood"]))},
		{"result-error", FragmentResult, resultLine("pii-lab", "pii-redaction", "mask-them",
			&state.CheckpointResult{ID: "no-ssn-in-index", Status: "error", At: at(2), Duration: "30s",
				Error: &pdr.Error{Code: "PDR-E401", Message: "checkpoint attempt timed out"}}, ptr(cps["no-ssn-in-index"]))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := r.Fragment(c.frag, c.data)
			if err != nil {
				t.Fatal(err)
			}
			check(t, filepath.Join("testdata", c.name+".html"), []byte(got))
		})
	}
}

func ptr[T any](v T) *T { return &v }

// The instance page, assembled: one start-here card, the tab strip with
// Overview first and Evidence last, a panel per tab, and the rail's
// region — present even with no playbook open, so a later fragment has
// something to swap into.
func TestTheLabSurfaceAssembles(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	views := fixtureInstances()
	pb := fixturePlaybook()
	d := LabData{
		Instance:  views[0],
		StartHere: StartHereFor(views[0], []engine.PlaybookSummary{pb.PlaybookSummary}, nil),
		Tabs: TabsFor(engine.InstanceView{Name: "pii-lab", Services: []engine.ServiceView{
			{Name: "beta", Stage: "healthy", Word: "ready", Embed: "iframe", URL: "https://beta-pii-lab.lab.example.com:8443"},
			{Name: "gamma", Stage: "healthy", Word: "ready", Embed: "newtab", URL: "https://gamma-pii-lab.lab.example.com:8443"},
		}}),
		Playbooks: []engine.PlaybookSummary{pb.PlaybookSummary},
		CSRF:      "csrf-token",
	}
	got, err := r.Fragment(FragmentLab, d)
	if err != nil {
		t.Fatal(err)
	}
	check(t, filepath.Join("testdata", "labsurface.html"), []byte(got))
	html := string(got)
	// Exactly one start-here card, always (UX §6).
	if n := strings.Count(html, `class="start-here`); n != 1 {
		t.Errorf("start-here cards: %d, want exactly 1", n)
	}
	// Overview first, Evidence last.
	first, last := strings.Index(html, `id="tab-overview"`), strings.Index(html, `id="tab-evidence"`)
	if first < 0 || last < 0 || first > last {
		t.Errorf("Overview must come first and Evidence last (%d, %d)", first, last)
	}
	// The rail's region exists even with no playbook open.
	if !strings.Contains(html, `id="rail"`) {
		t.Errorf("the rail's region is missing")
	}
	// The evidence panel loads when it is first shown, not on page load:
	// the scoreboard is a query, and an unopened tab must not run one.
	// Once it exists it stays true — it re-reads on the same events the
	// ladder does, or it would keep saying what the board said before a
	// verify — and on `audit` as well,
	// which the ladder has no use for but the journal beneath the board
	// does (round 5). Round 6 moved that keeping-up into the scoreboard
	// fragment, because the fragment is what knows which filter chip is
	// in force and a refresh from out here discarded it. So the panel's
	// job is now exactly the first load, asserted exactly; the triggers
	// are asserted on the fragment, in
	// TestTheEvidencePanelListensForTheAuditEventsItsJournalShows and
	// TestTheEvidenceFilterSurvivesALiveRefresh.
	if !strings.Contains(html, `hx-trigger="revealed once"`) {
		t.Errorf("the evidence panel does not defer its load to the tab being shown")
	}
	if strings.Contains(html, `id="panel-evidence"`) && strings.Contains(around(html, `id="panel-evidence"`, 400), "sse:") {
		t.Errorf("the evidence panel re-reads on the feed and will discard the learner's filter")
	}
	// Every product panel starts hidden: a browser lays out and loads an
	// iframe as it parses, so a panel that is only hidden once Alpine
	// runs has already cost the first paint.
	for _, panel := range []string{`id="panel-beta"`, `id="panel-gamma"`} {
		if i := strings.Index(html, panel); i >= 0 {
			end := strings.Index(html[i:], ">")
			if end < 0 || !strings.Contains(html[i:i+end], "hidden") {
				t.Errorf("panel %s is not hidden before its tab is selected", panel)
			}
		}
	}
	// A product that refuses framing gets the Open ↗ card, never an
	// iframe that would break (UX §6).
	if !strings.Contains(html, "Open ↗") {
		t.Errorf("the newtab product has no Open card")
	}
	if strings.Contains(html, `src="https://gamma-pii-lab`) {
		t.Errorf("a non-embeddable product was framed anyway")
	}
}

// A provisioning lab teaches while it waits rather than showing a bare
// spinner (UX §6, Journey §5).
func TestStartHereTeachesWhileProvisioning(t *testing.T) {
	views := fixtureInstances()
	pb := fixturePlaybook()
	card := StartHereFor(views[0], []engine.PlaybookSummary{pb.PlaybookSummary}, nil)
	if card.State != "provisioning" {
		t.Fatalf("a lab short of ready is provisioning: %+v", card)
	}
	if !strings.Contains(card.Body, pb.Description) {
		t.Errorf("the card does not offer the lab's story: %q", card.Body)
	}
	// A failed lab says so and points at the error, and offers no action
	// that cannot work yet.
	failed := StartHereFor(views[1], []engine.PlaybookSummary{pb.PlaybookSummary}, nil)
	if failed.State != "failed" || failed.Action != "" {
		t.Errorf("a failed lab: %+v", failed)
	}
}

// The instance page drives its live region from the SSE feed, not a
// timer (UX §11, ADR-0003). The instance list keeps the timer: it spans
// instances, so it has no single stream to listen to.
func TestTheInstancePageListensToItsFeed(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	views := fixtureInstances()
	body, _ := r.Fragment(FragmentInstance, views[0])
	var buf bytes.Buffer
	if err := r.Page(&buf, ShellData{Title: "pii-lab · Podaro", Version: "0.1.0", Assets: "0123456789ab",
		HomeURL:  "https://lab.example.com:8443",
		Instance: &views[0], Session: &SessionView{Subject: "jross", CSRF: "csrf-token"},
		Poll: "/api/v1alpha1/instances/pii-lab",
		Feed: "/api/v1alpha1/instances/pii-lab/events",
		Body: body}); err != nil {
		t.Fatal(err)
	}
	check(t, filepath.Join("testdata", "page-instance-sse.html"), buf.Bytes())
	page := buf.String()
	for _, want := range []string{
		`hx-ext="sse"`,
		`sse-connect="/api/v1alpha1/instances/pii-lab/events"`,
		`src="/assets/sse.min.js`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the instance page lacks %s", want)
		}
	}
	if strings.Contains(page, "every 2s") {
		t.Errorf("a page with a feed still polls on a timer")
	}
	// The shell opens the connection and nothing more. A refresh aimed at
	// the whole main region would swap the lab surface away and leave the
	// ladder standing alone in its place — which is what happened until a
	// browser walked it, and no golden could have said so, since each
	// fragment was correct on its own.
	main := page[strings.Index(page, "<main"):]
	main = main[:strings.Index(main, ">")]
	for _, forbidden := range []string{"hx-get", "hx-swap", "hx-trigger"} {
		if strings.Contains(main, forbidden) {
			t.Errorf("the shell's main region carries %s; the regions that listen name themselves: %s", forbidden, main)
		}
	}
}

// The live region is the ladder, not the page: an event refreshes the
// ladder from the instance twin and leaves the surface around it — the
// start-here card, the tabs, the rail — standing.
func TestTheLiveRegionIsTheLadderNotThePage(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	views := fixtureInstances()
	got, err := r.Fragment(FragmentLab, LabData{Instance: views[0], Tabs: TabsFor(views[0])})
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	i := strings.Index(html, `id="ladder-region"`)
	if i < 0 {
		t.Fatal("the lab surface has no ladder region")
	}
	region := html[i:]
	region = region[:strings.Index(region, ">")]
	for _, want := range []string{
		`hx-get="/api/v1alpha1/instances/pii-lab"`,
		"sse:ladder from:body",
		`hx-swap="innerHTML"`,
	} {
		if !strings.Contains(region, want) {
			t.Errorf("the ladder region lacks %s: %s", want, region)
		}
	}
	// And the surface's own parts sit outside it, so a swap cannot take
	// them with it.
	ladderEnd := strings.Index(html, "</div>")
	for _, outside := range []string{`class="start-here`, `class="tabs"`, `id="rail"`} {
		if at := strings.Index(html, outside); at >= 0 && at > i && at < ladderEnd {
			t.Errorf("%s sits inside the ladder region and would be swapped away", outside)
		}
	}
}

// A step never claims more than the engine judged (invariant 3, UX §12).
func TestARailNeverClaimsAnUnjudgedStepPassed(t *testing.T) {
	r, _ := New()
	d := RailData{Instance: "pii-lab", Mode: ModeGuided, Playbook: fixturePlaybook(), Results: map[string]engine.CheckpointView{}}
	got, err := r.Fragment(FragmentRail, d)
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	for _, forbidden := range []string{"passed", "self-verified", `class="result status-pass`} {
		if strings.Contains(html, forbidden) {
			t.Errorf("a rail with no results renders %q", forbidden)
		}
	}
	// Counted on the result lines themselves. The spine's dots say the
	// same words now — one per step, for a screen reader (UX §4's
	// pairing, round 23) — so counting the whole document counts them
	// too. The claim here is about the result lines and is unchanged.
	if strings.Count(html, `<span class="word mono">not verified yet</span>`) != 2 {
		t.Errorf("both checkpointed steps must read as unverified:\n%s", html)
	}
}

// UX §6: secrets are never present in the DOM before the click.
func TestTheCredentialListCarriesNoValue(t *testing.T) {
	r, _ := New()
	d := SecretsData{Instance: "pii-lab", CSRF: "t", Secrets: []engine.SecretView{
		{Name: "beta-admin", Kind: "password", DeclaredBy: []string{"beta"}},
	}}
	got, _ := r.Fragment(FragmentSecrets, d)
	// The twin carries no value, so there is nothing to leak; assert the
	// mask is what stands in its place.
	if !strings.Contains(string(got), "●●●●●●") {
		t.Errorf("the credential list must render the mask:\n%s", got)
	}
	// One reveal control per secret and no collective one: the count of
	// reveal buttons equals the count of secrets.
	if n := strings.Count(string(got), `class="button reveal"`); n != 1 {
		t.Errorf("one reveal control per secret, got %d", n)
	}
}

// UX §8, Presenter hard rules: notes are the presenter's, and Guided
// must not carry them into the learner's DOM.
func TestGuidedCarriesNoPresenterNotes(t *testing.T) {
	r, _ := New()
	pb := fixturePlaybook()
	guided, _ := r.Fragment(FragmentRail, RailData{Instance: "x", Mode: ModeGuided, Playbook: pb, Results: map[string]engine.CheckpointView{}})
	presenter, _ := r.Fragment(FragmentRail, RailData{Instance: "x", Mode: ModePresenter, Playbook: pb, Results: map[string]engine.CheckpointView{}})
	note := "Say out loud that nothing is redacted yet"
	if strings.Contains(string(guided), note) {
		t.Errorf("Guided carries a presenter note")
	}
	if !strings.Contains(string(presenter), note) {
		t.Errorf("Presenter lacks its notes")
	}
	// Presenter runs verification silently: no Verify button to press.
	if strings.Contains(string(presenter), "verify-button") {
		t.Errorf("Presenter shows a Verify button; UX §8 says it runs silently")
	}
	if !strings.Contains(string(guided), "verify-button") {
		t.Errorf("Guided lacks its Verify button")
	}
}

// The scoreboard never launders an attestation into a machine pass.
func TestTheScoreboardMarksAnAttestationAsSelfVerified(t *testing.T) {
	r, _ := New()
	got, _ := r.Fragment(FragmentEvidence, EvidenceData{Instance: "pii-lab", Checkpoints: fixtureScoreboard()})
	html := string(got)
	i := strings.Index(html, "routes-understood")
	if i < 0 {
		t.Fatalf("no attested row:\n%s", html)
	}
	row := html[max(0, i-400) : i+200]
	if !strings.Contains(row, "◇") || !strings.Contains(row, "self-verified") {
		t.Errorf("an attested row must read ◇ self-verified:\n%s", row)
	}
}

// The expectation column reads the authored expectation, and a JSON
// number keeps the shape it was authored in.
func TestTheScoreboardRendersExpectationsExactly(t *testing.T) {
	var expect map[string]any
	if err := json.Unmarshal([]byte(`{"count":0,"status":200}`), &expect); err != nil {
		t.Fatal(err)
	}
	got := expectation(engine.CheckpointView{Adapter: "http", Expect: expect})
	if got != "count 0 · status 200" {
		t.Errorf("expectation rendered %q", got)
	}
}

// Journey §2 stage 3: the First Green result line is a receipt, not a
// checkmark — it says what was checked against reality, in the adapter's
// own words, and the console never paraphrases it.
func TestTheFirstGreenLineShowsTheReceipt(t *testing.T) {
	r, _ := New()
	receipt := `queried gamma: 0 events matched "ssn=" — verified`
	line := resultLine("pii-lab", "pii-redaction", "mask-them",
		&state.CheckpointResult{ID: "no-ssn-in-index", Status: "pass", At: at(2), Duration: "1.4s", Message: receipt,
			Evidence: "/api/v1alpha1/instances/pii-lab/evidence/ev_01M1"}, nil)
	got, err := r.Fragment(FragmentResult, line)
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	// html/template escapes the quotes; the text must survive unchanged.
	if !strings.Contains(html, `queried gamma: 0 events matched &#34;ssn=&#34; — verified`) {
		t.Errorf("the pass line does not carry the adapter's receipt:\n%s", html)
	}
	if !strings.Contains(html, "1.4s") {
		t.Errorf("the pass line does not report its duration honestly:\n%s", html)
	}
	if !strings.Contains(html, "evidence") {
		t.Errorf("the pass line does not link its evidence:\n%s", html)
	}
	// Passing leaves no residue: no hint beside a pass (UX §6).
	if strings.Contains(html, `class="hint"`) {
		t.Errorf("a passing step still shows a hint:\n%s", html)
	}
}

// Review round 1. Four controls in the rail and the reset
// dialog posted to endpoints whose answer they could not use. Each is a
// rule a golden shows but does not state, so each is stated here.

// TestVerifyPostsWhereTheVerdictComesFrom: a machine checkpoint runs, a
// human's confirmation is attested. `…/run` on an attest checkpoint
// records a failed evaluation saying it awaits confirmation and can
// never produce the attested result, so a learner offered only that
// button could not complete a self-confirmation step at all.
func TestVerifyPostsWhereTheVerdictComesFrom(t *testing.T) {
	r, _ := New()
	d := RailData{Instance: "pii-lab", Mode: ModeGuided, Playbook: fixturePlaybook(),
		CSRF: "t", Results: map[string]engine.CheckpointView{}}
	got, err := r.Fragment(FragmentRail, d)
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	// The machine checkpoint of the fixture and the attest one, each to
	// its own endpoint, each carrying the step it belongs to — and the
	// playbook, which round 9 added because the answer has to know which
	// steps are on the page (a checkpoint's `steps` are qualified
	// `playbook/step`). Still exact assertions, on longer strings.
	for _, want := range []string{
		`hx-post="/api/v1alpha1/instances/pii-lab/checkpoints/no-ssn-in-index/run?step=mask-them&amp;playbook=pii-redaction"`,
		`hx-post="/api/v1alpha1/instances/pii-lab/checkpoints/routes-understood/attest?step=confirm&amp;playbook=pii-redaction"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the rail does not carry %s\n%s", want, html)
		}
	}
	if strings.Contains(html, "routes-understood/run") {
		t.Errorf("an attest checkpoint is posted to /run, which can never attest it")
	}
}

// TestTheStepIDSurvivesAVerify: the result fragment comes back with the
// id the button targets. Without `?step=`, a step whose id differs from
// its checkpoint's got back an element identified by the checkpoint, so
// the button's `hx-target` no longer resolved and a second Verify — the
// one after a failed objective is fixed — went nowhere.
func TestTheStepIDSurvivesAVerify(t *testing.T) {
	r, _ := New()
	d := RailData{Instance: "pii-lab", Mode: ModeGuided, Playbook: fixturePlaybook(),
		CSRF: "t", Results: map[string]engine.CheckpointView{}}
	got, err := r.Fragment(FragmentRail, d)
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	// The fixture's step ids differ from their checkpoint ids, which is
	// the case that broke.
	for _, pair := range []struct{ step, checkpoint string }{
		{"mask-them", "no-ssn-in-index"},
		{"confirm", "routes-understood"},
	} {
		if pair.step == pair.checkpoint {
			t.Fatalf("the fixture must differ to prove anything: %s", pair.step)
		}
		if !strings.Contains(html, "?step="+pair.step+"&amp;playbook=pii-redaction") {
			t.Errorf("the verify of step %s does not name it in the request", pair.step)
		}
		if !strings.Contains(html, `hx-target="#result-`+pair.step+`"`) {
			t.Errorf("the verify of step %s does not target its own result", pair.step)
		}
	}
}

// TestControlsDoNotSwapAJobEnvelopeIntoThePage: a seed press and a reset
// both answer 202 with a job, and neither has an HTML twin — a fragment
// may render only what its JSON twin contains (ADR-0003), and these
// contain a job. So neither swaps: the seed's control stays a button and
// the reset leaves the lab surface where it is, with the ladder — which
// is on the feed — narrating what happens next.
func TestControlsDoNotSwapAJobEnvelopeIntoThePage(t *testing.T) {
	r, _ := New()
	rail, err := r.Fragment(FragmentRail, RailData{Instance: "pii-lab", Mode: ModeGuided,
		Playbook: fixturePlaybook(), CSRF: "t", Results: map[string]engine.CheckpointView{}})
	if err != nil {
		t.Fatal(err)
	}
	// The rule is unchanged and so is this test's job: a seed's 202 job
	// envelope has no HTML twin, so it never reaches the page. Round 9
	// moved *where* that holds — the control is driven from console.js
	// now, because `hx-swap="none"` also threw away the fact that the
	// job had finished, and a learner could not tell whether the seed
	// happened. So it makes no htmx request at all, and what it writes
	// is its own receipt, never the server's JSON.
	seed := section(string(rail), `class="button primary seed-button"`)
	if seed == "" {
		t.Fatalf("the fixture has no seed action to check")
	}
	for _, forbidden := range []string{"hx-post", "hx-swap", "hx-target"} {
		if strings.Contains(seed, forbidden) {
			t.Errorf("the seed control carries %s, so its job envelope can reach the page:\n%s", forbidden, seed)
		}
	}
	if !strings.Contains(seed, `data-actions="seed:`) {
		t.Errorf("the seed control does not name the seed it sends:\n%s", seed)
	}
	reset, err := r.Fragment(FragmentResetPlan, ResetData{Instance: "pii-lab", CSRF: "t",
		Plan: &engine.ResetPlan{Destroyed: []string{"container gamma"}, Survives: []string{"its evidence journal"}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(reset), `hx-target="#main"`) {
		t.Errorf("the reset form replaces the lab surface with the job envelope:\n%s", reset)
	}
	if !strings.Contains(string(reset), `hx-swap="none"`) {
		t.Errorf("the reset form does not say it swaps nothing:\n%s", reset)
	}
}

// TestTheRailCarriesTheProgressItWillSendBack: the page writes the
// learner's position and earned statuses through `PUT …/progress`, and
// that endpoint replaces the record whole — so the rail hands the page
// the record to change one field of, rather than letting it invent one.
func TestTheRailCarriesTheProgressItWillSendBack(t *testing.T) {
	r, _ := New()
	p := &state.Progress{Instance: "pii-lab", Playbook: "pii-redaction", CurrentStep: "mask-them",
		Steps: map[string]state.StepProgress{"send-events": {Status: "pass"}}}
	d := RailData{Instance: "pii-lab", Mode: ModeGuided, Playbook: fixturePlaybook(),
		Progress: p, CSRF: "t", Results: map[string]engine.CheckpointView{}}
	got, err := r.Fragment(FragmentRail, d)
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	for _, want := range []string{
		`data-instance="pii-lab"`,
		`data-playbook="pii-redaction"`,
		`data-csrf="t"`,
		"current_step",
		"send-events",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the rail does not carry %q for the progress write:\n%s", want, html)
		}
	}
	// The body it carries is the twin, and parses as one.
	var body struct {
		CurrentStep string                        `json:"current_step"`
		Steps       map[string]state.StepProgress `json:"steps"`
	}
	if err := json.Unmarshal([]byte(d.ProgressBody()), &body); err != nil {
		t.Fatalf("the progress body is not JSON: %v", err)
	}
	if body.CurrentStep != "mask-them" || body.Steps["send-events"].Status != "pass" {
		t.Fatalf("the progress body is not the record: %+v", body)
	}
}

// section returns the element containing needle, for asserting about one
// control rather than the whole fragment.
func section(html, needle string) string {
	i := strings.Index(html, needle)
	if i < 0 {
		return ""
	}
	start := strings.LastIndex(html[:i], "<button")
	if start < 0 {
		start = 0
	}
	end := strings.Index(html[i:], "</button>")
	if end < 0 {
		return html[start:]
	}
	return html[start : i+end]
}

// Review round 2. Six more rules a golden shows but does
// not state, and one the page could not have honoured at all.

// TestARevealedCredentialCarriesItsOwnWayBack: the remask has to work
// wherever a reveal control appears, and it appears in two places — the
// credentials table and a playbook step's actions. A swap aimed at an
// ancestor only one of them has left the value in the DOM for good.
func TestARevealedCredentialCarriesItsOwnWayBack(t *testing.T) {
	r, _ := New()
	got, err := r.Fragment(FragmentReveal, RevealData{Instance: "pii-lab", Name: "admin",
		Value: "s3cr3t", RemaskAfter: "30s", Seconds: 30, CSRF: "t"})
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	// The fragment holds the value, the countdown, and the control that
	// returns when the value goes.
	for _, want := range []string{`class="value mono"`, `class="muted countdown mono"`, `class="masked"`,
		`class="button reveal"`, `hx-target="closest .revealed"`} {
		if !strings.Contains(html, want) {
			t.Errorf("the reveal fragment lacks %q:\n%s", want, html)
		}
	}
	// And it does not reach for an ancestor that may not be there.
	if strings.Contains(html, "closest .secrets") {
		t.Errorf("the remask targets an ancestor a playbook step does not have")
	}
	// Both reveal controls hand their own place to the fragment, so the
	// fragment's own control lands where the button was.
	for _, frag := range []struct {
		name string
		data any
	}{
		{FragmentSecrets, SecretsData{Instance: "pii-lab", CSRF: "t",
			Secrets: []engine.SecretView{{Name: "admin", Kind: "password"}}}},
		{FragmentRail, RailData{Instance: "pii-lab", Mode: ModeGuided, Playbook: fixturePlaybook(),
			CSRF: "t", Results: map[string]engine.CheckpointView{}}},
	} {
		out, err := r.Fragment(frag.name, frag.data)
		if err != nil {
			t.Fatal(err)
		}
		if i := strings.Index(string(out), "/reveal"); i >= 0 {
			control := string(out)[max(0, i-400) : i+300]
			if !strings.Contains(control, `hx-target="this"`) {
				t.Errorf("the %s reveal control does not hand its own place to the fragment:\n%s", frag.name, control)
			}
		}
	}
}

// TestEveryPlaybookCanBeOpened: the rows were headings. A lab's second
// playbook, and the Presenter mode Manual §3 documents, could not be
// reached from the console at all.
func TestEveryPlaybookCanBeOpened(t *testing.T) {
	r, _ := New()
	pb := fixturePlaybook().PlaybookSummary
	second := pb
	second.Name, second.Title, second.Modes = "second", "Second Playbook", []string{"guided"}
	got, err := r.Fragment(FragmentPlaybooks, PlaybooksData{Instance: "pii-lab",
		Playbooks: []engine.PlaybookSummary{pb, second}})
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	for _, want := range []string{
		`hx-get="/api/v1alpha1/instances/pii-lab/playbooks/pii-redaction"`,
		`hx-get="/api/v1alpha1/instances/pii-lab/playbooks/pii-redaction?mode=presenter"`,
		`hx-get="/api/v1alpha1/instances/pii-lab/playbooks/second"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the chooser does not offer %s:\n%s", want, html)
		}
	}
	// A mode a playbook does not declare is not offered: a link to a
	// refusal is worse than no link.
	if strings.Contains(html, "playbooks/second?mode=presenter") {
		t.Errorf("Presenter is offered for a playbook that does not declare it")
	}
}

// TestTheLiveRegionRefreshesWhatOneEventChanges: the ladder was not the
// only thing an event changed. The start-here card offers Begin once a
// lab is ready and stops offering it after a reset, and the status bar
// carries the same rungs; both were rendered once and left behind.
func TestTheLiveRegionRefreshesWhatOneEventChanges(t *testing.T) {
	r, _ := New()
	v := engine.InstanceView{Name: "pii-lab", Template: "o11y", Mode: "delivery",
		Ladder: engine.LadderView{Stage: "ready", Condensed: "●●●●●●●", Label: "ready", Rank: 7}}
	got, err := r.Fragment(FragmentInstanceLive, InstanceLive{Instance: v,
		StartHere: StartHere{State: "ready", Headline: "Begin: PII Redaction", Action: "Begin",
			ActionHRef: "/api/v1alpha1/instances/pii-lab/playbooks/pii-redaction"}})
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	for _, want := range []string{
		`id="start-here-region" hx-swap-oob="true"`,
		`id="statusbar-ladder" hx-swap-oob="true"`,
		`id="statusbar-label" hx-swap-oob="true"`,
		"Begin: PII Redaction",
		"●●●●●●●",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the live answer does not carry %q:\n%s", want, html)
		}
	}
	// The page it swaps into carries the same ids, or the swaps land
	// nowhere: the card in the lab surface, the rungs in the shell.
	views := fixtureInstances()
	pbv := fixturePlaybook()
	surface, err := r.Fragment(FragmentLab, LabData{Instance: views[0],
		StartHere: StartHereFor(views[0], []engine.PlaybookSummary{pbv.PlaybookSummary}, nil),
		Tabs:      TabsFor(views[0]), Playbooks: []engine.PlaybookSummary{pbv.PlaybookSummary}, CSRF: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(surface), `id="start-here-region"`) {
		t.Errorf("the lab surface has no start-here region for the live answer to swap into")
	}
	var page bytes.Buffer
	if err := r.Page(&page, ShellData{Version: "0.1.0", Assets: "0123456789ab", HomeURL: "https://lab.example.com:8443",
		Instance: &views[0], Session: &SessionView{Subject: "jross", CSRF: "t"}, Body: template.HTML(surface)}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`id="statusbar-ladder"`, `id="statusbar-label"`} {
		if !strings.Contains(page.String(), want) {
			t.Errorf("the shell has no %s for the live region to swap into", want)
		}
	}
}

// TestPresenterLightsAreEarnedNotRemembered: Manual §3 promises
// checkpoints running silently as confidence lights. A light that only
// reflects a result recorded before the rail was rendered is a claim
// about the lab as it was, shown on a stage where it matters that it is
// true now.
func TestPresenterLightsAreEarnedNotRemembered(t *testing.T) {
	r, _ := New()
	got, err := r.Fragment(FragmentRail, RailData{Instance: "pii-lab", Mode: ModePresenter,
		Playbook: fixturePlaybook(), CSRF: "t", Results: map[string]engine.CheckpointView{}})
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	if !strings.Contains(html, `class="light-region"`) {
		t.Fatalf("Presenter renders no region that re-runs its checkpoint:\n%s", html)
	}
	if !strings.Contains(html, `hx-trigger="load delay:2s, every 20s"`) {
		t.Errorf("the Presenter light does not re-check on its own")
	}
	// It is still silent: no button, because a presenter presses nothing
	// (UX §8).
	if strings.Contains(html, "verify-button") {
		t.Errorf("Presenter renders a Verify button")
	}
}

// TestAnAutoStepIsOneControl: spec 0001 §8 — a step marked `auto: true`
// offers one action that runs what it declares and then judges it, not a
// shelf of separate buttons followed by Verify.
func TestAnAutoStepIsOneControl(t *testing.T) {
	r, _ := New()
	pb := fixturePlaybook()
	for i := range pb.StepList {
		if len(pb.StepList[i].Actions) > 0 {
			pb.StepList[i].Auto = true
		}
	}
	got, err := r.Fragment(FragmentRail, RailData{Instance: "pii-lab", Mode: ModeGuided,
		Playbook: pb, CSRF: "t", Results: map[string]engine.CheckpointView{}})
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	if !strings.Contains(html, `class="button primary run-step"`) {
		t.Fatalf("an auto step renders no single control:\n%s", html)
	}
	// It names every action it performs, not only the seeds: spec 0001
	// makes the one control all of the step's actions and then its
	// verification, and a reveal among them had no other way to happen.
	// Still an exact assertion, on a
	// longer string.
	if !strings.Contains(html, `data-actions="seed:events"`) {
		t.Errorf("the control does not name the actions it runs")
	}
	// And the separate seed button is not also rendered.
	if strings.Contains(html, `hx-post="/api/v1alpha1/instances/pii-lab/seeds/events"`) {
		t.Errorf("an auto step still renders its actions separately")
	}
}

// Review round 3. Round two's own fixes had consequences,
// and one of them fabricated evidence.

// TestPresenterNeverAttestsByItself: the confidence light re-runs its
// checkpoint on a timer, and `Action` resolves an attest checkpoint to
// `…/attest` — so pointing the timer at one recorded a human's
// confirmation, and an immutable evidence entry, every twenty seconds
// with nobody confirming anything. A human's claim is earned once, by a
// human, or it is not a human's claim.
func TestPresenterNeverAttestsByItself(t *testing.T) {
	r, _ := New()
	got, err := r.Fragment(FragmentRail, RailData{Instance: "pii-lab", Mode: ModePresenter,
		Playbook: fixturePlaybook(), CSRF: "t", Results: map[string]engine.CheckpointView{}})
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	// The machine checkpoint re-checks…
	if !strings.Contains(html, `hx-post="/api/v1alpha1/instances/pii-lab/checkpoints/no-ssn-in-index/run?step=mask-them&amp;playbook=pii-redaction&amp;mode=presenter"`) {
		t.Errorf("the machine checkpoint does not re-check in Presenter:\n%s", html)
	}
	// …and the attest checkpoint does not, by any route.
	if strings.Contains(html, "routes-understood/attest") {
		t.Fatalf("Presenter posts to the attest endpoint on its own:\n%s", html)
	}
	// The step is still shown, with the result it has.
	if !strings.Contains(html, `id="verify-confirm"`) {
		t.Errorf("the attest step vanished from Presenter")
	}
}

// TestAPresenterVerdictMovesItsLight: the light lives in the step's
// title, outside the region a result swaps. Without it coming along, a
// checkpoint that regressed changed its result text and left the light
// green — the stale green the re-check exists to prevent.
func TestAPresenterVerdictMovesItsLight(t *testing.T) {
	r, _ := New()
	// The rail's light carries the id the verdict will address.
	rail, err := r.Fragment(FragmentRail, RailData{Instance: "pii-lab", Mode: ModePresenter,
		Playbook: fixturePlaybook(), CSRF: "t", Results: map[string]engine.CheckpointView{}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rail), `id="light-mask-them"`) {
		t.Fatalf("the Presenter light has no id for a verdict to address:\n%s", rail)
	}
	// A Presenter verdict carries the light out of band; an ordinary one
	// does not, because in Guided there is no light to move.
	failed := &state.CheckpointResult{ID: "no-ssn-in-index", Class: "objective", Status: "fail", Duration: "1s"}
	presenter, err := r.Fragment(FragmentResult, NewPresenterResultLine("pii-lab", "pii-redaction", "mask-them", failed, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(presenter), `id="light-mask-them" hx-swap-oob="true" class="light light-warn"`) {
		t.Errorf("a Presenter verdict does not move its light:\n%s", presenter)
	}
	guided, err := r.Fragment(FragmentResult, NewResultLine("pii-lab", "pii-redaction", "mask-them", failed, nil))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(guided), "hx-swap-oob") {
		t.Errorf("a Guided verdict carries a light nobody is showing:\n%s", guided)
	}
}

// TestTheTabWordsAreRefreshedWithTheLadder: a console opened while a lab
// provisions kept its tabs saying `creating` after the services were
// ready. Only the words are swapped — replacing the strip would take the
// learner's selected tab with it.
func TestTheTabWordsAreRefreshedWithTheLadder(t *testing.T) {
	r, _ := New()
	v := engine.InstanceView{Name: "pii-lab", Mode: "delivery",
		Ladder: engine.LadderView{Stage: "ready", Condensed: "●●●●●●●", Label: "ready"},
		Services: []engine.ServiceView{
			{Name: "beta", Stage: "healthy", Word: "ready", Embed: "iframe", URL: "https://beta-pii-lab.lab.example.com:8443"},
		}}
	got, err := r.Fragment(FragmentInstanceLive, InstanceLive{Instance: v, StartHere: StartHere{State: "ready", Headline: "Begin"}})
	if err != nil {
		t.Fatal(err)
	}
	html := string(got)
	if !strings.Contains(html, `id="tab-stage-beta" hx-swap-oob="true"`) {
		t.Errorf("the live answer does not refresh the tab's word:\n%s", html)
	}
	// The strip itself is not swapped: that would reset the open tab.
	if strings.Contains(html, `role="tablist"`) {
		t.Errorf("the live answer replaces the whole tab strip")
	}
	// And the page carries the id the swap addresses.
	tabs, err := r.Fragment(FragmentTabs, TabsFor(v))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(tabs), `id="tab-stage-beta"`) {
		t.Errorf("the tab strip has no id for the word to be swapped into:\n%s", tabs)
	}
}
