// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"bytes"
	"encoding/json"
	"html/template"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/engine"
)

// UX §5, plan S14: a ladder that has fallen from ready wears the warn
// token in the bar and says so in words. The colour is never the only
// carrier — the accessible name says it too, and the sentence is what a
// screen reader is given, because the cells themselves are glyphs.
func TestAFallenLadderIsSaidInColourAndInWords(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	views := fixtureInstances()
	fallen := views[0]
	fallen.Ladder = engine.LadderView{Stage: "seeded", Condensed: "●●●●●○○", Rank: 5, Label: "seeded", Regressed: true}

	var page bytes.Buffer
	if err := r.Page(&page, ShellData{Version: "0.1.0", Assets: "0123456789ab", HomeURL: "https://lab.example.com:8443",
		Instance: &fallen, Session: &SessionView{Subject: "jross", CSRF: "t"}, Body: template.HTML("<p>x</p>")}); err != nil {
		t.Fatal(err)
	}
	got := page.String()
	for _, want := range []string{
		`class="mono ladder-bar regressed"`,
		`aria-label="ready ladder, regressed"`,
		`id="statusbar-regression" class="sr-only" role="status" aria-live="polite">The ready ladder regressed`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("a fallen ladder is missing %s", want)
		}
	}

	// The other two renderings of the same bar have no live region to
	// carry the fact, so each carries the word itself. Without it a
	// screen reader is given `●●●●●○○ seeded` for a lab that has
	// fallen and for one still climbing alike, and the colour is the
	// only carrier on those surfaces — which is the one thing UX §5
	// promises it never is.
	for _, c := range []struct{ name, fragment string }{
		{"the instance headline", FragmentInstance},
		{"the instance list", FragmentInstances},
	} {
		data := any(fallen)
		if c.fragment == FragmentInstances {
			data = []engine.InstanceView{fallen, views[0]}
		}
		out, err := r.Fragment(c.fragment, data)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		html := string(out)
		if !strings.Contains(html, `<span class="ladder-bar regressed">`) {
			t.Errorf("%s does not colour the fallen bar", c.name)
		}
		if !strings.Contains(html, `<span class="sr-only"> regressed,</span>`) {
			t.Errorf("%s leaves colour as the only carrier of the fall", c.name)
		}
		// And says it once, for the one lab that fell.
		if n := strings.Count(html, `<span class="sr-only"> regressed,</span>`); n != 1 {
			t.Errorf("%s says it %d times, want once", c.name, n)
		}
	}

	// And a ladder that has not fallen carries none of it: the region is
	// present but empty, so nothing is announced while a lab climbs.
	var climbing bytes.Buffer
	if err := r.Page(&climbing, ShellData{Version: "0.1.0", Assets: "0123456789ab", HomeURL: "https://lab.example.com:8443",
		Instance: &views[0], Session: &SessionView{Subject: "jross", CSRF: "t"}, Body: template.HTML("<p>x</p>")}); err != nil {
		t.Fatal(err)
	}
	up := climbing.String()
	if strings.Contains(up, "ladder-bar regressed") || strings.Contains(up, "regressed\"") || strings.Contains(up, "The ready ladder regressed") {
		t.Error("a climbing ladder wears no regression")
	}
	if !strings.Contains(up, `id="statusbar-regression" class="sr-only" role="status" aria-live="polite"></span>`) {
		t.Error("the live region is present and empty before the fall")
	}
}

// ADR-0003's binding rule: a fragment may render only what its JSON twin
// contains. The bar's colour and its sentence both come from one field,
// so the JSON must carry it — and must leave it out when it is false,
// which is what keeps every response that has not regressed byte-identical
// to the one before this field existed.
func TestTheRegressionIsInTheJSONTwin(t *testing.T) {
	fallen, err := json.Marshal(engine.LadderView{Stage: "seeded", Condensed: "●●●●●○○", Rank: 5, Label: "seeded", Regressed: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fallen), `"regressed":true`) {
		t.Errorf("the twin must carry the fall: %s", fallen)
	}
	climbing, err := json.Marshal(engine.LadderView{Stage: "seeded", Condensed: "●●●●●○○", Rank: 5, Label: "seeded"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(climbing), "regressed") {
		t.Errorf("a ladder that has not fallen says nothing about it: %s", climbing)
	}
}

// A live region must be mounted and observed *before* its text changes.
// An `hx-swap-oob="true"` swap is outerHTML: it replaces the region with
// a fresh node that arrives with its text already inside, and a node
// inserted that way is not an update to a live region — many screen
// readers announce nothing, which is the whole feature lost.
// The contents are swapped instead, leaving the
// region, its role and its politeness in place; the bar beside it still
// swaps whole, because its class and its accessible name must change and
// an innerHTML swap carries no attributes.
func TestTheLiveRegionStaysMountedWhileItsTextChanges(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	views := fixtureInstances()
	fallen := views[0]
	fallen.Ladder = engine.LadderView{Stage: "seeded", Condensed: "●●●●●○○", Rank: 5, Label: "seeded", Regressed: true}
	out, err := r.Fragment(FragmentInstanceLive, InstanceLive{Instance: fallen})
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	if !strings.Contains(html, `<span id="statusbar-regression" hx-swap-oob="innerHTML">`) {
		t.Error("the live region must swap its contents, not itself")
	}
	if strings.Contains(html, `id="statusbar-regression" hx-swap-oob="true"`) {
		t.Error("an outerHTML swap replaces the region and the announcement is lost")
	}
	if !strings.Contains(html, "The ready ladder regressed") {
		t.Error("the swapped contents carry the sentence")
	}
	// The bar is the opposite case and must stay whole.
	if !strings.Contains(html, `<span id="statusbar-ladder" hx-swap-oob="true" class="mono ladder-bar regressed"`) {
		t.Error("the bar swaps whole, because its class and name change")
	}
}
