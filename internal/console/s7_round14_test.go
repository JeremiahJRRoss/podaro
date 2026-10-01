// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/engine"
)

// The reset form swaps nothing on success and must keep doing so: its
// 202 is a job envelope, and a fragment may render only what its JSON
// twin contains (ADR-0003). But `hx-swap="none"` threw away the *failure*
// as well. The console asks htmx to swap every response (layout.html),
// so a refusal renders wherever the control was aiming — and this one
// aims nowhere: a reset the engine refused (another exclusive job holds
// the instance: 409, PDR-E201) left the button re-enabled and the page
// unchanged, and no ladder event is produced for a reset that never
// started. The operator pressed a button and was told nothing at all.
//
// So the dialog carries the region a failure lands in. The region is the
// template's, not the script's: what lands in it is the server's own
// error fragment, swapped by htmx once console.js re-aims the failure
// here, and a page whose script never ran shows an empty region rather
// than a receipt nobody wrote.
func TestTheResetDialogHasSomewhereForARefusalToLand(t *testing.T) {
	r, _ := New()
	reset, err := r.Fragment(FragmentResetPlan, ResetData{Instance: "pii-lab", CSRF: "t",
		Plan: &engine.ResetPlan{Destroyed: []string{"container gamma"}, Survives: []string{"its evidence journal"}}})
	if err != nil {
		t.Fatal(err)
	}
	html := string(reset)
	// The success path is unchanged: the job envelope still reaches no
	// part of the page.
	if !strings.Contains(html, `hx-swap="none"`) {
		t.Fatalf("the reset form no longer says it swaps nothing:\n%s", html)
	}
	tag := openTag(html, `class="action-output"`)
	if tag == "" {
		t.Fatalf("the reset dialog offers a refusal nowhere to land:\n%s", html)
	}
	if !strings.Contains(tag, "aria-live=") {
		t.Errorf("the region a refusal lands in is not announced: %s", tag)
	}
	// It is inside the dialog, so the handler finds it from the form that
	// was pressed and cannot land a refusal in another component's region.
	dialog := strings.Index(html, `class="reset-dialog"`)
	if dialog < 0 {
		t.Fatalf("the reset fragment is no longer the reset dialog:\n%s", html)
	}
	if strings.Index(html, `class="action-output"`) < dialog {
		t.Errorf("the region sits outside the reset dialog, so a refusal cannot be routed to it:\n%s", html)
	}
}

// openTag is the whole opening tag of the element carrying needle, or ""
// when the markup does not carry it — never a slice taken from a index
// of -1, which reads as "found it at the start" and hides the miss.
func openTag(html, needle string) string {
	i := strings.Index(html, needle)
	if i < 0 {
		return ""
	}
	start := strings.LastIndex(html[:i], "<")
	end := strings.Index(html[i:], ">")
	if start < 0 || end < 0 {
		return ""
	}
	return html[start : i+end+1]
}
