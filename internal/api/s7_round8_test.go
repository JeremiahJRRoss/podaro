// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"
	"strings"
	"testing"
)

// Review round 8: Author preview is the authoring instance's
// own surface, and railMode never asked which kind of instance it was
// on. That was harmless while the manner rendered like Guided; round 6
// gave it the notes UX §8 promises, so `?mode=author` on a delivery
// instance became a way for anyone with the lab open to read the
// presenter notes their author wrote for someone else — the thing
// Guided's manners exist to prevent.
//
// The mode is engine-enforced everywhere else. It is enforced here too:
// a delivery instance falls back to Guided, the safe default, rather
// than being refused, because a mistyped manner must never drop the
// Verify button a learner needs (the rule railMode already followed).
func TestAuthorPreviewIsRefusedOnADeliveryInstance(t *testing.T) {
	srv, eng := newCatalogServer(t)
	code, out := call(t, srv, http.MethodPost, "/instances", map[string]any{"template": "grafana-prometheus-intro", "name": "intro"})
	if code != http.StatusAccepted {
		t.Fatalf("create: %d %v", code, out)
	}
	waitJob(t, eng, out)

	hdr := map[string]string{"Accept": "text/html"}
	author := readAll(do(t, srv, http.MethodGet, "/instances/intro/playbooks/first-dashboard?mode=author", hdr, ""))
	if strings.Contains(author, `data-mode="author"`) {
		t.Errorf("a delivery instance served Author preview:\n%s", author[:min(len(author), 400)])
	}
	if !strings.Contains(author, `data-mode="guided"`) {
		t.Errorf("the fallback is not Guided:\n%s", author[:min(len(author), 400)])
	}
	// The notes are the reason this matters.
	if strings.Contains(author, `class="notes"`) {
		t.Errorf("a delivery instance leaked the presenter notes through ?mode=author")
	}
	// Presenter is unaffected — it is a manner the playbook declares,
	// not one the instance is in.
	presenter := readAll(do(t, srv, http.MethodGet, "/instances/intro/playbooks/first-dashboard?mode=presenter", hdr, ""))
	if !strings.Contains(presenter, `data-mode="presenter"`) {
		t.Errorf("Presenter stopped working on a delivery instance")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
