// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// Review round 69: rounds 67 and 68 refused a body that was not an object
// and a member that was present and null — but a *misspelled* member was
// still dropped silently, leaving the destination at its zero values and
// erasing the learner's position by a third door. A member the shape does
// not have is now refused.

func TestAMisspelledMemberNeverErasesTheLearnersPosition(t *testing.T) {
	srv, eng := newCatalogServer(t)
	code, out := call(t, srv, http.MethodPost, "/instances", map[string]any{"template": "grafana-prometheus-intro", "name": "intro"})
	if code != http.StatusAccepted {
		t.Fatalf("create: %d %v", code, out)
	}
	waitJob(t, eng, out)

	code, out = call(t, srv, http.MethodPut, "/instances/intro/playbooks/first-dashboard/progress",
		map[string]any{"current_step": "build-a-dashboard", "steps": map[string]any{"meet-the-stack": map[string]any{"status": "skipped"}}})
	if code != http.StatusOK {
		t.Fatalf("recording progress: %d %v", code, out)
	}

	for _, body := range []string{
		`{"current_stap":"build-a-dashboard"}`,
		`{"currentStep":"build-a-dashboard"}`,
		`{"steps":{"meet-the-stack":{"status":"skipped"}},"extra":1}`,
	} {
		code, out := raw(t, srv, http.MethodPut, "/instances/intro/playbooks/first-dashboard/progress", body)
		if code != http.StatusBadRequest {
			t.Errorf("PUT %s: status %d, want 400 (%v)", body, code, out)
		}
		if got := errCodeOf(out); got != pdr.CodeProgressRefused {
			t.Errorf("PUT %s: code %s, want %s", body, got, pdr.CodeProgressRefused)
		}
		_, got := call(t, srv, http.MethodGet, "/instances/intro/playbooks/first-dashboard/progress", nil)
		if got["current_step"] != "build-a-dashboard" {
			t.Fatalf("PUT %s erased the learner's position: %v", body, got)
		}
		if steps, _ := got["steps"].(map[string]any); len(steps) == 0 {
			t.Fatalf("PUT %s erased the learner's step results: %v", body, got)
		}
	}

	// The shape's own members still work.
	if code, out := call(t, srv, http.MethodPut, "/instances/intro/playbooks/first-dashboard/progress",
		map[string]any{"current_step": "drive-real-traffic", "steps": map[string]any{"meet-the-stack": map[string]any{"status": "skipped"}}}); code != http.StatusOK {
		t.Fatalf("a well-formed progress write was refused: %d %v", code, out)
	}
}

// A misspelled option on the two optional bodies invoked their defaults
// silently — a verify of every playbook when one was named, an attest
// with no note when one was written.
func TestAMisspelledOptionIsRefusedRatherThanDefaulted(t *testing.T) {
	srv, eng := newCatalogServer(t)
	code, out := call(t, srv, http.MethodPost, "/instances", map[string]any{"template": "grafana-prometheus-intro", "name": "intro"})
	if code != http.StatusAccepted {
		t.Fatalf("create: %d %v", code, out)
	}
	waitJob(t, eng, out)

	for _, c := range []struct{ path, body, want string }{
		{"/instances/intro/verify", `{"playbok":"first-dashboard"}`, pdr.CodeCreateRequest},
		{"/instances/intro/checkpoints/self-scrape-up/attest", `{"notes":"looked"}`, pdr.CodeAttestRefused},
	} {
		code, out := raw(t, srv, http.MethodPost, c.path, c.body)
		if code != http.StatusBadRequest {
			t.Errorf("POST %s %s: status %d, want 400 (%v)", c.path, c.body, code, out)
			continue
		}
		if got := errCodeOf(out); got != c.want {
			t.Errorf("POST %s %s: code %s, want %s", c.path, c.body, got, c.want)
		}
	}
	// The documented bodies still work.
	if code, out := raw(t, srv, http.MethodPost, "/instances/intro/verify", `{"playbook":"first-dashboard"}`); code != http.StatusAccepted {
		t.Fatalf("a well-formed verify body was refused: %d %v", code, out)
	}
}

// A member that differs only in case is *not* an unknown member:
// encoding/json matches field names case-insensitively, so
// `{"CURRENT_STEP":…}` lands in CurrentStep — the value reaches where its
// author meant it, which is the opposite of the silent drop this round
// closed. Recorded here so the difference is deliberate rather than
// discovered again.
//
// It still replaces, because PUT replaces (API §8): a body naming only
// `current_step` leaves no steps, exactly as the correctly spelled
// `{"current_step":…}` does. That is the endpoint's documented contract,
// not a defect this round introduces or fixes.
func TestAMemberDifferingOnlyInCaseIsNotUnknown(t *testing.T) {
	srv, eng := newCatalogServer(t)
	code, out := call(t, srv, http.MethodPost, "/instances", map[string]any{"template": "grafana-prometheus-intro", "name": "intro"})
	if code != http.StatusAccepted {
		t.Fatalf("create: %d %v", code, out)
	}
	waitJob(t, eng, out)

	code, out = raw(t, srv, http.MethodPut, "/instances/intro/playbooks/first-dashboard/progress",
		`{"CURRENT_STEP":"build-a-dashboard","STEPS":{"meet-the-stack":{"status":"skipped"}}}`)
	if code != http.StatusOK {
		t.Fatalf("a case-different member is not unknown: %d %v", code, out)
	}
	got := out
	if got["current_step"] != "build-a-dashboard" {
		t.Errorf("the value did not reach current_step: %v", got)
	}
	if steps, _ := got["steps"].(map[string]any); len(steps) != 1 {
		t.Errorf("the value did not reach steps: %v", got)
	}
}
