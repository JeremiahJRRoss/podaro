// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// Review round 68: round 67 refused a body that was not an object, but
// `{"current_step":null,"steps":null}` *is* an object — and
// `encoding/json` leaves both fields at their zero values, so it still
// erased the learner's position. A member that is present and null is
// refused for the same reason the whole body is.

func TestANullMemberNeverErasesTheLearnersPosition(t *testing.T) {
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
		`{"current_step":null,"steps":null}`,
		`{"current_step":null}`,
		`{"steps":null}`,
		`{"current_step":"build-a-dashboard","steps":null}`,
		`{ "steps" : null }`,
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
		steps, _ := got["steps"].(map[string]any)
		if len(steps) == 0 {
			t.Fatalf("PUT %s erased the learner's step results: %v", body, got)
		}
	}

	// A null one level down is a different error, and already refused by
	// name: the engine judges the status it decodes to, not the null.
	code, out = raw(t, srv, http.MethodPut, "/instances/intro/playbooks/first-dashboard/progress",
		`{"current_step":"build-a-dashboard","steps":{"meet-the-stack":null}}`)
	if code != http.StatusBadRequest || errCodeOf(out) != pdr.CodeProgressRefused {
		t.Errorf("a null step: %d %v", code, out)
	}

	// And a well-formed write still lands.
	if code, out := call(t, srv, http.MethodPut, "/instances/intro/playbooks/first-dashboard/progress",
		map[string]any{"current_step": "drive-real-traffic", "steps": map[string]any{"meet-the-stack": map[string]any{"status": "skipped"}}}); code != http.StatusOK {
		t.Fatalf("a well-formed progress write was refused: %d %v", code, out)
	}
}

// The rule is the helper's, so it holds on every body it reads.
func TestANullMemberIsRefusedOnVerifyAndAttest(t *testing.T) {
	srv, eng := newCatalogServer(t)
	code, out := call(t, srv, http.MethodPost, "/instances", map[string]any{"template": "grafana-prometheus-intro", "name": "intro"})
	if code != http.StatusAccepted {
		t.Fatalf("create: %d %v", code, out)
	}
	waitJob(t, eng, out)

	for _, c := range []struct{ path, body, want string }{
		{"/instances/intro/verify", `{"playbook":null}`, pdr.CodeCreateRequest},
		{"/instances/intro/checkpoints/self-scrape-up/attest", `{"note":null}`, pdr.CodeAttestRefused},
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
	// An empty object is still the documented way to say "no options".
	if code, out := raw(t, srv, http.MethodPost, "/instances/intro/verify", `{}`); code != http.StatusAccepted {
		t.Fatalf("an empty verify object must still be accepted: %d %v", code, out)
	}
}
