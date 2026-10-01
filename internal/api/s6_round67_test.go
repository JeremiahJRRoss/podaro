// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// Review round 67: a body that is not a JSON object decodes into a struct
// pointer without error and leaves it at its zero value, so the handler
// acts on a body it never received. The worst of it is `PUT …/progress`
// with the literal `null`: an empty record persisted over the learner's
// position, silently.

// raw sends a body verbatim, so a test can post bytes json.Marshal would
// never produce from a Go value.
func raw(t *testing.T, srv *httptest.Server, method, path, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+Prefix+path, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestANullProgressBodyNeverErasesTheLearnersPosition(t *testing.T) {
	srv, eng := newCatalogServer(t)
	code, out := call(t, srv, http.MethodPost, "/instances", map[string]any{"template": "grafana-prometheus-intro", "name": "intro"})
	if code != http.StatusAccepted {
		t.Fatalf("create: %d %v", code, out)
	}
	waitJob(t, eng, out)

	// A real position, recorded the documented way.
	code, out = call(t, srv, http.MethodPut, "/instances/intro/playbooks/first-dashboard/progress",
		map[string]any{"current_step": "build-a-dashboard", "steps": map[string]any{"meet-the-stack": map[string]any{"status": "skipped"}}})
	if code != http.StatusOK {
		t.Fatalf("recording progress: %d %v", code, out)
	}

	for _, body := range []string{"null", " null ", "7", `"build-a-dashboard"`, "[]", "true"} {
		code, out := raw(t, srv, http.MethodPut, "/instances/intro/playbooks/first-dashboard/progress", body)
		if code != http.StatusBadRequest {
			t.Errorf("PUT %s: status %d, want 400 (%v)", body, code, out)
		}
		if got := errCodeOf(out); got != pdr.CodeProgressRefused {
			t.Errorf("PUT %s: code %s, want %s", body, got, pdr.CodeProgressRefused)
		}
		// And, the point of the round: the position still stands.
		code, got := call(t, srv, http.MethodGet, "/instances/intro/playbooks/first-dashboard/progress", nil)
		if code != http.StatusOK {
			t.Fatalf("reading progress back: %d %v", code, got)
		}
		if got["current_step"] != "build-a-dashboard" {
			t.Fatalf("PUT %s erased the learner's position: %v", body, got)
		}
		steps, _ := got["steps"].(map[string]any)
		if len(steps) == 0 {
			t.Fatalf("PUT %s erased the learner's step results: %v", body, got)
		}
	}

	// A well-formed object still works: the rule refuses non-objects, not
	// writes.
	code, out = call(t, srv, http.MethodPut, "/instances/intro/playbooks/first-dashboard/progress",
		map[string]any{"current_step": "drive-real-traffic", "steps": map[string]any{"meet-the-stack": map[string]any{"status": "skipped"}}})
	if code != http.StatusOK {
		t.Fatalf("a well-formed progress write was refused: %d %v", code, out)
	}
	if _, got := call(t, srv, http.MethodGet, "/instances/intro/playbooks/first-dashboard/progress", nil); got["current_step"] != "drive-real-traffic" {
		t.Fatalf("the write did not land: %v", got)
	}
}

// The same rule on the two optional bodies: an absent body is the empty
// object, but a present `null` is not, and never reads as one.
func TestANullBodyIsNotAnEmptyObjectOnVerifyOrAttest(t *testing.T) {
	srv, eng := newCatalogServer(t)
	code, out := call(t, srv, http.MethodPost, "/instances", map[string]any{"template": "grafana-prometheus-intro", "name": "intro"})
	if code != http.StatusAccepted {
		t.Fatalf("create: %d %v", code, out)
	}
	waitJob(t, eng, out)

	// An absent body is still accepted where the endpoint documents it —
	// asserted first, and its job awaited, so a later refusal cannot be
	// mistaken for this one and no case meets a busy instance.
	code, out = raw(t, srv, http.MethodPost, "/instances/intro/verify", "")
	if code != http.StatusAccepted {
		t.Fatalf("an empty verify body must still be accepted: %d %v", code, out)
	}
	waitJob(t, eng, out)

	for _, c := range []struct {
		path string
		want string
	}{
		{"/instances/intro/verify", pdr.CodeCreateRequest},
		// self-scrape-up is a real checkpoint of this template, so the
		// refusal below is the body's, not a missing id's.
		{"/instances/intro/checkpoints/self-scrape-up/attest", pdr.CodeAttestRefused},
	} {
		for _, body := range []string{"null", " null ", "[]", `"x"`, "7"} {
			code, out := raw(t, srv, http.MethodPost, c.path, body)
			if code != http.StatusBadRequest {
				t.Errorf("POST %s %s: status %d, want 400 (%v)", c.path, body, code, out)
				continue
			}
			if got := errCodeOf(out); got != c.want {
				t.Errorf("POST %s %s: code %s, want %s", c.path, body, got, c.want)
			}
		}
	}
}
