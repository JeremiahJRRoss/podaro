// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// The reconciliation plan's R3 over the socket door: an instance an
// earlier build created from a template the owner has since retired is
// read — the instance object says it is unsupported, its evidence and
// its reports answer 200 — and every route that would run its lab answers
// 409 with PDR-E215, never a 500. Destroy is admitted. The name is read
// from the embedded manifest.
func TestAnUnsupportedInstanceOverTheSocketDoor(t *testing.T) {
	m := podaro.Retirement()
	if len(m.Scenarios) == 0 {
		t.Fatal("the embedded manifest lists no retired template")
	}
	store := state.NewMemory()
	srv, eng := newServerWith(t, store)
	now := time.Now().UTC().Truncate(time.Second)
	if err := store.PutInstance(state.Instance{Name: "old-lab", Template: m.Scenarios[0].Name, Version: "1.0.0", Mode: state.ModeDelivery,
		Source: "/nowhere", Created: now, Updated: now, Stage: state.StageReady, Reached: state.StageReady}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutCheckpointResult(state.CheckpointResult{Instance: "old-lab", ID: "events-arrived", Class: "baseline", Adapter: "http", Status: "pass", At: now}); err != nil {
		t.Fatal(err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/instances/old-lab/verify", nil},
		{http.MethodPost, "/instances/old-lab/seeds/any", nil},
		{http.MethodPost, "/instances/old-lab/reset", nil},
		{http.MethodGet, "/instances/old-lab/reset-plan", nil},
		{http.MethodPost, "/instances/old-lab/checkpoints/events-arrived/run", nil},
		{http.MethodPost, "/instances/old-lab/checkpoints/events-arrived/attest", map[string]any{"note": "seen"}},
		{http.MethodGet, "/instances/old-lab/checkpoints", nil},
		{http.MethodGet, "/instances/old-lab/playbooks", nil},
		{http.MethodPut, "/instances/old-lab/playbooks/any/progress", map[string]any{"current_step": "one"}},
		{http.MethodGet, "/instances/old-lab/secrets", nil},
		{http.MethodGet, "/instances/old-lab/services/index/logs", nil},
	} {
		status, out := call(t, srv, c.method, c.path, c.body)
		if status != http.StatusConflict || errCodeOf(out) != pdr.CodeInstanceUnsupported {
			t.Errorf("%s %s: %d %s, want 409 %s", c.method, c.path, status, errCodeOf(out), pdr.CodeInstanceUnsupported)
		}
	}

	status, out := call(t, srv, http.MethodGet, "/instances/old-lab", nil)
	inst, _ := out["instance"].(map[string]any)
	ladder, _ := inst["ladder"].(map[string]any)
	if status != http.StatusOK || inst["unsupported"] != "retired template" || ladder["label"] != "unsupported · retired template" {
		t.Errorf("the instance object: %d %v", status, out)
	}
	status, out = call(t, srv, http.MethodGet, "/instances/old-lab/evidence", nil)
	if entries, _ := out["evidence"].([]any); status != http.StatusOK || len(entries) != 1 {
		t.Errorf("the evidence: %d %v", status, out)
	}
	for _, p := range []string{"/instances/old-lab/evidence/report.html", "/instances/old-lab/evidence/report.junit.xml"} {
		resp := do(t, srv, http.MethodGet, p, nil, "")
		body := readAll(resp)
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, "events-arrived") {
			t.Errorf("%s: %d, the recorded result absent", p, resp.StatusCode)
		}
	}
	if status, html := getHTML(t, srv, "/instances/old-lab"); status != http.StatusOK || !strings.Contains(html, "unsupported · retired template") {
		t.Errorf("the console's instance fragment: %d\n%s", status, html)
	}

	status, out = call(t, srv, http.MethodDelete, "/instances/old-lab?confirm=old-lab", nil)
	if status != http.StatusAccepted {
		t.Fatalf("destroy: %d %v", status, out)
	}
	waitJob(t, eng, out)
	if status, _ := call(t, srv, http.MethodGet, "/instances/old-lab", nil); status != http.StatusNotFound {
		t.Errorf("after destroy: %d", status)
	}
}
