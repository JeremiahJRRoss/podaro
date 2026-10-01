// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// A reset without --yes where stdin is not a terminal is a usage problem
// (UX §7: reset asks y/N; --yes exists for scripts): exit 2 with PDR-E213
// before the engine is asked anything, the envelope on stdout under --json.
func TestResetWithoutConfirmationExitsTwo(t *testing.T) {
	code, out, errOut := run(t, "reset", "demo")
	if code != 2 || out != "" || !strings.HasPrefix(errOut, "✗ PDR-E213") || !strings.Contains(errOut, "podaro reset demo --yes") {
		t.Errorf("non-interactive reset: code=%d out=%q err=%q", code, out, errOut)
	}
	code, out, errOut = run(t, "reset", "--json", "demo")
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil || code != 2 || errOut != "" || env.Error.Code != pdr.CodeResetConfirm {
		t.Errorf("--json non-interactive reset: code=%d out=%q err=%q %v", code, out, errOut, err)
	}
	if got := exitCode(pdr.New(pdr.CodeResetConfirm, "x")); got != 2 {
		t.Errorf("E213 exits %d, want 2", got)
	}
}

// The closing block of up and reset is the User Manual §6 line: the
// class-split tally (never summed), "verified" on the baselines, the
// earned-objectives clause only when there are objectives, W101 warnings
// before it, and the console URL last, alone on its line (UX §7).
func TestCompletionLine(t *testing.T) {
	var buf bytes.Buffer
	p := render.New(&buf, false, true)
	v := &engine.InstanceView{Name: "pii-lab", Ladder: engine.LadderView{Stage: "ready"}, ConsoleURL: "https://pii-lab.lab.example.com:8443",
		Checkpoints: engine.Tally{Baseline: engine.Count{Passed: 8, Total: 8}, Objective: engine.ObjectiveCount{Failed: 4, Total: 4}}}
	completion(p, v, []state.Event{{Step: "checkpoint", Status: "warn", Detail: "PDR-W101 objective x passed at create"}, {Step: "ready", Status: "ok"}})
	want := "\n! PDR-W101 objective x passed at create\n\n✓ pii-lab is ready — baseline 8/8 verified · objectives 0/4 (those are yours to earn)\n\nhttps://pii-lab.lab.example.com:8443\n"
	if buf.String() != want {
		t.Fatalf("completion:\n%q\nwant\n%q", buf.String(), want)
	}
	buf.Reset()
	v = &engine.InstanceView{Name: "t1", Ladder: engine.LadderView{Stage: "alive"}}
	completion(p, v, nil)
	if got := buf.String(); got != "\n✓ t1 is alive — baseline 0/0 verified · objectives 0/0\n  console: not yet — podaro setup --domain <domain> opens the gateway\n" {
		t.Fatalf("completion without objectives or a gateway:\n%q", got)
	}
}

// The reset preview is two columns — destroyed, survives — with a header
// (UX §7), and the verify listing is split by class with the UX §4 glyphs.
func TestResetPreviewAndCheckpointListing(t *testing.T) {
	var buf bytes.Buffer
	p := render.New(&buf, false, true)
	renderResetPlan(p, "pii-lab", &engine.ResetPlan{Destroyed: []string{"container grafana", "container prometheus", "objective results"}, Survives: []string{"instance pii-lab", "secrets (values unchanged)"}})
	want := "reset pii-lab — impact\n  destroyed               survives\n  container grafana       instance pii-lab\n  container prometheus    secrets (values unchanged)\n  objective results\n"
	if buf.String() != want {
		t.Fatalf("preview:\n%q\nwant\n%q", buf.String(), want)
	}
	buf.Reset()
	cps := []engine.CheckpointView{
		{ID: "dashboard-exists", Class: "objective", Steps: []string{"first-dashboard/build-a-dashboard"}, Result: &state.CheckpointResult{Status: "fail", Duration: "12ms", Hint: "Create a dashboard in Grafana"}},
		{ID: "grafana-healthy", Class: "baseline", Result: &state.CheckpointResult{Status: "pass", Duration: "3ms", Message: "GET /api/health → 200"}},
		{ID: "broken", Class: "baseline", Result: &state.CheckpointResult{Status: "error", Error: pdr.New(pdr.CodeCheckpointTimeout, "did not answer")}},
		{ID: "unseen", Class: "objective", Steps: []string{"other/step"}},
	}
	renderCheckpoints(p, cps)
	// The row grammar is the ladder's (UX §5): name, glyph, word, context.
	want = "  baselines\n    broken            ! error          PDR-E401 did not answer\n" +
		"    grafana-healthy   ✓ pass           3ms · GET /api/health → 200\n" +
		"  objectives\n    dashboard-exists  ✗ fail           12ms · Create a dashboard in Grafana\n" +
		"    unseen            – pending        not yet evaluated\n"
	if buf.String() != want {
		t.Fatalf("listing:\n%q\nwant\n%q", buf.String(), want)
	}
	// --playbook keeps every baseline and only that playbook's objectives.
	kept := verified(cps, "first-dashboard")
	if len(kept) != 3 || kept[0].ID != "dashboard-exists" || kept[1].ID != "grafana-healthy" || kept[2].ID != "broken" {
		t.Fatalf("verified filter: %+v", kept)
	}
	if len(verified(cps, "")) != 4 {
		t.Fatal("no playbook keeps everything")
	}
}
