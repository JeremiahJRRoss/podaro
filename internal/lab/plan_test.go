// SPDX-License-Identifier: AGPL-3.0-only

package lab

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/render"
)

var update = flag.Bool("update", false, "rewrite the plan goldens under testdata/golden")

type planCase struct {
	name    string
	path    string
	lib     *Library
	profile string
}

func planCases() []planCase {
	return []planCase{
		{name: "grafana-prometheus-intro", path: filepath.Join("..", "..", "scenarios", "grafana-prometheus-intro")},
		{name: "conformance-lab", path: filepath.Join("..", "..", "hack", "fixtures", "conformance-lab")},
		{name: "valid-aliases", path: filepath.Join("testdata", "valid-aliases"), lib: testLibrary()},
	}
}

func renderPlan(t *testing.T, c planCase) (human, js []byte) {
	t.Helper()
	plan, _, err := MakePlan(PlanOptions{Options: Options{Path: c.path, Library: c.lib}, Profile: c.profile})
	if err != nil {
		t.Fatalf("%s: %v", c.name, err)
	}
	var buf bytes.Buffer
	plan.Render(render.New(&buf, false, true))
	out, err := json.MarshalIndent(map[string]any{"plan": plan}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), append(out, '\n')
}

// The P0 exit gate: plan twice → byte-identical, human and JSON alike.
func TestPlanIsDeterministic(t *testing.T) {
	for _, c := range planCases() {
		h1, j1 := renderPlan(t, c)
		h2, j2 := renderPlan(t, c)
		if !bytes.Equal(h1, h2) {
			t.Errorf("%s: human plan differs between runs", c.name)
		}
		if !bytes.Equal(j1, j2) {
			t.Errorf("%s: JSON plan differs between runs", c.name)
		}
	}
}

// Goldens pin the exact review artifact; `go test ./internal/lab -update`
// rewrites them after a deliberate change.
func TestPlanGoldens(t *testing.T) {
	for _, c := range planCases() {
		human, js := renderPlan(t, c)
		for _, g := range []struct {
			file string
			got  []byte
		}{
			{filepath.Join("testdata", "golden", c.name+".plan.txt"), human},
			{filepath.Join("testdata", "golden", c.name+".plan.json"), js},
		} {
			if *update {
				if err := os.MkdirAll(filepath.Dir(g.file), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(g.file, g.got, 0o644); err != nil {
					t.Fatal(err)
				}
				continue
			}
			want, err := os.ReadFile(g.file)
			if err != nil {
				t.Fatalf("%s: %v (run with -update to create)", g.file, err)
			}
			if !bytes.Equal(want, g.got) {
				t.Errorf("%s differs from golden\n--- want ---\n%s--- got ---\n%s", g.file, want, g.got)
			}
		}
	}
}

// Secrets appear by name and kind only (invariant 6): no unrendered
// reference anywhere in a plan, and each secret record carries exactly
// name, kind, and declared_by — asserted on the JSON keys so a value field
// can never slip in through a struct change.
func TestPlanSecretsCarryNoValues(t *testing.T) {
	for _, c := range planCases() {
		human, js := renderPlan(t, c)
		for _, out := range [][]byte{human, js} {
			if bytes.Contains(out, []byte("${secret:")) {
				t.Errorf("%s: plan carries a secret reference", c.name)
			}
		}
		var doc struct {
			Plan struct {
				Secrets []map[string]any `json:"secrets"`
			} `json:"plan"`
		}
		if err := json.Unmarshal(js, &doc); err != nil {
			t.Fatal(err)
		}
		for _, rec := range doc.Plan.Secrets {
			for k := range rec {
				switch k {
				case "name", "kind", "declared_by":
				default:
					t.Errorf("%s: secret record carries field %q", c.name, k)
				}
			}
		}
	}
}

func TestPlanProfileSelection(t *testing.T) {
	fixture := filepath.Join("testdata", "valid-profile")
	plan, _, err := MakePlan(PlanOptions{Options: Options{Path: fixture}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Profile == nil || plan.Profile.Name != "standard" {
		t.Fatalf("default profile should be standard, got %v", plan.Profile)
	}
	applied := false
	for _, s := range plan.Services {
		if s.Name == "prometheus" {
			applied = s.Resources.Memory == "2GiB"
		}
	}
	if !applied {
		t.Errorf("profile override not applied: prometheus memory is not the profile's 2GiB: %+v", plan.Services)
	}
	_, res, err := MakePlan(PlanOptions{Options: Options{Path: fixture}, Profile: "huge"})
	if err == nil || res == nil {
		t.Fatalf("unknown profile must fail with the validated result attached: err=%v res=%v", err, res)
	}
}
