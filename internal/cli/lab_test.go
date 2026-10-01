// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// run executes the CLI in-process with stdout and stderr captured.
func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	capture := func(f **os.File) (*os.File, func() string) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		orig := *f
		*f = w
		done := make(chan string)
		go func() {
			var buf bytes.Buffer
			_, _ = io.Copy(&buf, r)
			done <- buf.String()
		}()
		return w, func() string {
			w.Close()
			*f = orig
			return <-done
		}
	}
	_, outDone := capture(&os.Stdout)
	_, errDone := capture(&os.Stderr)
	cmd := newRoot()
	cmd.SetArgs(args)
	err := cmd.Execute()
	code = exitCode(err)
	return code, outDone(), errDone()
}

var (
	catalogDir = filepath.Join("..", "..", "scenarios", "grafana-prometheus-intro")
	brokenDir  = filepath.Join("..", "lab", "testdata", "broken", "schema")
	unreadable = filepath.Join("..", "lab", "testdata", "broken", "manifest-unreadable")
)

func TestLabValidateExitCodes(t *testing.T) {
	if code, out, _ := run(t, "lab", "validate", catalogDir); code != 0 || !strings.HasPrefix(out, "✓ "+catalogDir) || !strings.Contains(out, "valid") {
		t.Errorf("valid lab: code=%d out=%q", code, out)
	}
	code, out, errOut := run(t, "lab", "validate", brokenDir)
	if code != 1 || out != "" || !strings.HasPrefix(errOut, "✗ PDR-E101") || !strings.Contains(errOut, "lab.yaml:4") {
		t.Errorf("broken lab: code=%d out=%q err=%q", code, out, errOut)
	}
	// A playbook that is not YAML is still a failed validation (exit 1),
	// not a precondition problem.
	if code, _, errOut := run(t, "lab", "validate", unreadable); code != 1 || !strings.HasPrefix(errOut, "✗ PDR-E100") {
		t.Errorf("unreadable playbook: code=%d err=%q", code, errOut)
	}
	// A missing template path is doctor-shaped: exit 2 with the anatomy —
	// and under --json the envelope still lands on stdout.
	missing := filepath.Join("..", "lab", "testdata", "nope")
	if code, _, errOut := run(t, "lab", "validate", missing); code != 2 || !strings.HasPrefix(errOut, "✗ PDR-E100") {
		t.Errorf("missing path: code=%d err=%q", code, errOut)
	}
	for _, sub := range []string{"validate", "plan"} {
		code, out, errOut := run(t, "lab", sub, "--json", missing)
		var env struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(out), &env); err != nil || code != 2 || errOut != "" || env.Error.Code != "PDR-E100" {
			t.Errorf("%s --json missing path: code=%d out=%q err=%q %v", sub, code, out, errOut, err)
		}
	}
}

func TestLabValidateJSONShapes(t *testing.T) {
	code, out, _ := run(t, "lab", "validate", "--json", catalogDir)
	var ok struct {
		Valid    bool  `json:"valid"`
		Warnings []any `json:"warnings"`
	}
	if err := json.Unmarshal([]byte(out), &ok); err != nil || code != 0 || !ok.Valid || ok.Warnings == nil {
		t.Errorf("valid --json: code=%d out=%q err=%v", code, out, err)
	}
	code, out, errOut := run(t, "lab", "validate", "--json", brokenDir)
	var bad struct {
		Error struct {
			Code    string `json:"code"`
			Details []struct {
				Code string `json:"code"`
				Path string `json:"path"`
				Hint string `json:"hint"`
			} `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(out), &bad); err != nil || code != 1 || errOut != "" {
		t.Fatalf("broken --json: code=%d out=%q err=%q %v", code, out, errOut, err)
	}
	if bad.Error.Code != "PDR-E101" || len(bad.Error.Details) != 1 || !strings.HasSuffix(bad.Error.Details[0].Path, "lab.yaml:4") || bad.Error.Details[0].Code != "PDR-E101" {
		t.Errorf("envelope = %+v", bad.Error)
	}
}

func TestLabPlanJSON(t *testing.T) {
	code, out, _ := run(t, "lab", "plan", "--json", catalogDir)
	var body struct {
		Plan struct {
			Services []struct {
				Name  string `json:"name"`
				Image struct {
					Digest string `json:"digest"`
				} `json:"image"`
			} `json:"services"`
			Licenses []struct {
				ID string `json:"id"`
			} `json:"licenses"`
			Secrets []struct {
				Name string `json:"name"`
				Kind string `json:"kind"`
			} `json:"secrets"`
		} `json:"plan"`
	}
	if err := json.Unmarshal([]byte(out), &body); err != nil || code != 0 {
		t.Fatalf("plan --json: code=%d err=%v out=%q", code, err, out)
	}
	if len(body.Plan.Services) != 2 || len(body.Plan.Licenses) != 0 || len(body.Plan.Secrets) != 1 {
		t.Errorf("plan counts: %d services, %d licenses, %d secrets", len(body.Plan.Services), len(body.Plan.Licenses), len(body.Plan.Secrets))
	}
	for _, s := range body.Plan.Services {
		if !strings.HasPrefix(s.Image.Digest, "sha256:") {
			t.Errorf("service %s not digest-pinned in the plan", s.Name)
		}
	}
	if code, _, errOut := run(t, "lab", "plan", "--profile", "huge", catalogDir); code != 1 || !strings.HasPrefix(errOut, "✗ PDR-E102") {
		t.Errorf("unknown profile: code=%d err=%q", code, errOut)
	}
	if code, _, errOut := run(t, "lab", "plan", brokenDir); code != 1 || !strings.HasPrefix(errOut, "✗ PDR-E101") {
		t.Errorf("plan of a broken lab: code=%d err=%q", code, errOut)
	}
}
