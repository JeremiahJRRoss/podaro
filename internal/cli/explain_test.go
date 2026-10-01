// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// Plan S9: `podaro explain` answers from the registry embedded in this
// binary — no engine, no socket, no network. Every case here runs with
// neither, which is the point: the moment an operator needs an error
// explained is the moment the engine may be the thing that is wrong.
func TestExplainAnswersOffline(t *testing.T) {
	code, out, errOut := run(t, "explain", "PDR-E503")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"PDR-E503", "cause", "background", "next"} {
		if !strings.Contains(out, want) {
			t.Fatalf("explain PDR-E503 printed no %q:\n%s", want, out)
		}
	}
	entry, _ := pdr.Lookup(pdr.CodeExecTimeout)
	if !strings.Contains(out, entry.Title) || !strings.Contains(out, entry.Next) {
		t.Fatalf("explain prints the registry entry:\n%s", out)
	}
	// A label column that touches its value is not a column: `background`
	// is ten characters, and the anatomy's own column is ten wide.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "  background") && !strings.HasPrefix(line, "  background  ") {
			t.Fatalf("the background row runs into its value: %q", line)
		}
	}

	// An operator types the code the way they read it.
	for _, spelling := range []string{"pdr-e503", "E503", "e503", "503", " PDR-E503 "} {
		code, got, _ := run(t, "explain", spelling)
		if code != 0 || !strings.Contains(got, "PDR-E503") {
			t.Fatalf("explain %q: exit %d\n%s", spelling, code, got)
		}
	}
}

func TestExplainJSONAndListAreTheSameRegistry(t *testing.T) {
	code, out, errOut := run(t, "explain", "PDR-E402", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	var one struct {
		Help pdr.Entry `json:"error_help"`
	}
	if err := json.Unmarshal([]byte(out), &one); err != nil {
		t.Fatalf("explain --json: %v\n%s", err, out)
	}
	want, _ := pdr.Lookup(pdr.CodeAdapterUnavailable)
	if one.Help != want {
		t.Fatalf("explain --json carried %+v, want %+v", one.Help, want)
	}

	code, out, _ = run(t, "explain", "--list", "--json")
	if code != 0 {
		t.Fatalf("explain --list --json: exit %d", code)
	}
	var all struct {
		Help []pdr.Entry `json:"error_help"`
	}
	if err := json.Unmarshal([]byte(out), &all); err != nil {
		t.Fatalf("explain --list --json: %v", err)
	}
	if len(all.Help) != len(pdr.Codes()) {
		t.Fatalf("--list carried %d codes, the registry holds %d", len(all.Help), len(pdr.Codes()))
	}
	code, plain, _ := run(t, "explain", "--list")
	if code != 0 || strings.Count(strings.TrimSpace(plain), "\n")+1 != len(pdr.Codes()) {
		t.Fatalf("--list prints one line per code: exit %d, %d lines", code, strings.Count(plain, "\n"))
	}
}

func TestExplainRefusesACodeItDoesNotHold(t *testing.T) {
	code, _, errOut := run(t, "explain", "PDR-E999")
	if code == 0 || !strings.Contains(errOut, pdr.CodeExplainUnknown) {
		t.Fatalf("an unknown code is refused with its own code: exit %d\n%s", code, errOut)
	}
	// A near miss names what the operator probably meant.
	_, _, errOut = run(t, "explain", "PDR-E504")
	if strings.Contains(errOut, pdr.CodeExplainUnknown) {
		t.Fatalf("PDR-E504 is registered: %s", errOut)
	}
	_, _, errOut = run(t, "explain", "PDR-E413")
	if strings.Contains(errOut, pdr.CodeExplainUnknown) {
		t.Fatalf("PDR-E413 is itself registered: %s", errOut)
	}
	_, _, errOut = run(t, "explain", "PDR-E509")
	if !strings.Contains(errOut, "did you mean") {
		t.Fatalf("a near miss names its neighbours: %s", errOut)
	}
}
