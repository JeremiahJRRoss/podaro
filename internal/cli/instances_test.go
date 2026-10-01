// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// Usage-shaped codes exit 2 (UX §7): a malformed create request (an
// unknown --mode reaches the engine as PDR-E212) and a refused destroy
// confirmation; an operation that failed exits 1.
func TestUsageCodesExitTwo(t *testing.T) {
	for _, tc := range []struct {
		code string
		want int
	}{{pdr.CodeCreateRequest, 2}, {pdr.CodeDestroyConfirm, 2}, {pdr.CodeInstanceExists, 1}} {
		if got := exitCode(pdr.New(tc.code, "x")); got != tc.want {
			t.Errorf("%s: exit %d, want %d", tc.code, got, tc.want)
		}
	}
}

// A destroy without --yes where stdin is not a terminal is a usage
// problem: exit 2 with the anatomy on stderr, and the envelope on stdout
// under --json (UX §7).
func TestDestroyWithoutConfirmationExitsTwo(t *testing.T) {
	code, out, errOut := run(t, "destroy", "demo")
	if code != 2 || out != "" || !strings.HasPrefix(errOut, "✗ PDR-E203") || !strings.Contains(errOut, "podaro destroy demo --yes") {
		t.Errorf("non-interactive destroy: code=%d out=%q err=%q", code, out, errOut)
	}
	code, out, errOut = run(t, "destroy", "--json", "demo")
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil || code != 2 || errOut != "" || env.Error.Code != "PDR-E203" {
		t.Errorf("--json non-interactive destroy: code=%d out=%q err=%q %v", code, out, errOut, err)
	}
}

// The engine is another process with its own working directory: a
// relative directory given to `up` is sent as an absolute path, and
// anything that is not a directory here is a template name.
func TestUpSendsAbsolutePaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "lab"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	path, template, err := sourceOf("./lab")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(path) || filepath.Base(path) != "lab" || template != "" {
		t.Fatalf("relative directory: path=%q template=%q", path, template)
	}
	path, template, err = sourceOf("hello-nginx")
	if err != nil {
		t.Fatal(err)
	}
	if path != "" || template != "hello-nginx" {
		t.Fatalf("template name: path=%q template=%q", path, template)
	}
}
