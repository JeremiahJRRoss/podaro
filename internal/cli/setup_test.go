// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/config"
)

// TestAnExplicitPortIsNeverTheFlagsAbsence holds the other half of
// `--port`'s contract through the flag itself: zero is a port an operator
// can type, and an out-of-range one, so `--port=0` meets the documented
// 1–65535 in the preflight. Only never passing the flag keeps the
// configured port — a distinction the value alone cannot carry, so the
// command reads the flag's own state.
func TestAnExplicitPortIsNeverTheFlagsAbsence(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	path := config.Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	working := "domain: lab.example.com\ngateway:\n  port: 8443\n"
	if err := os.WriteFile(path, []byte(working), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := run(t, "setup", "--domain", "lab.example.com", "--port", "0")
	if code == 0 || !strings.Contains(errOut, "PDR-E023") {
		t.Fatalf("--port=0 must be refused: code=%d err=%q", code, errOut)
	}
	// The refusal is the preflight's: no certificate work ran, so the
	// block names no certificate step at all.
	if strings.Contains(out, "certificate") {
		t.Fatalf("a port outside the range must stop setup before any certificate work:\n%s", out)
	}
	if raw, _ := os.ReadFile(path); string(raw) != working {
		t.Fatalf("a refused setup replaced the working configuration:\n%s", raw)
	}
}
