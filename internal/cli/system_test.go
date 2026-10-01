// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSystemctl puts a `systemctl` on PATH that logs its arguments and
// runs the script; the service commands resolve it through PATH.
func fakeSystemctl(t *testing.T, script string) (log string) {
	t.Helper()
	dir := t.TempDir()
	log = filepath.Join(dir, "calls.log")
	body := "#!/bin/sh\nprintf '%s\\n' \"$*\" >>\"" + log + "\"\n" + script + "\n"
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

// `podaro system status|start|stop|restart` (INSTALL §2 step 6, Manual
// §15): the unit through systemctl --user, exit codes per UX §7, and
// --json on the read.
func TestSystemServiceCommands(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	// status: an active unit with no engine behind it is not healthy —
	// exit 1, both rows, the next action — and --json carries the facts.
	fakeSystemctl(t, "printf 'LoadState=loaded\\nActiveState=active\\nSubState=running\\nNRestarts=2\\nMainPID=77\\nStateChangeTimestamp=Sat 2026-09-20 18:02:11 UTC\\n'")
	code, out, errOut := run(t, "system", "status")
	if code != 1 {
		t.Fatalf("status of an active unit with no engine exits %d, want 1: %q / %q", code, out, errOut)
	}
	for _, want := range []string{"✓ service", "podaro.service · active (running) since Sat 2026-09-20 18:02:11 UTC · pid 77 · 2 restarts", "! engine", "no answer on", "→ next: journalctl --user -u podaro"} {
		if !strings.Contains(out, want) {
			t.Errorf("the status block lacks %q:\n%s", want, out)
		}
	}
	code, out, _ = run(t, "system", "status", "--json")
	if code != 1 {
		t.Fatalf("--json exits %d, want the same 1", code)
	}
	var st struct {
		Unit     string `json:"unit"`
		Loaded   bool   `json:"loaded"`
		State    string `json:"state"`
		Restarts int    `json:"restarts"`
		PID      int    `json:"pid"`
		Engine   struct {
			Socket  string `json:"socket"`
			Answers bool   `json:"answers"`
			Detail  string `json:"detail"`
		} `json:"engine"`
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		t.Fatalf("--json is not one object: %v\n%s", err, out)
	}
	if st.Unit != "podaro.service" || !st.Loaded || st.State != "active" || st.Restarts != 2 || st.PID != 77 || st.Engine.Answers || st.Engine.Detail == "" || !strings.HasSuffix(st.Engine.Socket, "/podaro/api.sock") {
		t.Errorf("--json does not carry the facts: %+v", st)
	}

	// A unit systemd does not know: exit 2, the install named.
	fakeSystemctl(t, "printf 'LoadState=not-found\\nActiveState=inactive\\nSubState=dead\\nNRestarts=0\\nMainPID=0\\nStateChangeTimestamp=\\n'")
	code, out, _ = run(t, "system", "status")
	if code != 2 || !strings.Contains(out, "not installed") || !strings.Contains(out, "→ next: podaro system install") {
		t.Errorf("status without the unit exits %d with:\n%s", code, out)
	}

	// stop: the verb reaches systemctl and the row says what happened.
	log := fakeSystemctl(t, "exit 0")
	code, out, _ = run(t, "system", "stop")
	if code != 0 || !strings.Contains(out, "✓ service") || !strings.Contains(out, "podaro.service stopped") {
		t.Errorf("stop exits %d with:\n%s", code, out)
	}
	calls, _ := os.ReadFile(log)
	if !strings.Contains(string(calls), "--user stop podaro.service") {
		t.Errorf("stop did not run systemctl --user stop podaro.service:\n%s", calls)
	}

	// A systemd that cannot be reached: PDR-E027 on stderr, exit 1, the
	// lingering remedy in the next line.
	fakeSystemctl(t, "echo 'Failed to connect to bus: No medium found' >&2; exit 1")
	code, _, errOut = run(t, "system", "stop")
	if code != 1 || !strings.Contains(errOut, "PDR-E027") || !strings.Contains(errOut, "enable-linger") {
		t.Errorf("an unreachable bus exits %d with:\n%s", code, errOut)
	}

	// The group lists the four beside install, upgrade and uninstall.
	_, out, _ = run(t, "system", "--help")
	for _, want := range []string{"install", "upgrade", "uninstall", "status", "start", "stop", "restart"} {
		if !strings.Contains(out, "  "+want+" ") {
			t.Errorf("podaro system --help does not list %q:\n%s", want, out)
		}
	}
}
