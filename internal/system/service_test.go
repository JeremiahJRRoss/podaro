// SPDX-License-Identifier: AGPL-3.0-only

package system

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
)

// fakeSystemctl puts a `systemctl` on PATH that appends its arguments to
// a log and behaves as the script says; the log is what the test reads.
// The service commands resolve systemctl through PATH at each call, so
// the fake is what they run.
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

// showActive is what `systemctl --user show` prints for the unit the
// manual's step 6 shows: active, running, one automatic restart behind
// it, and a main pid.
const showActive = `cat <<'OUT'
LoadState=loaded
ActiveState=active
SubState=running
NRestarts=0
MainPID=4242
StateChangeTimestamp=Sat 2026-09-20 18:02:11 UTC
OUT`

// fakeServiceEngine answers the probe on the engine's socket with the
// instances it holds, the way a running engine does.
func fakeServiceEngine(t *testing.T, names ...string) {
	t.Helper()
	sock := filepath.Join(config.RuntimeDir(), "api.sock")
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1alpha1/instances", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		parts := make([]string, 0, len(names))
		for _, n := range names {
			parts = append(parts, `{"name":"`+n+`"}`)
		}
		_, _ = w.Write([]byte(`{"instances":[` + strings.Join(parts, ",") + `]}`))
	})
	go func() { _ = http.Serve(l, mux) }()
}

func TestServiceStatusReadsSystemdAndProbesTheEngine(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	fakeSystemctl(t, showActive)

	// No engine behind an active unit: the unit is not the engine.
	st, err := ServiceStatusNow()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Loaded || st.State != "active" || st.SubState != "running" || st.PID != 4242 || st.Restarts != 0 || st.Since == "" {
		t.Errorf("systemd's words were not read: %+v", st)
	}
	if st.Engine.Answers || st.Engine.Detail == "" || st.Healthy() {
		t.Errorf("an active unit with no engine behind it was reported healthy: %+v", st)
	}

	// The engine answers: healthy.
	fakeServiceEngine(t)
	st, err = ServiceStatusNow()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Engine.Answers || !st.Healthy() || st.Engine.Detail != "" {
		t.Errorf("an answering engine was not seen: %+v", st)
	}
	if st.Engine.Socket != filepath.Join(config.RuntimeDir(), "api.sock") {
		t.Errorf("the socket named is %q", st.Engine.Socket)
	}

	// A unit systemd does not know is a host where install has not run —
	// reported, never an error.
	fakeSystemctl(t, "printf 'LoadState=not-found\\nActiveState=inactive\\nSubState=dead\\nNRestarts=0\\nMainPID=0\\nStateChangeTimestamp=\\n'")
	st, err = ServiceStatusNow()
	if err != nil {
		t.Fatal(err)
	}
	if st.Loaded || st.Healthy() {
		t.Errorf("a unit systemd does not know was reported as installed: %+v", st)
	}

	// A systemd it cannot ask is the one error status has.
	fakeSystemctl(t, "echo 'Failed to connect to bus: No medium found' >&2; exit 1")
	_, err = ServiceStatusNow()
	var pe *pdr.Error
	if !errors.As(err, &pe) || pe.Code != pdr.CodeServiceControl {
		t.Fatalf("an unreachable systemd gave %v, want %s", err, pdr.CodeServiceControl)
	}
	if !strings.Contains(pe.Cause, "No medium found") || !strings.Contains(pe.Next, "enable-linger") {
		t.Errorf("the refusal does not carry systemd's words and the lingering remedy:\n%s\n%s", pe.Cause, pe.Next)
	}
}

// TestServiceStatusBlockMatchesManual locks the block to INSTALL §2 step
// 6, the way the install block is locked to step 2.
func TestServiceStatusBlockMatchesManual(t *testing.T) {
	st := ServiceStatus{
		Unit: ServiceUnit, Loaded: true, State: "active", SubState: "running",
		Since: "Sat 2026-09-20 18:02:11 UTC", Restarts: 0, PID: 4242,
		Engine: EngineStatus{Socket: "/run/user/1001/podaro/api.sock", Answers: true},
	}
	var buf bytes.Buffer
	RenderServiceStatus(render.New(&buf, false, true), st)
	want := docBlock(t, "$ podaro system status")
	if got := buf.String(); got != want {
		t.Fatalf("status output diverges from INSTALL §2 step 6\n--- want ---\n%s--- got ---\n%s", want, got)
	}

	// The states that are not healthy each name their next action.
	for _, tc := range []struct {
		st   ServiceStatus
		want []string
	}{
		{ServiceStatus{Unit: ServiceUnit, Loaded: false}, []string{"✗ service", "not installed", "→ next: podaro system install"}},
		{ServiceStatus{Unit: ServiceUnit, Loaded: true, State: "inactive", SubState: "dead", Restarts: 0, Engine: EngineStatus{Socket: "/s"}}, []string{"✗ service", "inactive (dead)", "0 restarts", "✗ engine", "no answer on /s", "→ next: podaro system start"}},
		{ServiceStatus{Unit: ServiceUnit, Loaded: true, State: "activating", SubState: "auto-restart", Restarts: 3, Engine: EngineStatus{Socket: "/s"}}, []string{"! service", "activating (auto-restart)", "3 restarts", "→ next: journalctl --user -u podaro"}},
		{ServiceStatus{Unit: ServiceUnit, Loaded: true, State: "active", SubState: "running", Restarts: 1, Engine: EngineStatus{Socket: "/s", Detail: "dial unix /s: connect: no such file"}}, []string{"✓ service", "· 1 restart\n", "! engine", "no answer on /s · dial unix", "→ next: journalctl --user -u podaro"}},
	} {
		buf.Reset()
		RenderServiceStatus(render.New(&buf, false, true), tc.st)
		for _, w := range tc.want {
			if !strings.Contains(buf.String(), w) {
				t.Errorf("state %s/%s: the block lacks %q:\n%s", tc.st.State, tc.st.SubState, w, buf.String())
			}
		}
	}
}

func TestServiceControlRunsSystemctlAndReportsItsRefusals(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	orig := serviceAnswerWait
	serviceAnswerWait = 400 * time.Millisecond
	t.Cleanup(func() { serviceAnswerWait = orig })

	// stop: the verb reaches systemctl, the row says what happened.
	log := fakeSystemctl(t, "exit 0")
	var buf bytes.Buffer
	p := render.New(&buf, false, true)
	if err := ServiceStop(p); err != nil {
		t.Fatal(err)
	}
	calls, _ := os.ReadFile(log)
	if !strings.Contains(string(calls), "--user stop podaro.service") {
		t.Errorf("stop did not run systemctl --user stop podaro.service:\n%s", calls)
	}
	if !strings.Contains(buf.String(), "✓ service") || !strings.Contains(buf.String(), "stopped") || !strings.Contains(buf.String(), "→ next: podaro system start") {
		t.Errorf("the stop block:\n%s", buf.String())
	}

	// start and restart: the unit is up, and the engine answers — the
	// restart names what the engine reattached to.
	fakeServiceEngine(t, "intro")
	buf.Reset()
	if err := ServiceStart(p); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "podaro.service started") || !strings.Contains(buf.String(), "✓ engine") {
		t.Errorf("the start block:\n%s", buf.String())
	}
	buf.Reset()
	if err := ServiceRestart(p); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "podaro.service restarted") || !strings.Contains(buf.String(), "1 instance reattached: intro") {
		t.Errorf("the restart block:\n%s", buf.String())
	}
	calls, _ = os.ReadFile(log)
	for _, want := range []string{"--user start podaro.service", "--user restart podaro.service"} {
		if !strings.Contains(string(calls), want) {
			t.Errorf("systemctl was not run with %q:\n%s", want, calls)
		}
	}

	// A unit systemd does not know: the next action is the install.
	fakeSystemctl(t, "echo 'Failed to start podaro.service: Unit podaro.service not found.' >&2; exit 5")
	err := ServiceStart(p)
	var pe *pdr.Error
	if !errors.As(err, &pe) || pe.Code != pdr.CodeServiceControl || !strings.Contains(pe.Next, "podaro system install") {
		t.Errorf("an unknown unit gave %v", err)
	}

	// A bus it cannot reach: the lingering remedy, and podaroctl.
	fakeSystemctl(t, "echo 'Failed to connect to bus: No medium found' >&2; exit 1")
	err = ServiceRestart(p)
	if !errors.As(err, &pe) || !strings.Contains(pe.Next, "enable-linger") || !strings.Contains(pe.Next, "podaroctl system restart") {
		t.Errorf("an unreachable bus gave %v", err)
	}

	// Started, but no engine answers within the wait: that is the failure,
	// with the wait's own words as the cause.
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir()) // no socket here
	fakeSystemctl(t, "exit 0")
	err = ServiceStart(p)
	if !errors.As(err, &pe) || !strings.Contains(pe.Message, "did not answer") || !strings.Contains(pe.Cause, "journalctl") {
		t.Errorf("a start the engine did not answer gave %v", err)
	}
}
