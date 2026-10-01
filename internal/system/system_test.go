// SPDX-License-Identifier: AGPL-3.0-only

package system

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/api"
	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/fsx"
	"github.com/jeremiahjrross/podaro/internal/gateway"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
	"github.com/jeremiahjrross/podaro/internal/tlsca"
)

// docBlock pulls a fenced block from INSTALL.md starting at the given
// command line — the docs are the golden files.
func docBlock(t *testing.T, command string) string {
	t.Helper()
	raw, err := os.ReadFile("../../public-docs/INSTALL.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	marker := "```\n" + command + "\n"
	start := strings.Index(doc, marker)
	if start < 0 {
		t.Fatalf("INSTALL.md has no fenced block starting %q", command)
	}
	rest := doc[start+len(marker):]
	return rest[:strings.Index(rest, "```")]
}

// TestInstallBlockMatchesManual locks the step-2 board layout to INSTALL
// §2, using the manual's example host facts as the fixture ("modulo host
// facts" — TestEmbeddedCatalogIsDocumentedSubset couples the real
// extraction to the documented catalog line).
func TestInstallBlockMatchesManual(t *testing.T) {
	results := []StepResult{
		{Label: "directories", Detail: "~/.config/podaro · ~/.local/state/podaro (0700)"},
		{Label: "console assets", Detail: "extracted from binary (no downloads)"},
		{Label: "starter catalog", Detail: "grafana-prometheus-intro"},
		{Label: "legal notices", Detail: "~/.local/state/podaro/legal/ · licence and notices, from the binary"},
		{Label: "user service", Detail: "podaro.service enabled and running"},
		{Label: "api socket", Detail: "/run/user/1000/podaro/api.sock (0600)"},
	}
	var buf bytes.Buffer
	RenderInstallBlock(render.New(&buf, false, true), results, true)
	want := docBlock(t, "$ podaro system install")
	if got := buf.String(); got != want {
		t.Fatalf("install output diverges from INSTALL §2 step 2\n--- want ---\n%s--- got ---\n%s", want, got)
	}
}

// TestUninstallRefusalMatchesManual locks the §7 refusal lines.
func TestUninstallRefusalMatchesManual(t *testing.T) {
	var buf bytes.Buffer
	RenderUninstallRefusal(render.New(&buf, false, true), []string{"pii-lab"})
	want := "✗ 1 instance still exists: pii-lab\n" +
		"  → podaro destroy pii-lab        (uninstall will not destroy labs for you)\n"
	if got := buf.String(); got != want {
		t.Fatalf("refusal block wrong\n--- want ---\n%s--- got ---\n%s", want, got)
	}
	// And the same lines must be what INSTALL §7 shows.
	if doc := docBlock(t, "$ podaro system uninstall"); !strings.HasPrefix(doc, want) {
		t.Fatalf("INSTALL §7 refusal differs:\n%s", doc)
	}
}

func TestUninstallRefusesWhileInstancesExist(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	if err := os.MkdirAll(state+"/podaro/instances/pii-lab", 0o755); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	code, err := Uninstall(render.New(&buf, false, true), func() bool {
		t.Fatal("confirm must not be reached while instances exist")
		return false
	})
	if err != nil || code != 2 {
		t.Fatalf("code, err = %d, %v — want 2, nil", code, err)
	}
	if !strings.Contains(buf.String(), "1 instance still exists: pii-lab") {
		t.Fatalf("refusal not rendered: %q", buf.String())
	}
}

// The staging area under the state directory — a delivery snapshot while
// its create is admitted (INSTALL §3) — is never an instance: uninstall
// counts instances/ and nothing else.
func TestStagingIsNotAnInstance(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	if err := os.MkdirAll(state+"/podaro/staging/snapshot-x/template", 0o755); err != nil {
		t.Fatal(err)
	}
	names, err := Instances()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Fatalf("a staged snapshot counted as an instance: %v", names)
	}
}

// Setup validates its inputs before it touches config.yaml: a bad
// --domain or --port fails the run and leaves the working configuration
// exactly as it was.
func TestSetupPreflightsBeforeTouchingConfig(t *testing.T) {
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
	taken, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	occupied := taken.Addr().(*net.TCPAddr).Port
	for _, o := range []SetupOptions{{Domain: "Bad_Domain"}, {Domain: "lab.example.com", Port: 70000}, {Domain: "lab.example.com", Port: occupied}} {
		var buf bytes.Buffer
		err := Setup(render.New(&buf, false, true), o)
		if err == nil || code(err) != pdr.CodeSetupFailed {
			t.Fatalf("setup with %+v must fail with E023: %v", o, err)
		}
		raw, _ := os.ReadFile(path)
		if string(raw) != working {
			t.Fatalf("a refused setup replaced the working configuration:\n%s", raw)
		}
	}
	// The managed CA and leaf are prepared before config.yaml is
	// replaced: a CA that cannot be loaded fails setup at that step with
	// the working file untouched.
	paths := tlsca.NewPaths(config.StateDir())
	if err := os.MkdirAll(paths.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{paths.CACert(), paths.CAKey()} {
		if err := os.WriteFile(f, []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	err = Setup(render.New(&buf, false, true), SetupOptions{Domain: "new.example.com"})
	if err == nil || code(err) != pdr.CodeSetupFailed || !strings.Contains(buf.String(), "certificate authority") {
		t.Fatalf("a damaged CA must fail setup at the CA step: %v\n%s", err, buf.String())
	}
	if raw, _ := os.ReadFile(path); string(raw) != working {
		t.Fatalf("a setup that could not prepare its certificate replaced the working configuration:\n%s", raw)
	}
}

// TestAPortGivenIsNeverReadAsNoPort holds the flag's contract: only its
// absence (zero) keeps the configured port, so a nonsensical
// `podaro setup --port=-1` meets the documented 1–65535 in the preflight
// and stops there — never silently retaining the configured port and
// reporting success on a port nobody asked for.
func TestAPortGivenIsNeverReadAsNoPort(t *testing.T) {
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
	var buf bytes.Buffer
	err := Setup(render.New(&buf, false, true), SetupOptions{Domain: "lab.example.com", Port: -1})
	if err == nil || code(err) != pdr.CodeSetupFailed {
		t.Fatalf("--port=-1 must be refused: %v\n%s", err, buf.String())
	}
	// The refusal is the preflight's: nothing on the certificate side ran,
	// so the block names no certificate step at all.
	if strings.Contains(buf.String(), "certificate") {
		t.Fatalf("a port outside the range must stop setup before any certificate work:\n%s", buf.String())
	}
	if raw, _ := os.ReadFile(path); string(raw) != working {
		t.Fatalf("a refused setup replaced the working configuration:\n%s", raw)
	}
}

// A candidate that cannot be read back is not left in place: the write
// landed but the read after it failed — another process wrote the file
// between them, a transient fault — so the previous configuration goes
// back, or `config.yaml` would name a domain the live certificates do
// not serve and the next start would refuse the gateway, after a setup
// that reported failure.
func TestAConfigurationThatCannotBeReadBackIsPutBack(t *testing.T) {
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
	loadConfig = func(string) (*config.Config, error) { return nil, errors.New("read back: input/output error") }
	t.Cleanup(func() { loadConfig = config.Load })
	var buf bytes.Buffer
	err := Setup(render.New(&buf, false, true), SetupOptions{Domain: "new.example.com", Now: func() time.Time { return time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC) }})
	if err == nil || code(err) != pdr.CodeSetupFailed {
		t.Fatalf("a candidate that cannot be read back must fail setup: %v\n%s", err, buf.String())
	}
	if raw, _ := os.ReadFile(path); string(raw) != working {
		t.Fatalf("the working configuration must be back, byte for byte:\n%s", raw)
	}
}

// A write that fails after the rename that puts the candidate in place —
// the directory sync that makes it durable is the last step — is rolled
// back like any other failure past the write; and when the snapshot
// itself cannot go back, the operator is told so rather than reading a
// failed step over a file that has already changed.
func TestAWriteThatFailsAfterTheRenameIsPutBack(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	path := config.Path()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	working := "domain: lab.example.com\ngateway:\n  port: 8443\n"
	write := func() {
		t.Helper()
		if err := os.WriteFile(path, []byte(working), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Only the configuration directory's sync fails — the rename has
	// happened by then, so config.yaml already holds the candidate.
	real := fsx.Sync
	var fails int
	limit := 1
	fsx.Sync = func(f *os.File) error {
		if f.Name() == dir {
			if fails++; fails <= limit {
				return errors.New("sync: input/output error")
			}
		}
		return real(f)
	}
	t.Cleanup(func() { fsx.Sync = real })
	now := func() time.Time { return time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC) }

	write()
	err := Setup(render.New(&bytes.Buffer{}, false, true), SetupOptions{Domain: "new.example.com", Now: now})
	if err == nil || code(err) != pdr.CodeSetupFailed {
		t.Fatalf("a sync that fails after the rename must fail setup: %v", err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != working {
		t.Fatalf("the working configuration must be back, byte for byte:\n%s", raw)
	}
	// The same failure, now on every attempt: the snapshot cannot go back
	// either, and the refusal says so.
	fails, limit = 0, 1000
	write()
	err = Setup(render.New(&bytes.Buffer{}, false, true), SetupOptions{Domain: "new.example.com", Now: now})
	var pe *pdr.Error
	if !errors.As(err, &pe) || pe.Code != pdr.CodeSetupFailed || !strings.Contains(pe.Cause, "could not be put back") {
		t.Fatalf("a snapshot that cannot go back must be reported: %v", err)
	}
}

// A reload that answers must have applied this run's configuration: a
// door that is merely open proves nothing, since another writer may have
// replaced config.yaml between this run's write and the engine's read of
// it — setup would otherwise commit its certificates and report a port
// nothing listens on.
func TestASuccessfulReloadMustServeThisRunsConfiguration(t *testing.T) {
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
	now := time.Now()
	// The engine opens the door another writer's configuration named: the
	// domain this run asked for, on a port it did not.
	d := newEngineDouble(t, true)
	d.applied = map[string]any{"listening": true, "address": ":9443", "domain": "new.example.com", "certificate": "local-ca"}
	var buf bytes.Buffer
	err := Setup(render.New(&buf, false, true), SetupOptions{Domain: "new.example.com", Now: func() time.Time { return now }, Socket: d.sock})
	if err == nil || code(err) != pdr.CodeSetupFailed {
		t.Fatalf("a reload that opened another configuration's door must fail setup: %v\n%s", err, buf.String())
	}
	if raw, _ := os.ReadFile(path); string(raw) != working {
		t.Fatalf("the working configuration must be back, byte for byte:\n%s", raw)
	}
}

// A first setup — no config.yaml before it — restores absence durably:
// the candidate is removed and the directory flushed, so a power loss
// cannot bring back a name the rollback reported gone; and a candidate
// that never landed is already restored, not a failed rollback (S5
// Review round 31).
func TestRestoringAnAbsentConfigurationIsDurable(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	path := config.Path()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC) }
	real := fsx.Sync
	var dirSyncs int
	var failFile, failDir bool
	fsx.Sync = func(f *os.File) error {
		if f.Name() == dir {
			dirSyncs++
			if failDir && dirSyncs == 1 {
				return errors.New("sync: input/output error")
			}
		}
		if failFile && f.Name() == path+".tmp" {
			return errors.New("sync: input/output error")
		}
		return real(f)
	}
	t.Cleanup(func() { fsx.Sync = real })

	// The candidate lands and its directory sync fails: the removal that
	// restores absence is itself flushed.
	failDir = true
	err := Setup(render.New(&bytes.Buffer{}, false, true), SetupOptions{Domain: "new.example.com", Now: now})
	if err == nil || code(err) != pdr.CodeSetupFailed {
		t.Fatalf("a sync that fails after the rename must fail setup: %v", err)
	}
	if _, serr := os.Stat(path); !os.IsNotExist(serr) {
		t.Fatalf("the candidate must be gone: %v", serr)
	}
	if dirSyncs < 2 {
		t.Fatalf("the removal that restores absence must be flushed: %d directory syncs", dirSyncs)
	}
	// The candidate never lands — the write fails before its rename — so
	// there is nothing to remove, and that is a restore, not a failure.
	failDir, failFile, dirSyncs = false, true, 0
	err = Setup(render.New(&bytes.Buffer{}, false, true), SetupOptions{Domain: "new.example.com", Now: now})
	var pe *pdr.Error
	if !errors.As(err, &pe) || pe.Code != pdr.CodeSetupFailed {
		t.Fatalf("a write that fails before the rename must fail setup: %v", err)
	}
	if strings.Contains(pe.Cause, "could not be put back") {
		t.Fatalf("a candidate that never landed is already restored: %s", pe.Cause)
	}
}

// A certificate rollback that fails is named in the refusal: the same
// fault can stop the way back, leaving the candidate set live under a
// restored configuration, and the operator must hear it.
func TestACertificateRollbackThatFailsIsReported(t *testing.T) {
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
	now := time.Now()
	paths := tlsca.NewPaths(config.StateDir())
	ca, _, err := tlsca.EnsureCA(paths, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.IssueWildcard(paths, "lab.example.com", 30*24*time.Hour, now); err != nil {
		t.Fatal(err)
	}
	// The directory holding the certificate sets cannot be flushed: the
	// swap's durability fails, and so does the way back.
	sets := filepath.Dir(paths.Dir)
	real := fsx.Sync
	fsx.Sync = func(f *os.File) error {
		if f.Name() == sets {
			return errors.New("sync: input/output error")
		}
		return real(f)
	}
	t.Cleanup(func() { fsx.Sync = real })
	var buf bytes.Buffer
	err = Setup(render.New(&buf, false, true), SetupOptions{Domain: "new.example.com", Now: func() time.Time { return now }})
	var pe *pdr.Error
	if !errors.As(err, &pe) || pe.Code != pdr.CodeSetupFailed || !strings.Contains(pe.Cause, "certificate set that served could not be put back") {
		t.Fatalf("a certificate rollback that fails must be reported: %v\n%s", err, buf.String())
	}
	if raw, _ := os.ReadFile(path); string(raw) != working {
		t.Fatalf("the working configuration must be back, byte for byte:\n%s", raw)
	}
}

// TestEmbeddedCatalogIsDocumentedSubset couples real extraction to the
// documented starter catalog: every embedded template must be one of the
// documented names, in the manual's order, the open-source lab first — so
// the extracted line is exactly the INSTALL step-2 catalog line.
func TestEmbeddedCatalogIsDocumentedSubset(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	detail, err := extractCatalog()
	if err != nil {
		t.Fatal(err)
	}
	names := strings.Split(detail, " · ")
	documented := []string{"grafana-prometheus-intro"}
	var want []string
	for _, d := range documented {
		for _, n := range names {
			if n == d {
				want = append(want, d)
			}
		}
	}
	for _, n := range names {
		ok := false
		for _, d := range documented {
			if n == d {
				ok = true
			}
		}
		if !ok {
			t.Fatalf("embedded template %q is not in the documented starter catalog", n)
		}
	}
	if len(names) == 0 || names[0] != "grafana-prometheus-intro" {
		t.Fatalf("the open-source lab must be embedded and listed first: %q", detail)
	}
	if strings.Join(want, " · ") != detail {
		t.Fatalf("catalog order diverges from INSTALL §2: %q", detail)
	}
}

func TestIsEngineArgv(t *testing.T) {
	for _, tc := range []struct {
		argv []string
		want bool
	}{
		{[]string{"/home/x/.local/bin/podaro", "engine", "serve"}, true},
		{[]string{"podaro", "engine", "serve"}, true},
		{[]string{"/usr/bin/podaro", "system", "uninstall"}, false},
		{[]string{"/usr/bin/other", "engine", "serve"}, false},
		{[]string{"podaro", "engine"}, false},
		{nil, false},
	} {
		if got := isEngineArgv(tc.argv); got != tc.want {
			t.Errorf("isEngineArgv(%v) = %v, want %v", tc.argv, got, tc.want)
		}
	}
}

// The affirmative-liveness decision behind the systemd-unreachable path:
// only provable absence may permit removal. Facts are injected so the
// tests are deterministic on hosts that do run their own user manager.
func TestProvablyStopped(t *testing.T) {
	none := processFacts{}
	sockIn := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		if err := os.MkdirAll(dir+"/podaro", 0o700); err != nil {
			t.Fatal(err)
		}
		return dir + "/podaro/api.sock"
	}

	t.Run("no facts, no socket path — affirmative absence", func(t *testing.T) {
		if !provablyStopped(none, nil, sockIn(t)) {
			t.Fatal("should be provably stopped")
		}
	})

	t.Run("engine process counts as running", func(t *testing.T) {
		if provablyStopped(processFacts{engine: true}, nil, sockIn(t)) {
			t.Fatal("an engine process must abort")
		}
	})

	t.Run("a live user manager makes everything unprovable", func(t *testing.T) {
		// Restart=on-failure: a manager we cannot talk to may be about
		// to revive the engine — even a missing socket proves nothing.
		if provablyStopped(processFacts{manager: true}, nil, sockIn(t)) {
			t.Fatal("a live systemd --user manager must abort")
		}
	})

	t.Run("a failed scan makes everything unprovable", func(t *testing.T) {
		if provablyStopped(none, os.ErrPermission, sockIn(t)) {
			t.Fatal("an unusable scan must abort")
		}
	})

	t.Run("live listener counts as running", func(t *testing.T) {
		sock := sockIn(t)
		l, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		if provablyStopped(none, nil, sock) {
			t.Fatal("an answering listener must count as running")
		}
	})

	t.Run("stale socket file is affirmative absence", func(t *testing.T) {
		sock := sockIn(t)
		l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		l.SetUnlinkOnClose(false)
		l.Close() // file remains; connections now refused
		if !provablyStopped(none, nil, sock) {
			t.Fatal("a refusing leftover with no manager and no engine is affirmative absence")
		}
	})

	t.Run("unprovable stat error counts as running", func(t *testing.T) {
		file := t.TempDir() + "/not-a-dir"
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		// Traversing a non-directory: ENOTDIR, not ENOENT.
		if provablyStopped(none, nil, file+"/podaro/api.sock") {
			t.Fatal("a stat error other than ENOENT must not prove absence")
		}
	})
}

func TestIsManagerArgv(t *testing.T) {
	for _, tc := range []struct {
		argv []string
		want bool
	}{
		{[]string{"/usr/lib/systemd/systemd", "--user"}, true},
		{[]string{"/lib/systemd/systemd", "--user"}, true},
		{[]string{"/usr/lib/systemd/systemd", "--system"}, false},
		{[]string{"/usr/bin/other", "--user"}, false},
		{[]string{"systemd"}, false},
		{nil, false},
	} {
		if got := isManagerArgv(tc.argv); got != tc.want {
			t.Errorf("isManagerArgv(%v) = %v, want %v", tc.argv, got, tc.want)
		}
	}
}

func TestUnitFile(t *testing.T) {
	unit := UnitFile("/home/x/.local/bin/podaro")
	for _, want := range []string{
		"Description=Podaro Community engine",
		"ExecStart=/home/x/.local/bin/podaro engine serve",
		"WantedBy=default.target",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("unit lacks %q:\n%s", want, unit)
		}
	}
}

func TestBuildInfoDefaults(t *testing.T) {
	cfg := &config.Config{Gateway: config.Gateway{Port: config.DefaultGatewayPort}}
	raw, err := json.Marshal(BuildInfo(cfg, nil))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		`"api_version":"v1alpha1"`,
		`"gateway_port":7777`,
		`"logs":"off"`, `"metrics":"off"`, `"traces":"off"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("info JSON lacks %s: %s", want, s)
		}
	}
}

// Invariant 8 at the engine door: a rootful Podman is PDR-E209, an
// unreachable one PDR-E204, the fake runtime is never asked.
func TestRequireRootless(t *testing.T) {
	ctx := context.Background()
	code := func(err error) string {
		if pe, ok := err.(*pdr.Error); ok {
			return pe.Code
		}
		return fmt.Sprint(err)
	}
	rootful := func(context.Context) (runtime.Info, error) {
		return runtime.Info{Name: "podman", Version: "5.4.0"}, nil
	}
	rootless := func(context.Context) (runtime.Info, error) {
		return runtime.Info{Name: "podman", Version: "5.4.0", Rootless: true}, nil
	}
	down := func(context.Context) (runtime.Info, error) {
		return runtime.Info{}, errors.New("exec: podman: not found")
	}
	if err := requireRootless(ctx, "podman", rootful); code(err) != pdr.CodeRuntimeRootful {
		t.Errorf("rootful: want PDR-E209, got %v", err)
	}
	if err := requireRootless(ctx, "podman", down); code(err) != pdr.CodeRuntimeFailed {
		t.Errorf("down: want PDR-E204, got %v", err)
	}
	if err := requireRootless(ctx, "podman", rootless); err != nil {
		t.Errorf("rootless: %v", err)
	}
	if err := requireRootless(ctx, "fake", rootful); err != nil {
		t.Errorf("fake is exempt: %v", err)
	}
}

// One engine per state directory: the second serve refuses with
// PDR-E210 while the first holds the lock, and takes over once it is
// released.
func TestEngineLockRefusesASecondEngine(t *testing.T) {
	dir := t.TempDir()
	first, err := lockEngine(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockEngine(dir); err == nil || code(err) != pdr.CodeEngineRunning {
		t.Fatalf("second engine must be refused with E210: %v", err)
	}
	first.Close()
	second, err := lockEngine(dir)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	second.Close()
}

// A socket that still answers belongs to a live engine and is never
// unlinked; one nothing answers on is the leftover of an unclean stop.
func TestClaimSocketKeepsALiveOne(t *testing.T) {
	sock := filepath.Join(shortTempDir(t), "api.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	if err := claimSocket(sock); err == nil || code(err) != pdr.CodeEngineRunning {
		t.Fatalf("a live socket must not be claimed: %v", err)
	}
	if _, err := os.Lstat(sock); err != nil {
		t.Fatal("the live socket was unlinked")
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	if err := claimSocket(sock); err != nil {
		t.Fatalf("a stale socket is claimed: %v", err)
	}
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Fatal("the stale socket was not removed")
	}
	if err := claimSocket(sock); err != nil {
		t.Fatalf("no socket at all is fine: %v", err)
	}
}

// shortTempDir keeps unix socket paths under the kernel's limit.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "pdr-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func code(err error) string {
	var pe *pdr.Error
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// TestSetupBlockMatchesManual locks the step-4 block to INSTALL §2 with
// the manual's example facts (domain, address, home-relative paths).
func TestSetupBlockMatchesManual(t *testing.T) {
	results := []StepResult{
		{Label: "config", Detail: "~/.config/podaro/config.yaml"},
		{Label: "certificate authority", Detail: "Podaro Local CA · valid 10 years"},
		{Label: "wildcard certificate", Detail: "*.lab.example.com · valid 1 year · auto-renews"},
		{Label: "gateway", Detail: "listening on :7777 (TLS)"},
	}
	var buf bytes.Buffer
	RenderSetupBlock(render.New(&buf, false, true), results, &SetupFacts{Domain: "lab.example.com", IP: "203.0.113.10", CAPath: "~/.local/state/podaro/ca/ca.crt", Port: 8443})
	want := docBlock(t, "$ podaro setup --domain lab.example.com")
	if got := buf.String(); got != want {
		t.Fatalf("setup output diverges from INSTALL §2 step 4\n--- want ---\n%s--- got ---\n%s", want, got)
	}
}

// TestAuthSetupBlockMatchesManual locks step 5's output (after the
// prompts, which are interactive) to INSTALL §2.
func TestAuthSetupBlockMatchesManual(t *testing.T) {
	var buf bytes.Buffer
	RenderAuthSetupBlock(render.New(&buf, false, true), false, ConsoleURL("lab.example.com", 7777))
	block := docBlock(t, "$ podaro auth setup")
	// The block starts with the three prompt lines; the output follows.
	i := strings.Index(block, "✓ operator account created")
	if i < 0 {
		t.Fatal("INSTALL step 5 block lacks the created row")
	}
	if got, want := buf.String(), block[i:]; got != want {
		t.Fatalf("auth setup output diverges from INSTALL §2 step 5\n--- want ---\n%s--- got ---\n%s", want, got)
	}
	if ConsoleURL("lab.example.com", 443) != "https://lab.example.com" {
		t.Fatal("default port must be omitted")
	}
}

// The managed certificates are published together with config.yaml (S5
// Review round 7): they are staged beside the live ones and moved into
// place only after the file is written, so a write that fails leaves the
// live leaf serving the configured domain and the CA untouched — a
// rotation included — and nothing staged behind; once the write works,
// both change together.
func TestSetupPublishesCertificatesWithTheConfig(t *testing.T) {
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
	now := time.Now()
	paths := tlsca.NewPaths(config.StateDir())
	live := func(caNow time.Time) []byte {
		t.Helper()
		os.Remove(paths.CACert())
		os.Remove(paths.CAKey())
		ca, _, err := tlsca.EnsureCA(paths, caNow)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ca.IssueWildcard(paths, "lab.example.com", 30*24*time.Hour, now); err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(paths.CACert())
		return raw
	}
	serves := func(domain string) error {
		t.Helper()
		_, leaf, err := tlsca.LoadLeaf(paths.LeafCert(), paths.LeafKey())
		if err != nil {
			return err
		}
		return tlsca.Serves(leaf, domain, now)
	}
	// config.yaml cannot be written: its temporary file is a directory.
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	for _, caNow := range []time.Time{now, now.AddDate(-9, -8, 0)} { // a fresh CA; one due for rotation
		before := live(caNow)
		var buf bytes.Buffer
		err := Setup(render.New(&buf, false, true), SetupOptions{Domain: "new.example.com", Now: func() time.Time { return now }})
		if err == nil || code(err) != pdr.CodeSetupFailed {
			t.Fatalf("a config that cannot be written must fail setup: %v", err)
		}
		if raw, _ := os.ReadFile(path); string(raw) != working {
			t.Fatalf("the working configuration was replaced:\n%s", raw)
		}
		if err := serves("lab.example.com"); err != nil {
			t.Fatalf("the live leaf must still serve the configured domain: %v", err)
		}
		if after, _ := os.ReadFile(paths.CACert()); !bytes.Equal(after, before) {
			t.Fatal("the live CA changed although the configuration did not")
		}
		for _, left := range []string{paths.Dir + ".staging", paths.Dir + ".previous"} {
			if _, err := os.Stat(left); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s left behind: %v", left, err)
			}
		}
	}
	// Once the file can be written and the engine opens the door, the
	// certificates follow it into place and the previous set is dropped.
	if err := os.Remove(path + ".tmp"); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err := Setup(render.New(&buf, false, true), SetupOptions{Domain: "new.example.com", Now: func() time.Time { return now }, Socket: fakeEngine(t, true)})
	if err != nil || !strings.Contains(buf.String(), "✓ gateway") {
		t.Fatalf("setup with a listening engine: %v\n%s", err, buf.String())
	}
	if raw, _ := os.ReadFile(path); !strings.Contains(string(raw), "new.example.com") {
		t.Fatalf("the configuration must name the new domain:\n%s", raw)
	}
	if err := serves("new.example.com"); err != nil {
		t.Fatalf("the published leaf must serve the new domain: %v", err)
	}
	for _, left := range []string{paths.Dir + ".staging", paths.Dir + ".previous"} {
		if _, err := os.Stat(left); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s left behind: %v", left, err)
		}
	}
}

// fakeEngine serves the socket door's reload endpoint: listening, or a
// gateway that did not open.
func fakeEngine(t *testing.T, listening bool) string {
	t.Helper()
	return newEngineDouble(t, listening).sock
}

// engineDouble is the socket door as setup sees it: a reload that opens
// the candidate's door (or reports it closed), whose answer can be lost —
// after the engine applied the candidate, or before — and a /system that
// tells what the engine serves now.
type engineDouble struct {
	sock        string
	mu          sync.Mutex
	listening   bool
	serving     map[string]any
	dropNext    string         // "after-apply" | "before-apply" | ""
	expires     string         // the expiry of the leaf the double reports serving (round 12)
	fingerprint func() string  // the identity of the leaf it reports serving, asked when /system is (round 13)
	applied     map[string]any // the door a reload opens (the candidate's)
	reloads     int
}

var (
	oldDoor = map[string]any{"listening": true, "address": ":8443", "domain": "lab.example.com", "certificate": "local-ca"}
	newDoor = map[string]any{"listening": true, "address": ":8443", "domain": "new.example.com", "certificate": "local-ca"}
)

func newEngineDouble(t *testing.T, listening bool) *engineDouble {
	t.Helper()
	d := &engineDouble{sock: filepath.Join(t.TempDir(), "api.sock"), listening: listening, serving: oldDoor, applied: newDoor}
	l, err := net.Listen("unix", d.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+api.Prefix+"/system/reload", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		d.reloads++
		drop := d.dropNext
		d.dropNext = ""
		if drop == "after-apply" || drop == "hang-after-apply" || (drop == "" && d.listening) {
			d.serving = d.applied
			if d.reloads > 1 && drop == "" {
				d.serving = oldDoor // a re-read of the restored configuration
			}
		}
		serving := map[string]any{}
		for k, v := range d.serving {
			serving[k] = v
		}
		d.mu.Unlock()
		if drop == "hang-after-apply" {
			<-r.Context().Done() // the answer never comes: the client gives up on it
			return
		}
		if drop != "" {
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					conn.Close() // the answer is lost
					return
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		// The answer names the door this reload opened — the engine
		// reports the configuration it read, and setup checks a
		// successful reload against its own candidate (round 31).
		gw := serving
		gw["listening"] = listening
		_ = json.NewEncoder(w).Encode(map[string]any{"gateway": gw})
	})
	mux.HandleFunc("GET "+api.Prefix+"/system", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		serving := map[string]any{}
		for k, v := range d.serving {
			serving[k] = v
		}
		if d.expires != "" {
			serving["expires"] = d.expires
		}
		if d.fingerprint != nil {
			serving["fingerprint"] = d.fingerprint()
		}
		d.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"host": map[string]any{"gateway": serving}})
	})
	go func() { _ = http.Serve(l, mux) }()
	return d
}

// Nothing changes unless the door opens: a reload
// that fails — the engine not running, or a gateway that did not open —
// puts config.yaml and the previous certificate set back, so the next
// engine start finds exactly what served before; once the door opens,
// both change together.
func TestSetupRestoresEverythingWhenTheReloadFails(t *testing.T) {
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
	now := time.Now()
	paths := tlsca.NewPaths(config.StateDir())
	ca, _, err := tlsca.EnsureCA(paths, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.IssueWildcard(paths, "lab.example.com", 30*24*time.Hour, now); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(paths.CACert())
	serving := func() string {
		t.Helper()
		_, leaf, err := tlsca.LoadLeaf(paths.LeafCert(), paths.LeafKey())
		if err != nil {
			t.Fatalf("the live leaf must load: %v", err)
		}
		return leaf.DNSNames[1]
	}
	for _, sock := range []string{filepath.Join(t.TempDir(), "absent.sock"), fakeEngine(t, false)} {
		var buf bytes.Buffer
		err := Setup(render.New(&buf, false, true), SetupOptions{Domain: "new.example.com", Now: func() time.Time { return now }, Socket: sock})
		if err == nil || code(err) != pdr.CodeSetupFailed || !strings.Contains(err.(*pdr.Error).Cause, "restored") {
			t.Fatalf("a reload that fails must fail setup and say what was restored: %v", err)
		}
		if raw, _ := os.ReadFile(path); string(raw) != working {
			t.Fatalf("config.yaml must be restored:\n%s", raw)
		}
		if got := serving(); got != "lab.example.com" {
			t.Fatalf("the live leaf must be the one that served before, got %s", got)
		}
		if after, _ := os.ReadFile(paths.CACert()); !bytes.Equal(after, before) {
			t.Fatal("the CA must be the one that served before")
		}
		for _, left := range []string{paths.Dir + ".staging", paths.Dir + ".previous", paths.Dir + ".rollback"} {
			if _, err := os.Stat(left); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s left behind: %v", left, err)
			}
		}
	}
	var buf bytes.Buffer
	if err := Setup(render.New(&buf, false, true), SetupOptions{Domain: "new.example.com", Now: func() time.Time { return now }, Socket: fakeEngine(t, true)}); err != nil {
		t.Fatalf("setup with a listening engine: %v\n%s", err, buf.String())
	}
	if raw, _ := os.ReadFile(path); !strings.Contains(string(raw), "new.example.com") {
		t.Fatalf("the configuration must name the new domain:\n%s", raw)
	}
	if got := serving(); got != "new.example.com" {
		t.Fatalf("the published leaf must serve the new domain, got %s", got)
	}
	if _, err := os.Stat(paths.Dir + ".previous"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the previous set must be dropped once the door opened")
	}
}

// A reload whose answer never arrived is reconciled with what the engine
// serves before anything is rolled back: an engine
// that applied the candidate and lost the answer is a reload that
// happened — the new configuration stands; one that did not apply it is
// rolled back on disk and asked to re-read the restored configuration.
func TestSetupReconcilesAnAnswerThatNeverArrived(t *testing.T) {
	for _, drop := range []string{"after-apply", "before-apply"} {
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
		now := time.Now()
		paths := tlsca.NewPaths(config.StateDir())
		ca, _, err := tlsca.EnsureCA(paths, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ca.IssueWildcard(paths, "lab.example.com", 30*24*time.Hour, now); err != nil {
			t.Fatal(err)
		}
		d := newEngineDouble(t, true)
		d.dropNext = drop
		if drop == "after-apply" {
			d.fingerprint = liveLeaf(paths) // the leaf the engine would serve once applied
		}
		var buf bytes.Buffer
		err = Setup(render.New(&buf, false, true), SetupOptions{Domain: "new.example.com", Now: func() time.Time { return now }, Socket: d.sock})
		raw, _ := os.ReadFile(path)
		_, leaf, lerr := tlsca.LoadLeaf(paths.LeafCert(), paths.LeafKey())
		if lerr != nil {
			t.Fatal(lerr)
		}
		switch drop {
		case "after-apply":
			if err != nil || !strings.Contains(buf.String(), "✓ gateway") {
				t.Fatalf("an engine that applied the candidate is a reload that happened: %v\n%s", err, buf.String())
			}
			if !strings.Contains(string(raw), "new.example.com") || leaf.DNSNames[1] != "new.example.com" {
				t.Fatalf("the new configuration and leaf must stand: %s / %s", raw, leaf.DNSNames[1])
			}
			if d.reloads != 1 {
				t.Fatalf("one reload, no re-read: %d", d.reloads)
			}
		case "before-apply":
			if err == nil || code(err) != pdr.CodeSetupFailed || !strings.Contains(err.(*pdr.Error).Cause, "re-read the restored configuration") {
				t.Fatalf("an engine that did not apply the candidate: %v", err)
			}
			if string(raw) != working || leaf.DNSNames[1] != "lab.example.com" {
				t.Fatalf("config.yaml and the leaf must be restored: %s / %s", raw, leaf.DNSNames[1])
			}
			if d.reloads != 2 {
				t.Fatalf("the engine must be asked to re-read the restored configuration: %d reloads", d.reloads)
			}
		}
	}
}

// liveLeaf reports the identity of the leaf on disk at the moment it is
// asked — what an engine that applied the candidate serves, since the
// candidate is published before the reload is requested.
func liveLeaf(paths tlsca.Paths) func() string {
	return func() string {
		_, leaf, err := tlsca.LoadLeaf(paths.LeafCert(), paths.LeafKey())
		if err != nil {
			return ""
		}
		return tlsca.Fingerprint(leaf)
	}
}

// The door alone proves nothing when only the certificate changed (S5
// Review round 12), and neither does the leaf's expiry (round 13): leaves
// issued in the same second share one, and a replacement can carry the
// old one. A lost answer on a re-issue for the same domain and port is
// settled by the identity of the leaf the engine reports serving — the
// old leaf's fingerprint means the candidate was not applied, and disk
// is restored; the candidate's means it was.
func TestReconciliationChecksTheCertificateTheEngineServes(t *testing.T) {
	for _, applied := range []bool{false, true} {
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
		now := time.Now()
		paths := tlsca.NewPaths(config.StateDir())
		ca, _, err := tlsca.EnsureCA(paths, now)
		if err != nil {
			t.Fatal(err)
		}
		// Issued at the instant setup will issue the candidate, for the
		// same validity: the two leaves share an expiry, as two setup runs
		// in one second would.
		old, err := ca.IssueWildcard(paths, "lab.example.com", tlsca.LeafValidity, now)
		if err != nil {
			t.Fatal(err)
		}
		d := newEngineDouble(t, true)
		d.serving = oldDoor // the same domain and port: only the leaf changes
		d.dropNext = "before-apply"
		d.expires = old.NotAfter.UTC().Format(time.RFC3339)
		d.fingerprint = func() string { return tlsca.Fingerprint(old) }
		if applied {
			d.dropNext = "after-apply"
			d.applied = oldDoor // the same door: only the leaf is new
			d.fingerprint = liveLeaf(paths)
		}
		var buf bytes.Buffer
		err = Setup(render.New(&buf, false, true), SetupOptions{Domain: "lab.example.com", Now: func() time.Time { return now }, Socket: d.sock})
		_, leaf, lerr := tlsca.LoadLeaf(paths.LeafCert(), paths.LeafKey())
		if lerr != nil {
			t.Fatal(lerr)
		}
		if applied {
			if err != nil {
				t.Fatalf("an engine serving the candidate leaf is a reload that happened: %v\n%s", err, buf.String())
			}
			if leaf.SerialNumber.Cmp(old.SerialNumber) == 0 {
				t.Fatal("the re-issued leaf must stand")
			}
			if !leaf.NotAfter.Equal(old.NotAfter) {
				t.Fatalf("the test needs leaves sharing an expiry: %s vs %s", leaf.NotAfter, old.NotAfter)
			}
			continue
		}
		if err == nil || code(err) != pdr.CodeSetupFailed {
			t.Fatalf("an engine still serving the old leaf did not apply the candidate: %v", err)
		}
		if leaf.SerialNumber.Cmp(old.SerialNumber) != 0 {
			t.Fatal("the old leaf must be restored")
		}
		d.mu.Lock()
		reloads := d.reloads
		d.mu.Unlock()
		if reloads != 2 {
			t.Fatalf("the engine must be asked to re-read: %d reloads", reloads)
		}
	}
}

// The calls that settle a lost answer have time limits of their own (S5
// Review round 13): a reload the engine applied whose answer hangs until
// the reload's deadline is settled by what the engine serves, asked with
// a fresh limit — not rolled back on disk under a gateway serving the
// candidate because the deadline that had expired was reused.
func TestReconciliationOutlivesTheReloadsDeadline(t *testing.T) {
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
	now := time.Now()
	paths := tlsca.NewPaths(config.StateDir())
	ca, _, err := tlsca.EnsureCA(paths, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.IssueWildcard(paths, "lab.example.com", 30*24*time.Hour, now); err != nil {
		t.Fatal(err)
	}
	d := newEngineDouble(t, true)
	d.dropNext = "hang-after-apply"
	d.fingerprint = liveLeaf(paths)
	var buf bytes.Buffer
	err = Setup(render.New(&buf, false, true), SetupOptions{Domain: "new.example.com", Now: func() time.Time { return now }, Socket: d.sock, ReloadTimeout: 300 * time.Millisecond})
	if err != nil || !strings.Contains(buf.String(), "✓ gateway") {
		t.Fatalf("an engine that applied the candidate is a reload that happened, however late its answer: %v\n%s", err, buf.String())
	}
	raw, _ := os.ReadFile(path)
	_, leaf, lerr := tlsca.LoadLeaf(paths.LeafCert(), paths.LeafKey())
	if lerr != nil {
		t.Fatal(lerr)
	}
	if !strings.Contains(string(raw), "new.example.com") || leaf.DNSNames[1] != "new.example.com" {
		t.Fatalf("the new configuration and leaf must stand: %s / %s", raw, leaf.DNSNames[1])
	}
	d.mu.Lock()
	reloads := d.reloads
	d.mu.Unlock()
	if reloads != 1 {
		t.Fatalf("one reload, no re-read: %d", reloads)
	}
}

// Two setups never overlap: the staged set, the
// previous set and config.yaml's temporary file are shared paths, so a
// second setup started while one runs is refused — nothing on disk is
// touched — and proceeds once the first has released the lock.
func TestSetupRefusesToOverlap(t *testing.T) {
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
	now := time.Now()
	paths := tlsca.NewPaths(config.StateDir())
	ca, _, err := tlsca.EnsureCA(paths, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.IssueWildcard(paths, "lab.example.com", 30*24*time.Hour, now); err != nil {
		t.Fatal(err)
	}
	held, err := os.OpenFile(setupLockPath(config.StateDir()), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	sock := fakeEngine(t, true)
	var buf bytes.Buffer
	err = Setup(render.New(&buf, false, true), SetupOptions{Domain: "new.example.com", Now: func() time.Time { return now }, Socket: sock})
	if err == nil || code(err) != pdr.CodeSetupFailed || !strings.Contains(err.Error(), "another podaro setup") {
		t.Fatalf("a setup while another runs must be refused: %v", err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != working {
		t.Fatalf("config.yaml must be untouched:\n%s", raw)
	}
	if _, err := os.Stat(paths.Dir + ".staging"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nothing may be staged: %v", err)
	}
	if _, leaf, err := tlsca.LoadLeaf(paths.LeafCert(), paths.LeafKey()); err != nil || leaf.DNSNames[1] != "lab.example.com" {
		t.Fatalf("the live leaf must be untouched: %v", err)
	}
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	held.Close()
	buf.Reset()
	if err := Setup(render.New(&buf, false, true), SetupOptions{Domain: "new.example.com", Now: func() time.Time { return now }, Socket: sock}); err != nil {
		t.Fatalf("released, setup proceeds: %v\n%s", err, buf.String())
	}
	if raw, _ := os.ReadFile(path); !strings.Contains(string(raw), "new.example.com") {
		t.Fatalf("the new configuration must stand:\n%s", raw)
	}
}

// A setup's candidate is derived from the configuration the run before it
// committed: the lock precedes the read, so a run
// that waited on another never writes a candidate built from the file as
// it was before that run replaced it — a domain-only re-run keeps the
// port the previous run set.
func TestSetupDerivesTheCandidateFromTheCommittedConfiguration(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	path := config.Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("domain: lab.example.com\ngateway:\n  port: 8443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	paths := tlsca.NewPaths(config.StateDir())
	ca, _, err := tlsca.EnsureCA(paths, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.IssueWildcard(paths, "lab.example.com", 30*24*time.Hour, now); err != nil {
		t.Fatal(err)
	}
	// The run before this one committed a new port the moment before this
	// run took the lock.
	afterSetupLock = func() {
		afterSetupLock = nil
		if err := os.WriteFile(path, []byte("domain: lab.example.com\ngateway:\n  port: 9443\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	defer func() { afterSetupLock = nil }()
	var buf bytes.Buffer
	// The double answers as the engine would: the door it opens is the
	// one this run's configuration names — domain and port both, which
	// setup now checks a successful reload against (round 31).
	d := newEngineDouble(t, true)
	d.applied = map[string]any{"listening": true, "address": ":9443", "domain": "lab.example.com", "certificate": "local-ca"}
	if err := Setup(render.New(&buf, false, true), SetupOptions{Domain: "lab.example.com", Now: func() time.Time { return now }, Socket: d.sock}); err != nil {
		t.Fatalf("setup: %v\n%s", err, buf.String())
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "port: 9443") {
		t.Fatalf("the candidate must be derived from the committed configuration, not a stale read:\n%s", raw)
	}
}

// Reloads are applied one at a time, in the order they read the
// configuration: a reload that read the candidate
// and lost its answer applies it before the restorative reload does,
// never after — so the live gateway ends where the restored disk is.
func TestReloadsAreAppliedInTheOrderTheyReadTheConfiguration(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	if err := os.MkdirAll(filepath.Dir(config.Path()), 0o700); err != nil {
		t.Fatal(err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	write := func(domain string) {
		t.Helper()
		if err := os.WriteFile(config.Path(), []byte(fmt.Sprintf("domain: %s\ngateway:\n  port: %d\n", domain, port)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	stateDir := config.StateDir()
	if _, _, err := tlsca.EnsureCA(tlsca.NewPaths(stateDir), now); err != nil {
		t.Fatal(err)
	}
	gw := gateway.New(gateway.Options{API: api.New(api.Options{}), Engine: engine.New(engine.Options{Store: state.NewMemory()}), Assets: podaro.ConsoleAssets(), Now: func() time.Time { return now }})
	defer gw.Close()
	reload := newReloader(func() *gateway.Gateway { return gw }, stateDir, nil)
	write("old.example.com")
	if _, err := reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	write("new.example.com") // the candidate a setup wrote
	restorative := make(chan error, 1)
	var fired atomic.Bool
	afterReloadRead = func() {
		if !fired.CompareAndSwap(false, true) {
			return // the re-read's own pass through the seam
		}
		// The candidate is read but not yet applied when setup — its
		// answer lost — restores the disk and asks for a re-read. Without
		// the order, that re-read completes here and the candidate lands
		// after it; with it, the re-read waits for this reload.
		write("old.example.com")
		go func() {
			_, err := reload(context.Background())
			restorative <- err
		}()
		select {
		case err := <-restorative:
			restorative <- err
		case <-time.After(2 * time.Second):
		}
	}
	defer func() { afterReloadRead = nil }()
	if _, err := reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-restorative; err != nil {
		t.Fatal(err)
	}
	if st := gw.Status(); st.Domain != "old.example.com" {
		t.Fatalf("the live gateway must match the restored disk, serving %q", st.Domain)
	}
}

// Nothing is replaced without a snapshot to put back: a config.yaml the
// rollback's read cannot take — an I/O fault, a mode that changed since
// the load — stops setup before anything is written, rather than
// leaving the rollback to write nothing over a working configuration.
func TestSetupRefusesWhenTheConfigurationCannotBeReadBack(t *testing.T) {
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
	now := time.Now()
	paths := tlsca.NewPaths(config.StateDir())
	ca, _, err := tlsca.EnsureCA(paths, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.IssueWildcard(paths, "lab.example.com", 30*24*time.Hour, now); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(paths.CACert())
	saved := readFile
	readFile = func(name string) ([]byte, error) {
		if name == path {
			return nil, fmt.Errorf("input/output error")
		}
		return saved(name)
	}
	defer func() { readFile = saved }()
	var buf bytes.Buffer
	err = Setup(render.New(&buf, false, true), SetupOptions{Domain: "new.example.com", Now: func() time.Time { return now }, Socket: filepath.Join(t.TempDir(), "absent.sock")})
	if err == nil || code(err) != pdr.CodeSetupFailed || !strings.Contains(err.(*pdr.Error).Cause, "cannot be read") {
		t.Fatalf("a configuration that cannot be read back must stop setup: %v", err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != working {
		t.Fatalf("config.yaml must be untouched:\n%q", raw)
	}
	if after, _ := os.ReadFile(paths.CACert()); !bytes.Equal(after, before) {
		t.Fatal("the CA must be untouched")
	}
	if _, leaf, err := tlsca.LoadLeaf(paths.LeafCert(), paths.LeafKey()); err != nil || leaf.DNSNames[1] != "lab.example.com" {
		t.Fatalf("the live leaf must be the one that served: %v", err)
	}
	for _, left := range []string{paths.Dir + ".staging", paths.Dir + ".previous", paths.Dir + ".rollback"} {
		if _, err := os.Stat(left); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("nothing may be left at %s: %v", left, err)
		}
	}
}
