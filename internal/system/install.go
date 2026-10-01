// SPDX-License-Identifier: AGPL-3.0-only

// Package system implements `podaro system install|uninstall` (INSTALL §2
// step 2, §7) and the S1 socket-only engine stub. Install is
// self-extraction plus a systemd user service: never root, never sudo,
// nothing outside the operator's home (the trust posture, INSTALL §1).
package system

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/brand"
	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/legal"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
)

// installColumn is the step-2 block's detail column (INSTALL §2).
const installColumn = 19

// StepResult is one install or setup step's outcome, rendered as a board
// row; Skipped renders the `–` glyph (setup with a bring-your-own cert),
// Warn the `!` of a row that reports rather than fails (the retired
// catalog entry an earlier build left — PDR-W103).
type StepResult struct {
	Label   string
	Detail  string
	Err     error
	Skipped bool
	Warn    bool
}

// Install runs the step-2 sequence, rendering the board as the manual
// shows it. On failure it renders the failed row and returns PDR-E020.
func Install(p *render.Printer) error {
	steps := []struct {
		label string
		run   func() (string, error)
	}{
		{"directories", makeDirectories},
		{"console assets", extractConsole},
		{"starter catalog", extractCatalog},
		{"legal notices", writeLegal},
		{"user service", installService},
		{"api socket", awaitSocket},
	}
	var results []StepResult
	for _, s := range steps {
		detail, err := s.run()
		results = append(results, StepResult{Label: s.label, Detail: detail, Err: err})
		if err != nil {
			RenderInstallBlock(p, results, false)
			e := pdr.New(pdr.CodeInstallFailed, "system install failed at %q", s.label)
			e.Cause = err.Error()
			e.Next = "fix the cause above, then re-run podaro system install (idempotent)"
			return e
		}
		if s.label == "starter catalog" {
			if row, ok := retiredCatalogRow(); ok {
				results = append(results, row)
			}
		}
	}
	RenderInstallBlock(p, results, true)
	return nil
}

// RenderInstallBlock renders step results in the INSTALL §2 step-2 layout;
// complete=true appends the closing lines.
func RenderInstallBlock(p *render.Printer, results []StepResult, complete bool) {
	for _, r := range results {
		switch {
		case r.Err != nil:
			p.Check(render.Fail, r.Label, installColumn, r.Err.Error())
		case r.Warn:
			p.Check(render.Warn, r.Label, installColumn, r.Detail)
		default:
			p.Check(render.Pass, r.Label, installColumn, r.Detail)
		}
	}
	if complete {
		p.Blank()
		p.Plain("engine is running · listening on the local socket only")
		p.NextAction("podaro doctor")
	}
}

func makeDirectories() (string, error) {
	for _, dir := range []string{config.Dir(), config.StateDir()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		// MkdirAll leaves pre-existing directories' modes alone; the
		// documented posture is 0700 for both (INSTALL §3).
		if err := os.Chmod(dir, 0o700); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%s · %s (0700)", tildify(config.Dir()), tildify(config.StateDir())), nil
}

func extractConsole() (string, error) {
	if err := extractFS(podaro.ConsoleAssets(), filepath.Join(config.StateDir(), "console")); err != nil {
		return "", err
	}
	return "extracted from binary (no downloads)", nil
}

func extractCatalog() (string, error) {
	dst := filepath.Join(config.StateDir(), "catalog")
	if err := extractFS(podaro.StarterCatalog(), dst); err != nil {
		return "", err
	}
	names, err := catalogEntries(dst)
	if err != nil {
		return "", err
	}
	// What may be offered, and only that. Extraction adds and never
	// deletes, so a template an earlier build extracted and the owner has
	// since retired stays where it is — and is reported on its own row
	// (retiredCatalogRow), never offered on this one (the reconciliation
	// plan's R3).
	offered, _ := podaro.Retirement().Catalog(names)
	return strings.Join(offered, " · "), nil
}

// LegalDir is where `system install` writes the legal files the binary
// carries (INSTALL §3): the bare-binary path's copy of what a release
// tarball holds beside the binary (the reconciliation §7.1).
func LegalDir() string { return filepath.Join(config.StateDir(), "legal") }

// writeLegal writes the licence and the notices — LICENSE, NOTICE,
// TRADEMARKS.md, THIRD-PARTY-NOTICES.md, LICENSES/, SOURCE-AND-BUILD.md —
// from the binary to <state>/legal/, and names the directory: an install
// that never saw a tarball still leaves them on disk beside the state
// they govern. `podaro legal` prints the same from the binary.
func writeLegal() (string, error) {
	if err := legal.WriteDir(LegalDir()); err != nil {
		return "", err
	}
	return tildify(LegalDir()) + "/ · licence and notices, from the binary", nil
}

// catalogEntries lists the template directories of a catalog in the
// documented order (SortCatalog).
func catalogEntries(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	SortCatalog(names)
	return names, nil
}

// RetiredCatalog lists the entries of a state directory's catalog that
// the retirement manifest lists: what an earlier build extracted and
// this one never offers, deletes or reads. A catalog that cannot be read
// holds none this can name.
func RetiredCatalog(stateDir string) []string {
	names, err := catalogEntries(filepath.Join(stateDir, "catalog"))
	if err != nil {
		return nil
	}
	_, retired := podaro.Retirement().Catalog(names)
	return retired
}

// retiredCatalogRow is the install board's one PDR-W103 row, after the
// catalog's: the retired entry is present and unsupported, and it is not
// offered. There is no row when there is nothing to report, so the board
// of a host that never held one is the one INSTALL §2 shows.
func retiredCatalogRow() (StepResult, bool) {
	retired := RetiredCatalog(config.StateDir())
	if len(retired) == 0 {
		return StepResult{}, false
	}
	return StepResult{Label: "retired template", Detail: strings.Join(retired, " · ") + " present, unsupported by this release · not offered · " + pdr.CodeRetiredPresent, Warn: true}, true
}

// catalogOrder is the documented starter-catalog order (INSTALL §2 step 2):
// the retained open-source lab first. Names outside it — an operator's own
// templates — sort after, alphabetically.
var catalogOrder = map[string]int{
	"grafana-prometheus-intro": 0,
}

// SortCatalog orders template names as the install board and the CLI's
// empty state offer them (INSTALL §2 steps 2 and 6): the open-source lab
// first, then anything else alphabetically. Exported because two surfaces
// make the same offer and there is one order between them.
func SortCatalog(names []string) {
	sort.Slice(names, func(i, j int) bool {
		oi, iKnown := catalogOrder[names[i]]
		oj, jKnown := catalogOrder[names[j]]
		switch {
		case iKnown && jKnown:
			return oi < oj
		case iKnown != jKnown:
			return iKnown
		default:
			return names[i] < names[j]
		}
	})
}

// UnitPath is the systemd user unit location (INSTALL §3).
func UnitPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "systemd", "user", "podaro.service")
}

// UnitFile renders the user service unit for the given executable. Its
// description is the build's display title (internal/brand); the unit's
// name, podaro.service, is an identifier and stays.
func UnitFile(exe string) string {
	return fmt.Sprintf(`[Unit]
Description=%s engine

[Service]
ExecStart=%s engine serve
Restart=on-failure

[Install]
WantedBy=default.target
`, brand.Title, exe)
}

func installService() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return "", err
	}
	path := UnitPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(UnitFile(exe)), 0o644); err != nil {
		return "", err
	}
	if out, err := systemctl("daemon-reload").CombinedOutput(); err != nil {
		return "", fmt.Errorf("systemctl --user daemon-reload: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := systemctl("enable", "--now", "podaro.service").CombinedOutput(); err != nil {
		return "", fmt.Errorf("systemctl --user enable --now: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return "podaro.service enabled and running", nil
}

func awaitSocket() (string, error) { return awaitEngine(engineAnswerWait) }

// engineAnswerWait is how long a starting engine has to answer.
// `Serve` binds the socket and only then reconciles, which is the work
// that grows with the instances a host holds, so the door exists well
// before it serves; the old three seconds were enough for a path to
// appear and are not enough for an engine to be ready.
const engineAnswerWait = 30 * time.Second

// awaitEngine waits for an engine that answers rather than a path that
// exists. The socket is bound before the fallible part of startup —
// reconcile-on-start — so it exists during a window in which the process
// is on its way to dying, and a `kill -9` leaves it behind for good: a
// stat reported "restarted" for an engine that was neither.
// The mode reported is the socket's own, 0600, which is what
// `Serve` sets and what this door has always been.
func awaitEngine(within time.Duration) (string, error) {
	sock := filepath.Join(config.RuntimeDir(), "api.sock")
	client := socketClient(sock)
	deadline := time.Now().Add(within)
	var last error
	for {
		if _, err := os.Stat(sock); err != nil {
			last = err
		} else if last = engineAnswers(client); last == nil {
			return fmt.Sprintf("%s (0600)", sock), nil
		}
		if !time.Now().Before(deadline) {
			return "", fmt.Errorf("the engine did not answer on %s: %v — journalctl --user -u podaro", sock, last)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// extractFS copies an embedded FS tree to dst, overwriting files.
func extractFS(src fs.FS, dst string) error {
	return fs.WalkDir(src, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(dst, path)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := fs.ReadFile(src, path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}

// tildify shortens a path under $HOME to ~/… for display.
func tildify(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return path
	}
	if strings.HasPrefix(path, home) {
		return "~" + strings.TrimPrefix(path, home)
	}
	return path
}
