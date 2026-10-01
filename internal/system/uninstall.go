// SPDX-License-Identifier: AGPL-3.0-only

package system

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/legal"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
)

// uninstallColumn aligns the detail of a failing removal row against the
// longest label that carries one ("configuration removal failed").
const uninstallColumn = 30

// Instances lists instance names present in the state directory. A missing
// directory is no instances; any other read failure is returned rather than
// flattened into "none", because uninstall's refusal rests on this answer
// and an instance directory it could not read is not an empty one — the
// rule the liveness probes below already follow.
func Instances() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(config.StateDir(), "instances"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil // nothing has been created yet
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

// Uninstall implements INSTALL §7: refuse while instances exist, confirm,
// then remove the service, state, configuration, and binary. It renders
// its own output; the returned code is the process exit code, and a
// non-nil error means the run aborted with nothing destroyed.
func Uninstall(p *render.Printer, confirm func() bool) (int, error) {
	names, err := Instances()
	if err != nil {
		e := pdr.New(pdr.CodeUninstallUnreadable, "could not read the instance directory — uninstall aborted, nothing removed")
		e.Cause = err.Error()
		e.Next = "make " + tildify(filepath.Join(config.StateDir(), "instances")) + " readable · podaro status · then re-run podaro system uninstall"
		return 0, e
	}
	if len(names) > 0 {
		RenderUninstallRefusal(p, names)
		return 2, nil // precondition: destroying labs is never a side effect
	}

	p.Plain(fmt.Sprintf("this removes: the service, the binary, %s, %s", tildify(config.Dir()), tildify(config.StateDir())))
	p.Plain("it does not touch: podman itself, images already pulled, your shell files")
	if !confirm() {
		return 1, nil
	}

	if err := stopService(); err != nil {
		return 0, err // state, config, and binary stay untouched
	}
	return removeInstallation(p), nil
}

// removeInstallation removes the unit, the state, the configuration and the
// binary, in that order, and reports each step by what it actually did: a
// step that could not be completed fails the run and says why, rather than
// printing a row that claims otherwise. The sequence stops at the first
// failure, so what is still there stays there and a re-run finishes the job.
//
// It is a step of its own so the tests can exercise it on any host: whether
// stopService can succeed depends on the machine — a `systemd --user`
// manager makes the engine's state unprovable, and CI runners have one —
// which is the same reason provablyStopped takes injected facts.
func removeInstallation(p *render.Printer) int {
	// A unit file left behind is not cosmetic: it carries
	// Restart=on-failure, so leaving one while the state goes is the
	// revival the liveness probes exist to prevent.
	if err := os.Remove(UnitPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		p.Check(render.Fail, "unit removal failed", uninstallColumn, err.Error())
		return 1
	}
	_ = systemctl("daemon-reload").Run() // best effort: systemd may be gone
	p.Check(render.Pass, "service stopped and removed", 0, "")

	if err := os.RemoveAll(config.StateDir()); err != nil {
		p.Check(render.Fail, "state removal failed", uninstallColumn, err.Error())
		return 1
	}
	if err := os.RemoveAll(config.Dir()); err != nil {
		p.Check(render.Fail, "configuration removal failed", uninstallColumn, err.Error())
		return 1
	}
	p.Check(render.Pass, "state and configuration removed", 0, "")

	home, _ := os.UserHomeDir()
	bin := filepath.Join(home, ".local", "bin", "podaro")
	// The notices install.sh put beside the binary go with it, and first:
	// a removal that fails here leaves the binary in place for the re-run
	// that finishes the job. Only notices that are Podaro's own are taken
	// (internal/legal): the directory may hold other software.
	notices, err := legal.RemoveBeside(filepath.Dir(bin))
	if err != nil {
		p.Check(render.Fail, "notices removal failed", uninstallColumn, err.Error())
		return 1
	}
	switch _, err := os.Stat(bin); {
	case err == nil:
		if err := os.Remove(bin); err != nil {
			p.Check(render.Fail, "binary removal failed", uninstallColumn, err.Error())
			return 1
		}
		if notices {
			p.Check(render.Pass, "binary and the notices beside it removed", 0, "")
		} else {
			p.Check(render.Pass, "binary removed", 0, "")
		}
	case errors.Is(err, fs.ErrNotExist):
		p.Check(render.Skip, "binary not installed at ~/.local/bin/podaro", 0, "")
		if notices {
			p.Check(render.Pass, "the notices beside it removed", 0, "")
		}
	default:
		// "not installed" would be a guess: this says which it is.
		p.Check(render.Fail, "binary state unknown", uninstallColumn, err.Error())
		return 1
	}

	p.Blank()
	p.Plain("podman images remain · remove with: podman rmi --all")
	return 0
}

// stopService stops the engine service, tolerating only affirmatively
// stopped states: systemd reports the unit inactive, or — with systemd
// unreachable — every liveness probe reports absence. A live or
// unknowable engine aborts the uninstall; data is never removed
// underneath it.
func stopService() error {
	stopErr := systemctl("disable", "--now", "podaro.service").Run()
	if stopErr == nil {
		return nil
	}
	// is-active exits non-zero for inactive units — read the state from
	// stdout, not the exit code (stderr carries bus-failure noise, and a
	// bus failure must leave state empty so the probes decide).
	out, _ := systemctl("is-active", "podaro.service").Output()
	switch state := strings.TrimSpace(string(out)); state {
	case "inactive", "failed", "unknown":
		return nil // systemd affirms it is not running
	case "":
		facts, scanErr := scanProcesses()
		if provablyStopped(facts, scanErr, filepath.Join(config.RuntimeDir(), "api.sock")) {
			return nil
		}
	}
	e := pdr.New(pdr.CodeUninstallStopFailed, "could not stop podaro.service — uninstall aborted, nothing removed")
	e.Cause = stopErr.Error()
	e.Next = "systemctl --user stop podaro.service · journalctl --user -u podaro · then re-run podaro system uninstall"
	return e
}

// processFacts is what a /proc scan established about this user's
// processes relevant to engine liveness.
type processFacts struct {
	engine  bool // a `podaro engine serve` process exists
	manager bool // a `systemd --user` manager exists — restart machinery
}

// provablyStopped decides the bus-unreachable case: removal may proceed
// only when every fact is affirmative. A usable scan found neither an
// engine process nor a user service manager — a live manager we cannot
// talk to could be mid-`Restart=on-failure`, reviving the engine into
// deleted state, so its mere existence makes the situation unknowable —
// and the socket is affirmatively gone (ENOENT) or a leftover that
// refuses connections (conclusively stale once nothing exists to revive
// it). Scan failures, other stat errors, and answering listeners all
// count as running.
func provablyStopped(facts processFacts, scanErr error, sock string) bool {
	if scanErr != nil || facts.manager || facts.engine {
		return false
	}
	_, statErr := os.Stat(sock)
	if errors.Is(statErr, fs.ErrNotExist) {
		return true
	}
	if statErr != nil {
		return false // permission and friends: absence not proven
	}
	conn, dialErr := net.DialTimeout("unix", sock, time.Second)
	if dialErr == nil {
		_ = conn.Close()
		return false
	}
	return errors.Is(dialErr, syscall.ECONNREFUSED)
}

// scanProcesses walks /proc for this user's engine and service-manager
// processes. Only a process that demonstrably vanished mid-scan (ENOENT)
// is skipped; any other unreadable entry could be the engine, so the
// scan reports an error and callers must treat the result as unprovable.
func scanProcesses() (processFacts, error) {
	var facts processFacts
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return facts, err
	}
	uid := uint32(os.Getuid())
	for _, entry := range entries {
		pid := entry.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		info, err := os.Stat("/proc/" + pid)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue // vanished mid-scan
			}
			return facts, err
		}
		if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != uid {
			continue // another user's process cannot be our engine
		}
		raw, err := os.ReadFile("/proc/" + pid + "/cmdline")
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue // vanished mid-scan
			}
			return facts, err // unknowable same-user process
		}
		argv := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		if isEngineArgv(argv) {
			facts.engine = true
		}
		if isManagerArgv(argv) {
			facts.manager = true
		}
	}
	return facts, nil
}

// isEngineArgv reports whether an argv is the engine service process
// (the unit's ExecStart: `<path>/podaro engine serve`).
func isEngineArgv(argv []string) bool {
	return len(argv) >= 3 && filepath.Base(argv[0]) == "podaro" &&
		argv[1] == "engine" && argv[2] == "serve"
}

// isManagerArgv reports whether an argv is the systemd user manager
// (`/usr/lib/systemd/systemd --user`).
func isManagerArgv(argv []string) bool {
	return len(argv) >= 2 && filepath.Base(argv[0]) == "systemd" &&
		argv[1] == "--user"
}

// RenderUninstallRefusal renders the §7 refusal block.
func RenderUninstallRefusal(p *render.Printer, names []string) {
	if len(names) == 1 {
		p.Check(render.Fail, fmt.Sprintf("1 instance still exists: %s", names[0]), 0, "")
	} else {
		p.Check(render.Fail, fmt.Sprintf("%d instances still exist: %s", len(names), joinNames(names)), 0, "")
	}
	p.Indent(fmt.Sprintf("→ podaro destroy %s        (uninstall will not destroy labs for you)", names[0]), 0, "")
}

func joinNames(names []string) string {
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}
