// SPDX-License-Identifier: AGPL-3.0-only

package system

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
)

// ServiceUnit is the systemd user unit `system install` writes (INSTALL
// §3); start, stop, restart and status drive it (INSTALL §2 step 6,
// Manual §15).
const ServiceUnit = "podaro.service"

// serviceColumn is the service block's detail column, the install
// block's (INSTALL §2).
const serviceColumn = 19

// serviceAnswerWait is how long a started or restarted engine has to
// answer before the start is called a failure; tests shorten it.
var serviceAnswerWait = engineAnswerWait

// ServiceStatus is what `podaro system status` reports (and its --json
// shape): the unit as systemd describes it, and whether the engine behind
// it answers on its socket — a unit that is active is not yet an engine
// that serves.
type ServiceStatus struct {
	Unit     string       `json:"unit"`
	Loaded   bool         `json:"loaded"`          // systemd knows the unit: system install has run
	State    string       `json:"state"`           // systemd's ActiveState: active, inactive, failed, activating, deactivating
	SubState string       `json:"sub_state"`       // running, dead, auto-restart, …
	Since    string       `json:"since,omitempty"` // when the state was entered, as systemd prints it
	Restarts int          `json:"restarts"`        // automatic restarts since the unit last started
	PID      int          `json:"pid,omitempty"`
	Engine   EngineStatus `json:"engine"`
}

// EngineStatus is the probe over the local socket.
type EngineStatus struct {
	Socket  string `json:"socket"`
	Answers bool   `json:"answers"`
	Detail  string `json:"detail,omitempty"` // why it does not answer
}

// Healthy is the state `status` exits 0 for: the unit active and the
// engine answering.
func (s ServiceStatus) Healthy() bool { return s.State == "active" && s.Engine.Answers }

// ServiceStatusNow reads the unit from systemd and probes the engine.
// A systemd it cannot ask is PDR-E027; a unit systemd does not know is
// reported, not an error — that is a host where install has not run.
func ServiceStatusNow() (ServiceStatus, error) {
	st := ServiceStatus{Unit: ServiceUnit, Engine: EngineStatus{Socket: filepath.Join(config.RuntimeDir(), "api.sock")}}
	out, err := systemctl("show", ServiceUnit, "-p", "LoadState,ActiveState,SubState,NRestarts,MainPID,StateChangeTimestamp").CombinedOutput()
	if err != nil {
		return st, serviceControlError("read", "the state of "+ServiceUnit+" could not be read", fmt.Sprintf("systemctl --user show %s: %v: %s", ServiceUnit, err, strings.TrimSpace(string(out))))
	}
	props := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			props[k] = strings.TrimSpace(v)
		}
	}
	st.Loaded = props["LoadState"] == "loaded"
	st.State = props["ActiveState"]
	st.SubState = props["SubState"]
	st.Since = props["StateChangeTimestamp"]
	st.Restarts, _ = strconv.Atoi(props["NRestarts"])
	st.PID, _ = strconv.Atoi(props["MainPID"])
	if err := engineAnswers(socketClient(st.Engine.Socket)); err != nil {
		st.Engine.Detail = err.Error()
	} else {
		st.Engine.Answers = true
	}
	return st, nil
}

// RenderServiceStatus prints the status block (INSTALL §2 step 6): the
// service row, the engine row, and the one next action the state calls
// for.
func RenderServiceStatus(p *render.Printer, st ServiceStatus) {
	if !st.Loaded {
		p.Check(render.Fail, "service", serviceColumn, st.Unit+" · not installed")
		p.NextAction("podaro system install")
		return
	}
	state := st.State
	if st.SubState != "" {
		state += " (" + st.SubState + ")"
	}
	detail := st.Unit + " · " + state
	if st.Since != "" {
		detail += " since " + st.Since
	}
	if st.PID > 0 {
		detail += " · pid " + strconv.Itoa(st.PID)
	}
	detail += fmt.Sprintf(" · %d restart%s", st.Restarts, plural(st.Restarts))
	var glyph render.Glyph
	switch st.State {
	case "active":
		glyph = render.Pass
	case "activating", "deactivating", "reloading":
		glyph = render.Warn
	default:
		glyph = render.Fail
	}
	p.Check(glyph, "service", serviceColumn, detail)
	switch {
	case st.Engine.Answers:
		p.Check(render.Pass, "engine", serviceColumn, "answers on "+st.Engine.Socket)
	case st.State == "active":
		p.Check(render.Warn, "engine", serviceColumn, "no answer on "+st.Engine.Socket+" · "+st.Engine.Detail)
	default:
		p.Check(render.Fail, "engine", serviceColumn, "no answer on "+st.Engine.Socket)
	}
	switch {
	case st.Healthy():
		p.NextAction("podaro status")
	case st.State == "active" || st.State == "activating":
		p.NextAction("journalctl --user -u podaro · podaro system status")
	default:
		p.NextAction("podaro system start")
	}
}

// ServiceStart starts the unit and waits for the engine to answer
// (INSTALL §2 step 6). Started but not answering is the failure that
// matters: a socket that exists is not an engine that serves.
func ServiceStart(p *render.Printer) error {
	if err := control("start"); err != nil {
		return err
	}
	sock, err := awaitEngine(serviceAnswerWait)
	if err != nil {
		return serviceControlError("start", ServiceUnit+" started but the engine did not answer", err.Error())
	}
	p.Check(render.Pass, "service", serviceColumn, ServiceUnit+" started")
	p.Check(render.Pass, "engine", serviceColumn, "answers on "+strings.TrimSuffix(sock, " (0600)"))
	p.NextAction("podaro status")
	return nil
}

// ServiceStop stops the unit. The labs' containers belong to Podman, not
// to the engine process, so they stay up; the console and every product
// hostname answer again after start (INSTALL §6).
func ServiceStop(p *render.Printer) error {
	if err := control("stop"); err != nil {
		return err
	}
	p.Check(render.Pass, "service", serviceColumn, ServiceUnit+" stopped · labs keep running under podman · the console answers again after start")
	p.NextAction("podaro system start")
	return nil
}

// ServiceRestart restarts the unit, waits for the engine to answer, and
// names the instances it reattached to — the restart wait and the
// reattach report `system upgrade` makes (INSTALL §6).
func ServiceRestart(p *render.Printer) error {
	if err := control("restart"); err != nil {
		return err
	}
	sock, err := awaitEngine(serviceAnswerWait)
	if err != nil {
		return serviceControlError("restart", ServiceUnit+" restarted but the engine did not answer", err.Error())
	}
	p.Check(render.Pass, "service", serviceColumn, ServiceUnit+" restarted")
	detail := "answers on " + strings.TrimSuffix(sock, " (0600)")
	if names, unsupported, err := reattached(); err == nil {
		switch {
		case len(names) == 0 && len(unsupported) == 0:
			detail += " · no instances"
		case len(names) > 0:
			detail += fmt.Sprintf(" · %d instance%s reattached: %s", len(names), plural(len(names)), strings.Join(names, ", "))
		}
		// An instance of a retired template is not reattached: the engine
		// leaves it as it found it (the reconciliation plan's R3).
		if len(unsupported) > 0 {
			detail += " · unsupported, left as found: " + strings.Join(unsupported, ", ")
		}
	}
	p.Check(render.Pass, "engine", serviceColumn, detail)
	p.NextAction("podaro status")
	return nil
}

// control runs one systemctl verb on the unit; a refusal is PDR-E027
// with systemd's words as the cause and the next action its words call
// for.
func control(verb string) error {
	out, err := systemctl(verb, ServiceUnit).CombinedOutput()
	if err == nil {
		return nil
	}
	return serviceControlError(verb, ServiceUnit+" could not be "+past(verb), fmt.Sprintf("systemctl --user %s %s: %v: %s", verb, ServiceUnit, err, strings.TrimSpace(string(out))))
}

// serviceControlError builds PDR-E027. The cause is read for the two
// states that have their own remedy: a unit systemd does not know (install
// has not run) and a bus it cannot reach (no service manager: the account
// is not lingering, or the shell has no session — sudo -iu podaro has one
// through the installer's profile block, and podaroctl supplies one).
func serviceControlError(verb, message, cause string) error {
	e := pdr.New(pdr.CodeServiceControl, "%s", message)
	e.Cause = cause
	lower := strings.ToLower(cause)
	switch {
	case strings.Contains(lower, "not found") || strings.Contains(lower, "not loaded") || strings.Contains(lower, "could not be found"):
		e.Next = "podaro system install (INSTALL §2 step 2) writes the unit · then re-run the " + verb
	case strings.Contains(lower, "connect to bus") || strings.Contains(lower, "dbus") || strings.Contains(lower, "xdg_runtime_dir"):
		e.Next = "this shell cannot reach the account's service manager: sudo loginctl enable-linger " + accountName() + " · then a sudo -iu " + accountName() + " login shell, or sudo podaroctl system " + verb
	default:
		e.Next = "journalctl --user -u podaro · podaro system status"
	}
	return e
}

// accountName is the account the manuals name; the engine has no other
// way to know which Linux account it runs as than the environment.
func accountName() string {
	for _, k := range []string{"USER", "LOGNAME"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return "podaro"
}

func past(verb string) string {
	switch verb {
	case "stop":
		return "stopped"
	case "start":
		return "started"
	case "restart":
		return "restarted"
	}
	return verb + "ed"
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
