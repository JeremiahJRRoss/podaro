// SPDX-License-Identifier: AGPL-3.0-only

// Package doctor implements every check in INSTALL §2 step 3. Doctor
// diagnoses and prescribes but never operates: every probe is a read, and
// where root is genuinely required it prints the exact command for the
// operator to run (the trust posture, INSTALL §1). The JSON report is the
// shape POST /system/doctor will serve at S5 (API §5).
package doctor

import (
	"fmt"
	"strings"

	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/render"
)

// Status is one check outcome. API §5: pass/warn/fail — plus pending for
// checks awaiting configuration (dns before `podaro setup`).
type Status string

const (
	Pass    Status = "pass"
	Warn    Status = "warn"
	Fail    Status = "fail"
	Pending Status = "pending"
)

// Check is one row of the report.
type Check struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Status      Status `json:"status"`
	Finding     string `json:"finding"`
	Remediation string `json:"remediation,omitempty"`
}

// Summary tallies the board.
type Summary struct {
	Pass     int `json:"pass"`
	Warn     int `json:"warn"`
	Fail     int `json:"fail"`
	Pending  int `json:"pending"`
	NeedRoot int `json:"need_root"`
}

// Report is the full doctor result; its JSON is the API §5 shape
// (`podaro doctor --json` emits exactly this).
type Report struct {
	Checks  []Check `json:"checks"`
	Summary Summary `json:"summary"`
}

// AdvisoryMapCount is the vm.max_map_count some search products require.
// Nothing in Podaro needs it, so the row that names it is advisory: it
// reports the value and never fails or asks for root (the reconciliation
// plan's D-R6; the retired golden lab was what once required it). An
// operator who runs such a product in a lab sets the value themselves.
const AdvisoryMapCount = 262144

// WildcardProbe is the label doctor resolves beneath the configured
// domain to test the wildcard record itself.
const WildcardProbe = "podaro-wildcard-check"

// MinPodman is the minimum supported Podman (User Manual §3).
const MinPodman = "4.4"

// Run executes every check against the given probes and configuration.
func Run(p Probes, cfg *config.Config) Report {
	var r Report
	add := func(c Check) {
		switch c.Status {
		case Pass:
			r.Summary.Pass++
		case Warn:
			r.Summary.Warn++
		case Fail:
			r.Summary.Fail++
			if strings.Contains(c.Remediation, "sudo ") {
				r.Summary.NeedRoot++
			}
		case Pending:
			r.Summary.Pending++
		}
		r.Checks = append(r.Checks, c)
	}

	user := p.Username()

	// podman: version, rootless, cgroups — `podman info`, read-only.
	if facts, err := p.PodmanInfo(); err != nil {
		add(Check{ID: "podman", Label: "podman", Status: Fail,
			Finding:     "not found — Podaro needs Podman ≥ " + MinPodman + " (rootless)",
			Remediation: "install Podman ≥ " + MinPodman + " from your distribution, then: podaro doctor"})
	} else {
		label := "podman " + facts.Version
		switch {
		case !versionAtLeast(facts.Version, MinPodman):
			add(Check{ID: "podman", Label: label, Status: Fail,
				Finding:     fmt.Sprintf("version < %s — upgrade required", MinPodman),
				Remediation: "upgrade Podman via your distribution, then: podaro doctor"})
		case !facts.Rootless:
			add(Check{ID: "podman", Label: label, Status: Fail,
				Finding:     "running rootful — Podaro is rootless-only (User Manual §3)",
				Remediation: "run podaro as your own user with rootless Podman configured"})
		case facts.CgroupVersion != "v2":
			add(Check{ID: "podman", Label: label, Status: Warn,
				Finding: "rootless · cgroups " + facts.CgroupVersion + " — v2 recommended"})
		default:
			add(Check{ID: "podman", Label: label, Status: Pass,
				Finding: "rootless · cgroups v2"})
		}
	}

	// subuid/subgid: ranges mapped for the user — /etc/subuid, /etc/subgid.
	if uidR, _, err := p.SubIDs(user); err != nil {
		add(Check{ID: "subids", Label: "subuid / subgid", Status: Fail,
			Finding:     fmt.Sprintf("no ranges mapped for %s", user),
			Remediation: fmt.Sprintf("sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 %s", user)})
	} else {
		add(Check{ID: "subids", Label: "subuid / subgid", Status: Pass,
			Finding: fmt.Sprintf("%d-%d mapped for %s", uidR.Start, uidR.Start+uidR.Count-1, user)})
	}

	// lingering: labs must survive logout — `loginctl show-user`.
	if linger, err := p.Linger(user); err != nil || !linger {
		add(Check{ID: "lingering", Label: "lingering", Status: Fail,
			Finding:     "disabled — labs would stop when you log out",
			Remediation: fmt.Sprintf("sudo loginctl enable-linger %s", user)})
	} else {
		add(Check{ID: "lingering", Label: "lingering", Status: Pass,
			Finding: "enabled for " + user})
	}

	// vm.max_map_count: advisory — a /proc/sys read, reported as it is.
	if mmc, err := p.MaxMapCount(); err != nil {
		add(Check{ID: "max-map-count", Label: "vm.max_map_count", Status: Warn,
			Finding: "unreadable: " + err.Error() + "; advisory"})
	} else {
		add(Check{ID: "max-map-count", Label: "vm.max_map_count", Status: Pass,
			Finding: fmt.Sprintf("%d — some search products require %d; advisory", mmc, AdvisoryMapCount)})
	}

	// gateway port: momentary bind test, released immediately.
	port := config.DefaultGatewayPort
	if cfg != nil {
		port = cfg.Gateway.Port
	}
	portLabel := fmt.Sprintf("port %d", port)
	if free, err := p.PortFree(port); err != nil || !free {
		add(Check{ID: "port", Label: portLabel, Status: Fail,
			Finding:     "in use — another service is listening",
			Remediation: fmt.Sprintf("free the port, or set gateway.port in %s", config.Path())})
	} else {
		add(Check{ID: "port", Label: portLabel, Status: Pass, Finding: "free"})
	}

	// disk: statfs on the state directory's filesystem, reported as it is.
	// Its warning below 60 GB was the retired golden lab's figure (the
	// reconciliation plan's D-R6); no retained template documents one.
	if free, err := p.DiskFree(config.StateDir()); err != nil {
		add(Check{ID: "disk", Label: "disk", Status: Fail,
			Finding: "cannot stat state directory: " + err.Error()})
	} else {
		add(Check{ID: "disk", Label: "disk", Status: Pass,
			Finding: fmt.Sprintf("%d GB free on ~/.local/state", free/1_000_000_000)})
	}

	// dns: resolution for the configured domain; pending before setup.
	// Instances live at single-level names under the domain and operators
	// create only the wildcard record (User Manual §5) — a DNS wildcard
	// does not make the apex resolve, so probe a covered hostname.
	if cfg == nil || cfg.Domain == "" {
		add(Check{ID: "dns", Label: "dns", Status: Pending,
			Finding: "no domain configured yet (podaro setup)"})
	} else if addrs, err := p.LookupHost(WildcardProbe + "." + cfg.Domain); err != nil || len(addrs) == 0 {
		add(Check{ID: "dns", Label: "dns", Status: Fail,
			Finding:     fmt.Sprintf("*.%s does not resolve — see User Manual §5", cfg.Domain),
			Remediation: fmt.Sprintf("point *.%s at this host (one wildcard A record), or use your workstation's hosts file", cfg.Domain)})
	} else {
		add(Check{ID: "dns", Label: "dns", Status: Pass,
			Finding: fmt.Sprintf("*.%s → %s", cfg.Domain, addrs[0])})
	}

	// observability: the export's posture, and only when there is one.
	// Export is off by default and a row saying so on every board would
	// be a line about a feature the operator did not ask for — the
	// INSTALL §2 step-3 block is the board with export off.
	if c := observability(cfg); c != nil {
		add(*c)
	}

	// legal notices: the directory `podaro system install` writes the
	// licence and the notices to (the reconciliation plan's R5). Named
	// only when it is missing — a board that says the files are where
	// they belong would be a row on every doctor run for nothing asked.
	// A warning, never a failure: `podaro legal` and /legal read the
	// binary, which always carries them.
	if lp, ok := p.(interface{ LegalNotices() (string, bool) }); ok {
		if dir, present := lp.LegalNotices(); !present {
			add(Check{ID: "legal-notices", Label: "legal notices", Status: Warn,
				Finding:     dir + " missing · podaro system install writes it (podaro legal prints the same)",
				Remediation: "podaro system install"})
		}
	}

	return r
}

// observability reports where the engine's own signals go (Manual §4,
// roadmap §9). Nil when export is off. A destination whose certificate
// is not verified is a warning, not a pass: it is the escape hatch the
// threat model allows and asks to be said out loud (B10).
func observability(cfg *config.Config) *Check {
	if cfg == nil || cfg.Observability == nil {
		return nil
	}
	var on, insecure []string
	for _, sig := range []struct {
		name string
		s    *config.Signal
	}{{"logs", cfg.Observability.Logs}, {"metrics", cfg.Observability.Metrics}, {"traces", cfg.Observability.Traces}} {
		if sig.s == nil {
			continue
		}
		on = append(on, fmt.Sprintf("%s→%s", sig.name, sig.s.Exporter))
		if sig.s.Insecure {
			insecure = append(insecure, sig.name)
		}
	}
	if len(on) == 0 {
		return nil
	}
	c := Check{ID: "observability", Label: "observability", Status: Pass,
		Finding: "export on · " + strings.Join(on, " · ")}
	if len(insecure) > 0 {
		c.Status = Warn
		c.Finding += fmt.Sprintf(" — %s: certificate verification off", strings.Join(insecure, ", "))
		c.Remediation = "remove insecure: true from those signals once the destination's CA is trusted"
	}
	return &c
}

// column is the doctor block's detail column (INSTALL §2 step 3).
const column = 22

// Render prints the report in the CLI grammar, byte-compatible with the
// INSTALL step-3 block.
func (r Report) Render(p *render.Printer) {
	for _, c := range r.Checks {
		p.Check(glyph(c.Status), c.Label, column, c.Finding)
		if c.Remediation != "" && c.Status == Fail {
			// "run once" is the idempotent-sudo-command promise (INSTALL
			// §2 step 3); advisory remediations get a neutral intro.
			intro := "→ next:"
			if strings.Contains(c.Remediation, "sudo ") {
				intro = "→ run once:"
			}
			p.Indent(intro, column, c.Remediation)
		}
	}
	if line := r.SummaryLine(); line != "" {
		p.Blank()
		p.Plain(line)
	}
}

// SummaryLine is the closing line under the board; empty when all green.
func (r Report) SummaryLine() string {
	s := r.Summary
	switch {
	case s.NeedRoot == 1:
		return "1 item needs root — run the printed command, then: podaro doctor"
	case s.NeedRoot > 1:
		return fmt.Sprintf("%d items need root — run the printed commands, then: podaro doctor", s.NeedRoot)
	case s.Fail == 1:
		return "1 check failed — fix the finding above, then: podaro doctor"
	case s.Fail > 1:
		return fmt.Sprintf("%d checks failed — fix the findings above, then: podaro doctor", s.Fail)
	}
	return ""
}

func glyph(s Status) render.Glyph {
	switch s {
	case Pass:
		return render.Pass
	case Warn:
		return render.Warn
	case Fail:
		return render.Fail
	default:
		return render.Pending
	}
}

// versionAtLeast compares dotted numeric versions ("4.9.4" ≥ "4.4").
func versionAtLeast(have, want string) bool {
	hp, wp := strings.Split(have, "."), strings.Split(want, ".")
	for i := range wp {
		var h, w int
		fmt.Sscanf(wp[i], "%d", &w)
		if i < len(hp) {
			fmt.Sscanf(hp[i], "%d", &h)
		}
		if h != w {
			return h > w
		}
	}
	return true
}
