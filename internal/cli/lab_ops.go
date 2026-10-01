// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremiahjrross/podaro/internal/client"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// The lab operations of User Manual §8 (plan S6): seed, verify, reset —
// clients of the engine's local socket door, each a job followed on the
// ladder (UX §7), each with a `--json` twin of stable shape.

// completion prints the closing block of up and reset (User Manual §6):
// any PDR-W101 warnings the job journaled, the ready line with the
// class-split tally (never summed, spec 0001 §1), and the console URL
// last, alone on its line (UX §7).
func completion(p *render.Printer, v *engine.InstanceView, events []state.Event) {
	warned := false
	for _, ev := range events {
		if ev.Step == "checkpoint" && ev.Status == "warn" {
			if !warned {
				p.Blank()
				warned = true
			}
			p.Check(render.Warn, ev.Detail, 0, "")
		}
	}
	p.Blank()
	label := fmt.Sprintf("%s is %s", v.Name, v.Ladder.Stage)
	detail := fmt.Sprintf("— baseline %d/%d verified · objectives %d/%d", v.Checkpoints.Baseline.Passed, v.Checkpoints.Baseline.Total, v.Checkpoints.Objective.Passed, v.Checkpoints.Objective.Total)
	if v.Checkpoints.Objective.Total > 0 {
		detail += " (those are yours to earn)"
	}
	p.Check(render.Pass, label, len(label)+1, detail)
	if v.ConsoleURL != "" {
		p.Blank()
		p.Plain(v.ConsoleURL)
	} else {
		p.Plain("  console: not yet — podaro setup --domain <domain> opens the gateway")
	}
}

// finish waits for a job, fails the command on a failed job, and returns
// the settled job with its journal.
func finish(ctx context.Context, c *client.Client, job *state.Job) (*state.Job, []state.Event, error) {
	final, err := followJob(ctx, c, job, os.Stdout)
	if err != nil {
		return nil, nil, jsonOrErr(err, 1)
	}
	if final.State != state.JobSucceeded {
		return nil, nil, jobFailure(final)
	}
	_, events, err := c.Job(ctx, final.ID)
	if err != nil {
		return nil, nil, jsonOrErr(err, 1)
	}
	return final, events, nil
}

func newSeed() *cobra.Command {
	return &cobra.Command{
		Use:   "seed <instance> <seed>",
		Short: "run a named data injection (again) — idempotent by contract",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClient()
			ctx := context.Background()
			job, err := c.Seed(ctx, args[0], args[1])
			if err != nil {
				return jsonOrErr(err, 1)
			}
			final, events, err := finish(ctx, c, job)
			if err != nil {
				return err
			}
			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{"job": final})
			}
			detail := ""
			for _, ev := range events {
				if ev.Step == "seed" && ev.Status == "ok" {
					detail = "· " + ev.Detail
				}
			}
			p := render.Detect(os.Stdout)
			p.Blank()
			label := "seed " + args[1] + " sent"
			p.Check(render.Pass, label, len(label)+1, detail)
			return nil
		},
	}
}

func newVerify() *cobra.Command {
	var playbook string
	cmd := &cobra.Command{
		Use:   "verify <instance>",
		Short: "run all (or one playbook's) checkpoints now — the pre-flight",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClient()
			ctx := context.Background()
			job, err := c.Verify(ctx, args[0], playbook)
			if err != nil {
				return jsonOrErr(err, 1)
			}
			final, _, err := finish(ctx, c, job)
			if err != nil {
				return err
			}
			cps, err := c.Checkpoints(ctx, args[0])
			if err != nil {
				return jsonOrErr(err, 1)
			}
			cps = verified(cps, playbook)
			if jsonOut {
				results := []state.CheckpointResult{}
				for _, cp := range cps {
					if cp.Result != nil {
						results = append(results, *cp.Result)
					}
				}
				return json.NewEncoder(os.Stdout).Encode(map[string]any{"job": final, "results": results})
			}
			v, err := c.Instance(ctx, args[0])
			if err != nil {
				return jsonOrErr(err, 1)
			}
			p := render.Detect(os.Stdout)
			p.Blank()
			p.Plain(fmt.Sprintf("%s · verify · baseline %d/%d · objectives %d/%d", v.Name, v.Checkpoints.Baseline.Passed, v.Checkpoints.Baseline.Total, v.Checkpoints.Objective.Passed, v.Checkpoints.Objective.Total))
			renderCheckpoints(p, cps)
			return nil
		},
	}
	cmd.Flags().StringVar(&playbook, "playbook", "", "verify one playbook's objectives beside every baseline")
	return cmd
}

// verified keeps the checkpoints a verify judged: every baseline, and the
// objectives of the named playbook when one was given.
func verified(cps []engine.CheckpointView, playbook string) []engine.CheckpointView {
	if playbook == "" {
		return cps
	}
	var out []engine.CheckpointView
	for _, cp := range cps {
		if cp.Class == "baseline" {
			out = append(out, cp)
			continue
		}
		for _, s := range cp.Steps {
			if strings.HasPrefix(s, playbook+"/") {
				out = append(out, cp)
				break
			}
		}
	}
	return out
}

// renderCheckpoints prints the class-split list (UX §6): glyph by status,
// id, status word, and one clause of context — the duration and the
// adapter's message, or the hint on a failed objective.
func renderCheckpoints(p *render.Printer, cps []engine.CheckpointView) {
	width := 14
	for _, cp := range cps {
		if len(cp.ID)+2 > width {
			width = len(cp.ID) + 2
		}
	}
	for _, class := range []string{"baseline", "objective"} {
		var rows []engine.CheckpointView
		for _, cp := range cps {
			if cp.Class == class {
				rows = append(rows, cp)
			}
		}
		if len(rows) == 0 {
			continue
		}
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
		p.Plain("  " + class + "s")
		for _, cp := range rows {
			g, word, context := render.Skip, "pending", "not yet evaluated"
			if r := cp.Result; r != nil {
				word = r.Status
				switch r.Status {
				case "pass":
					g = render.Pass
				case "fail":
					g = render.Fail
				case "attested":
					g = render.Attest
				case "error":
					g = render.Warn
				case "pending":
					g = render.Skip
				}
				var parts []string
				if r.Duration != "" {
					parts = append(parts, r.Duration)
				}
				switch {
				case r.Status == "error" && r.Error != nil:
					parts = append(parts, r.Error.Code+" "+r.Error.Message)
				case r.Status == "fail" && r.Hint != "":
					parts = append(parts, r.Hint)
				case r.Message != "":
					parts = append(parts, r.Message)
				}
				context = strings.Join(parts, " · ")
			}
			p.Plain("    " + p.Row(g, cp.ID, width, word, context))
		}
	}
}

func newReset() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "reset <instance>",
		Short: "return to freshly-verified baseline — the impact is shown first, then asked",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if !yes && !isTerminal(os.Stdin) {
				// No terminal to answer on: a usage problem, reported before
				// the engine is asked anything (UX §7).
				pe := pdr.New(pdr.CodeResetConfirm, "reset needs confirmation: answer on a terminal, or pass --yes in scripts")
				pe.Next = "podaro reset " + name + " --yes"
				return jsonOrErr(pe, 2)
			}
			c := newClient()
			ctx := context.Background()
			plan, err := c.ResetPlan(ctx, name)
			if err != nil {
				return jsonOrErr(err, 1)
			}
			p := render.Detect(os.Stdout)
			if !jsonOut {
				renderResetPlan(p, name, plan)
			}
			if !yes {
				fmt.Print("continue? [y/N]: ")
				line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
				if l := strings.ToLower(strings.TrimSpace(line)); l != "y" && l != "yes" {
					p.Plain("reset cancelled — nothing changed")
					return nil
				}
			}
			job, err := c.Reset(ctx, name)
			if err != nil {
				return jsonOrErr(err, 1)
			}
			final, events, err := finish(ctx, c, job)
			if err != nil {
				return err
			}
			v, err := c.Instance(ctx, name)
			if err != nil {
				return jsonOrErr(err, 1)
			}
			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{"reset_plan": plan, "instance": v, "job": final})
			}
			completion(p, v, events)
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the y/N confirmation (scripts)")
	return cmd
}

// renderResetPlan prints the two-column impact preview (UX §7): what the
// reset destroys on the left, what survives on the right.
func renderResetPlan(p *render.Printer, name string, plan *engine.ResetPlan) {
	width := 24
	for _, d := range plan.Destroyed {
		if len(d)+3 > width {
			width = len(d) + 3
		}
	}
	p.Plain(fmt.Sprintf("reset %s — impact", name))
	p.Plain(fmt.Sprintf("  %-*s%s", width, "destroyed", "survives"))
	rows := len(plan.Destroyed)
	if len(plan.Survives) > rows {
		rows = len(plan.Survives)
	}
	for i := 0; i < rows; i++ {
		left, right := "", ""
		if i < len(plan.Destroyed) {
			left = plan.Destroyed[i]
		}
		if i < len(plan.Survives) {
			right = plan.Survives[i]
		}
		p.Plain(strings.TrimRight(fmt.Sprintf("  %-*s%s", width, left, right), " "))
	}
}
