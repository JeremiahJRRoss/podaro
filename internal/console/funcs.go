// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/evidence"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// Template helpers for the S7 surfaces. Each reads only what the JSON
// twin already carries; none invents a fact.

// ResultLine is the Verify state machine's resting line (UX §6):
// idle → running → ✓ passed | ✗ failed (+ hint) | ◇ attested.
type ResultLine struct {
	Instance   string
	Step       string
	Status     string
	Word       string
	Result     *state.CheckpointResult
	Checkpoint *engine.CheckpointView
	// Hint is the author's hint, shown inside the step on a failure only
	// — never beside a pass, which must leave no residue (UX §6).
	Hint string
	// Light, set only for a Presenter re-check, carries the confidence
	// light this verdict earns. The light lives in the step's title,
	// outside the region a result swaps, so the answer brings it along
	// out of band — otherwise a checkpoint that regressed changes its
	// result text and leaves the light green, which is the stale green
	// the re-check exists to prevent.
	Light string
	// Also names the other steps *on this page* that reference this
	// checkpoint, as the page names them. A checkpoint lives on the
	// template and a playbook's steps refer to it, so two steps can name
	// the same one — and one run produces one verdict, which is the
	// verdict of every step that names it.
	//
	// CheckpointView.Steps holds *qualified* ids, `playbook/step` (see
	// lab.instance), and the rail's regions are `result-<bare step id>`.
	// Round 7 used the qualified values directly, so every swap was
	// aimed at `result-<playbook>/<step>` and matched nothing: the
	// fix was inert, and the test that proved it passed only because its
	// fixture used bare ids the engine never produces (round 9). The
	// qualifier is also the filter — a step in a playbook this rail is
	// not showing has no element here at all.
	Also []string
}

// NewResultLine builds the line for one step — the API's entry point to
// the same constructor the rail template uses.
func NewResultLine(instance, playbook, step string, r *state.CheckpointResult, cp *engine.CheckpointView) ResultLine {
	return resultLine(instance, playbook, step, r, cp)
}

// NewPresenterResultLine is the same line for a Presenter re-check: it
// carries the confidence light too, so the answer updates the light in
// the step's title as well as the result beneath it.
func NewPresenterResultLine(instance, playbook, step string, r *state.CheckpointResult, cp *engine.CheckpointView) ResultLine {
	l := resultLine(instance, playbook, step, r, cp)
	l.Light = confidence(r)
	return l
}

// resultLine builds the line for one step.
func resultLine(instance, playbook, step string, r *state.CheckpointResult, cp *engine.CheckpointView) ResultLine {
	l := ResultLine{Instance: instance, Step: step, Result: r, Checkpoint: cp, Status: stepStatus(r)}
	l.Word = statusWord(r)
	if cp != nil && playbook != "" {
		prefix := playbook + "/"
		for _, other := range cp.Steps {
			bare, ok := strings.CutPrefix(other, prefix)
			if ok && bare != "" && bare != step {
				l.Also = append(l.Also, bare)
			}
		}
	}
	if l.Status == "fail" || l.Status == "error" {
		if r != nil && r.Hint != "" {
			l.Hint = r.Hint
		} else if cp != nil {
			l.Hint = cp.Hint
		}
	}
	return l
}

// Glyph is UX §4's glyph for this verdict, from the same mapping the
// rail's spine and the evidence scoreboard use.
//
// The template used to hand `glyph` the raw `.Status`. That helper knows
// the *tokens* — `attest`, `warn` — and not the result values `attested`
// and `error`, so both fell to its default and rendered `○` beside the
// words "self-verified" and "error": a pairing whose glyph contradicted
// its word, which is the rule round 23 was about. `syncSpine` then
// copied that glyph into the collapsed spine, so one mapping mistake
// reached both renderings.
//
// `statusToken` is that mapping and there is not a second one.
func (l ResultLine) Glyph() Glyph { return glyph(statusToken(l.Result)) }

// statusWord is the word half of UX §4's colour+glyph+word pairing.
func statusWord(r *state.CheckpointResult) string {
	switch stepStatus(r) {
	case "pass":
		return "passed"
	case "fail":
		return "failed"
	case "error":
		return "error"
	case "attested":
		return "self-verified"
	default:
		return "not verified yet"
	}
}

// status maps a result to a glyph token for the scoreboard.
func statusToken(r *state.CheckpointResult) string {
	switch stepStatus(r) {
	case "pass":
		return "pass"
	case "fail":
		return "fail"
	case "error":
		return "warn"
	case "attested":
		return "attest"
	default:
		return "pending"
	}
}

// Chip is one filter chip of the Evidence scoreboard.
type Chip struct {
	Value string
	Label string
	On    bool
}

func chips(current string) []Chip {
	if current == "" {
		current = "all"
	}
	out := []Chip{}
	for _, c := range []Chip{{Value: "all", Label: "All"}, {Value: "baseline", Label: "baseline"},
		{Value: "objective", Label: "objective"}, {Value: "fail", Label: "✗"}, {Value: "attest", Label: "◇"}} {
		c.On = c.Value == current
		out = append(out, c)
	}
	return out
}

// expectation renders a checkpoint's expectation as one line. The
// scoreboard shows what was asked for, never a verdict of its own.
func expectation(c engine.CheckpointView) string {
	if len(c.Expect) == 0 {
		return c.Adapter
	}
	keys := make([]string, 0, len(c.Expect))
	for k := range c.Expect {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+" "+scalar(c.Expect[k]))
	}
	return strings.Join(parts, " · ")
}

// scalar renders one expectation value compactly and without inventing
// precision: JSON numbers keep the shape they were authored in.
func scalar(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case json.Number:
		return t.String()
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%g", t)
	case nil:
		return "null"
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprintf("%v", t)
		}
		return string(b)
	}
}

// join renders a string slice as a comma-separated line.
func join(ss []string) string { return strings.Join(ss, ", ") }

// evSummary is one journal line for an evidence entry: a projection of
// the entry's own fields, never a fact of its own. A checkpoint row says
// what was judged and how; a lifecycle row its event and code; a seed row
// what was sent; an audit row who did what. Values never appear — an
// audit of a reveal names the secret, not its value (invariant 6).
func evSummary(e evidence.Entry) string {
	switch {
	case e.Checkpoint != nil:
		c := e.Checkpoint
		s := c.ID + " " + c.Status
		if c.Duration != "" {
			s += " · " + c.Duration
		}
		if c.Message != "" {
			s += " · " + c.Message
		}
		return s
	case e.Lifecycle != nil:
		l := e.Lifecycle
		s := l.Event
		if l.Stage != "" {
			s += " · " + l.Stage
		}
		if l.Code != "" {
			s += " · " + l.Code
		}
		if l.Detail != "" {
			s += " · " + l.Detail
		}
		return s
	case e.Seed != nil:
		return "seed " + e.Seed.Name + " · " + e.Seed.Message
	case e.Audit != nil:
		a := e.Audit
		s := a.Action
		if a.Detail != "" {
			s += " · " + a.Detail
		}
		if a.Actor != "" {
			s += " · by " + a.Actor
		}
		return s
	default:
		return string(e.Type)
	}
}
