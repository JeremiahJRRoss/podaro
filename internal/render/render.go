// SPDX-License-Identifier: AGPL-3.0-only

// Package render is the shared CLI output grammar (UX Guide §7): one glyph
// set, column-aligned status lines, the error anatomy, honest degradation.
// TTY gets color; piped output or NO_COLOR gets plain lines with no ANSI;
// a non-UTF-8 locale gets the documented ASCII glyph fallbacks. JSON mode
// is handled by callers marshalling structs — decoration never mixes in.
package render

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// Glyph is one symbol from the UX Guide §4 set.
type Glyph int

const (
	None Glyph = iota // two-space indent, e.g. remediation lines
	Pending
	Progress
	Complete
	Pass
	Fail
	Warn
	Attest
	Skip
	Next
)

var unicodeGlyphs = map[Glyph]string{
	Pending: "○", Progress: "◐", Complete: "●", Pass: "✓",
	Fail: "✗", Warn: "!", Attest: "◇", Skip: "–", Next: "→",
}

// Terminal fallback per UX §4 when the locale can't render the set.
var asciiGlyphs = map[Glyph]string{
	Pending: ".", Progress: "o", Complete: "*", Pass: "ok",
	Fail: "x", Warn: "!", Attest: "~", Skip: "-", Next: ">",
}

var colors = map[Glyph]string{
	Pending: "\x1b[2m", Progress: "\x1b[34m", Complete: "\x1b[32m",
	Pass: "\x1b[32m", Fail: "\x1b[31m", Warn: "\x1b[33m", Attest: "\x1b[35m",
	Skip: "\x1b[2m",
}

const colorReset = "\x1b[0m"

// Printer renders the grammar onto one writer.
type Printer struct {
	w       io.Writer
	color   bool
	unicode bool
}

// New returns a Printer with explicit behavior — used by tests and JSON
// callers that must be deterministic.
func New(w io.Writer, color, unicode bool) *Printer {
	return &Printer{w: w, color: color, unicode: unicode}
}

// Detect returns a Printer configured for the environment: color only on a
// TTY without NO_COLOR (https://no-color.org) and with a capable TERM;
// ASCII glyphs when the locale is not UTF-8.
func Detect(w io.Writer) *Printer {
	color := false
	if f, ok := w.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		color = os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
	}
	return &Printer{w: w, color: color, unicode: localeIsUTF8()}
}

func localeIsUTF8() bool {
	for _, v := range []string{os.Getenv("LC_ALL"), os.Getenv("LC_CTYPE"), os.Getenv("LANG")} {
		if v == "" {
			continue
		}
		u := strings.ToUpper(v)
		return strings.Contains(u, "UTF-8") || strings.Contains(u, "UTF8")
	}
	// No locale variables at all (containers, systemd units): the glyphs
	// are more often right than wrong, and the fallback exists for
	// terminals that declare otherwise.
	return true
}

func (p *Printer) glyph(g Glyph) string {
	if g == None {
		return " "
	}
	set := unicodeGlyphs
	if !p.unicode {
		set = asciiGlyphs
	}
	s := set[g]
	if p.color {
		if c, ok := colors[g]; ok {
			return c + s + colorReset
		}
	}
	return s
}

// Check prints one column-aligned status line: glyph, label padded to
// width, detail. Blocks pick their width (INSTALL §2: doctor 22, install
// 19) so the detail column lands exactly where the manual shows it.
func (p *Printer) Check(g Glyph, label string, width int, detail string) {
	if detail == "" {
		fmt.Fprintf(p.w, "%s %s\n", p.glyph(g), label)
		return
	}
	fmt.Fprintf(p.w, "%s %-*s%s\n", p.glyph(g), width, label, detail)
}

// Indent prints a two-space-indented, column-aligned line — the
// remediation form: `  → run once:           sudo …`.
func (p *Printer) Indent(label string, width int, detail string) {
	label = strings.Replace(label, "→", p.glyph(Next), 1)
	if detail == "" {
		fmt.Fprintf(p.w, "  %s\n", label)
		return
	}
	fmt.Fprintf(p.w, "  %-*s%s\n", width, label, detail)
}

// Row renders one ladder line without printing it (UX §5): the service
// name padded to width, then glyph + stage word padded to 15, then the
// context clause — `prometheus     ● ready          healthy in 38s`. With
// the None glyph the line is name then text (the checkpoints tally).
func (p *Printer) Row(g Glyph, name string, width int, word, context string) string {
	var line string
	if g == None {
		line = fmt.Sprintf("%-*s%s", width, name, word)
	} else {
		line = fmt.Sprintf("%-*s%s %-15s%s", width, name, p.glyph(g), word, context)
	}
	return strings.TrimRight(line, " ")
}

// Plain prints a line verbatim (summaries, closing lines).
func (p *Printer) Plain(s string) { fmt.Fprintln(p.w, s) }

// Blank prints an empty line.
func (p *Printer) Blank() { fmt.Fprintln(p.w) }

// NextAction prints the closing pointer line: `→ next: podaro doctor`.
func (p *Printer) NextAction(cmd string) {
	fmt.Fprintf(p.w, "%s next: %s\n", p.glyph(Next), cmd)
}

// Anatomy renders the error anatomy (User Manual §14, API §3): code line,
// then cause / evidence / next in a 10-wide label column.
func (p *Printer) Anatomy(e *pdr.Error) {
	for _, l := range p.AnatomyLines(e) {
		fmt.Fprintln(p.w, l)
	}
}

// AnatomyLines is the same anatomy as lines, for a caller that redraws a
// frame in place and therefore has to know how many lines it wrote
// (`podaro status --watch`). One implementation, so the two can never
// drift apart.
//
// One element per *physical* line, because a field can hold several: an
// init failure's cause is the helper's combined output (engine create, and
// spec 0003 §9.1's runner), and one slice element holding three rows made
// a redrawing caller move the cursor up too few lines and leave the rest
// of the last frame on screen. Printing is
// unchanged — the same bytes either way.
func (p *Printer) AnatomyLines(e *pdr.Error) []string {
	lines := []string{fmt.Sprintf("%s %s  %s", p.glyph(Fail), e.Code, e.Message)}
	add := func(s string) { lines = append(lines, strings.Split(s, "\n")...) }
	row := func(label, value string) {
		if value != "" {
			add(fmt.Sprintf("  %-10s%s", label, value))
		}
	}
	row("cause", e.Cause)
	row("evidence", e.Evidence)
	row("next", e.Next)
	for _, d := range e.Details {
		code := ""
		if d.Code != "" && d.Code != e.Code {
			code = d.Code + " · "
		}
		add(fmt.Sprintf("  %-10s%s%s: %s", "detail", code, d.Path, d.Hint))
	}
	return lines
}

// Explain renders one registry entry for `podaro explain` (API §5, plan
// S9): the code and its title, then the same label column the error
// anatomy uses — so an explanation reads like the error it explains, and
// an operator moving between them is never re-learning a layout. The
// column is two wider than the anatomy's, because `background` is ten
// characters and a label that touches its value is not a column.
func (p *Printer) Explain(e pdr.Entry) {
	fmt.Fprintf(p.w, "%s  %s\n", e.Code, e.Title)
	row := func(label, value string) {
		if value != "" {
			fmt.Fprintf(p.w, "  %-12s%s\n", label, value)
		}
	}
	row("cause", e.Cause)
	row("background", e.Background)
	row("next", e.Next)
}
