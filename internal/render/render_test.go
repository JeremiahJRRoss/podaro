// SPDX-License-Identifier: AGPL-3.0-only

package render

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

func plain() (*bytes.Buffer, *Printer) {
	var buf bytes.Buffer
	return &buf, New(&buf, false, true)
}

func TestCheckColumns(t *testing.T) {
	buf, p := plain()
	p.Check(Pass, "podman 4.9.4", 22, "rootless · cgroups v2")
	p.Indent("→ run once:", 22, "sudo loginctl enable-linger jross")
	want := "✓ podman 4.9.4          rootless · cgroups v2\n" +
		"  → run once:           sudo loginctl enable-linger jross\n"
	if got := buf.String(); got != want {
		t.Fatalf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestCheckWithoutDetailHasNoTrailingSpace(t *testing.T) {
	buf, p := plain()
	p.Check(Pass, "service stopped and removed", 19, "")
	if got := buf.String(); got != "✓ service stopped and removed\n" {
		t.Fatalf("got %q", got)
	}
}

// The anatomy must match User Manual §14's block byte for byte — the docs
// are the golden files.
func TestAnatomyMatchesUserManual(t *testing.T) {
	raw, err := os.ReadFile("../../public-docs/USERMANUAL.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	start := strings.Index(doc, "```\n✗ PDR-E404")
	if start < 0 {
		t.Fatal("USERMANUAL.md §14 anatomy block not found")
	}
	rest := doc[start+len("```\n"):]
	want := rest[:strings.Index(rest, "```")]

	// The values are the ones the engine really produces for this failure
	// (internal/seed: the target cannot be reached, the instance named,
	// the evidence pointer an API path) — the manual's example was an
	// error code this engine uses for something else, fixed in plan S10's
	// drift audit.
	buf, p := plain()
	p.Anatomy(&pdr.Error{
		Code:     "PDR-E404",
		Message:  "seed query-load cannot reach prometheus:9090",
		Cause:    "dial tcp: connect: connection refused",
		Evidence: "/api/v1alpha1/instances/intro/evidence/ev_01J9…",
		Next:     "podaro status intro · the service must be running and the port a declared endpoint",
	})
	if got := buf.String(); got != want {
		t.Fatalf("anatomy diverges from Manual §14\n--- want ---\n%s--- got ---\n%s", want, got)
	}
}

func TestASCIIFallback(t *testing.T) {
	var buf bytes.Buffer
	p := New(&buf, false, false)
	p.Check(Pass, "podman", 10, "fine")
	p.Check(Fail, "lingering", 10, "off")
	out := buf.String()
	if !strings.HasPrefix(out, "ok podman") || !strings.Contains(out, "x lingering") {
		t.Fatalf("ascii fallback wrong: %q", out)
	}
}

func TestColorOnlyWhenEnabled(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, true, true).Check(Pass, "x", 4, "y")
	if !strings.Contains(buf.String(), "\x1b[32m") {
		t.Fatalf("expected ANSI color: %q", buf.String())
	}
	buf.Reset()
	New(&buf, false, true).Check(Pass, "x", 4, "y")
	if strings.Contains(buf.String(), "\x1b[") {
		t.Fatalf("plain mode must not emit ANSI: %q", buf.String())
	}
}

// Detect on a non-file writer (pipes in tests) must disable color — the
// UX §7 piped rule.
func TestDetectPipedIsPlain(t *testing.T) {
	var buf bytes.Buffer
	p := Detect(&buf)
	p.Check(Pass, "x", 4, "y")
	if strings.Contains(buf.String(), "\x1b[") {
		t.Fatalf("piped output must be plain: %q", buf.String())
	}
}

// The ladder line layout is UX §5's: name column, glyph + stage, context.
func TestRowMatchesLadderLayout(t *testing.T) {
	_, p := plain()
	if got := p.Row(Complete, "prometheus", 15, "ready", "healthy in 38s"); got != "prometheus     ● ready          healthy in 38s" {
		t.Fatalf("row: %q", got)
	}
	if got := p.Row(None, "checkpoints", 15, "baseline 8/8 · objectives 1/4", ""); got != "checkpoints    baseline 8/8 · objectives 1/4" {
		t.Fatalf("tally row: %q", got)
	}
}

// A field can hold several physical lines — an init failure's cause is the
// helper's combined output — and AnatomyLines is used by a caller that
// moves the cursor up by the number of lines it returned. One element
// holding three rows made that caller undercount and leave the tail of the
// last frame on screen.
func TestAnatomyLinesCountsPhysicalLines(t *testing.T) {
	_, p := plain()
	lines := p.AnatomyLines(&pdr.Error{
		Code:    "PDR-E204",
		Message: "init of grafana failed",
		Cause:   "curl: (22) The requested URL returned error: 401\nremote: authentication required\nexit 22",
		Next:    "podaro logs intro grafana",
	})
	for i, l := range lines {
		if strings.Contains(l, "\n") {
			t.Fatalf("line %d holds a newline, so a redrawing caller cannot count it: %q", i, l)
		}
	}
	// The code line, three rows of cause, and next.
	if len(lines) != 5 {
		t.Fatalf("want five physical lines, got %d: %q", len(lines), lines)
	}
	// The printed bytes are unchanged by the split.
	buf, p2 := plain()
	p2.Anatomy(&pdr.Error{
		Code:    "PDR-E204",
		Message: "init of grafana failed",
		Cause:   "curl: (22) The requested URL returned error: 401\nremote: authentication required\nexit 22",
		Next:    "podaro logs intro grafana",
	})
	if got, want := buf.String(), strings.Join(lines, "\n")+"\n"; got != want {
		t.Fatalf("Anatomy and AnatomyLines disagree:\n--- printed ---\n%s--- joined ---\n%s", got, want)
	}
}
