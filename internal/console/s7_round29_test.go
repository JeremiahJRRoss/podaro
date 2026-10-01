// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/state"
)

// UX §4: "every status pairs colour + glyph + word." The result line
// handed `glyph` its raw `.Status`, and that helper knows the tokens —
// `attest`, `warn` — not the result values `attested` and `error`. Both
// fell to its default, so the line rendered the pending `○` beside the
// words "self-verified" and "error": a pairing whose glyph contradicts
// its word, which is worse than no glyph. `syncSpine` copies the
// rendered glyph into the collapsed spine, so the same mistake reached
// both renderings from one place.
func TestAResultLineGlyphAgreesWithItsWord(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		status string
		word   string
		char   string
	}{
		{"pass", "passed", "●"},
		{"fail", "failed", "✗"},
		{"attested", "self-verified", "◇"},
		{"error", "error", "!"},
	} {
		line := NewResultLine("pii-lab", "pii-redaction", "mask-them",
			&state.CheckpointResult{ID: "mask-them", Status: c.status}, nil)
		if line.Word != c.word {
			t.Fatalf("%s: the line says %q, so this case is not what it claims", c.status, line.Word)
		}
		out, err := r.Fragment(FragmentResult, line)
		if err != nil {
			t.Fatal(err)
		}
		html := string(out)
		if !strings.Contains(html, `<span class="glyph" aria-hidden="true">`+c.char+`</span>`) {
			t.Errorf("%s (%s) is not paired with %s:\n%s", c.status, c.word, c.char, html)
		}
		if c.char != "○" && strings.Contains(html, `>○</span> <span class="word mono">`+c.word) {
			t.Errorf("%s renders the pending glyph beside %q:\n%s", c.status, c.word, html)
		}
	}
}
