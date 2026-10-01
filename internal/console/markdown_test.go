// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"strings"
	"testing"
)

// The narrative is markdown (UX §6), rendered by a subset that escapes
// first and only then adds the tags it recognises — so an author's text
// can never become markup the author chose.

func TestMarkdownRendersTheSubsetPlaybooksUse(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"plain words", "<p>plain words</p>"},
		{"**Prometheus** scraping itself", "<p><strong>Prometheus</strong> scraping itself</p>"},
		{"the counter `up` moved", "<p>the counter <code>up</code> moved</p>"},
		{"that line is _yours_", "<p>that line is <em>yours</em></p>"},
		{"that line is *yours*", "<p>that line is <em>yours</em></p>"},
		{"**bold** and *italic* together", "<p><strong>bold</strong> and <em>italic</em> together</p>"},
		{"a [link](https://example.com/x)", `<p>a <a href="https://example.com/x">link</a></p>`},
		{"an [in-console](/instances/x) link", `<p>an <a href="/instances/x">in-console</a> link</p>`},
		{"one\ntwo", "<p>one two</p>"},
		{"one\n\ntwo", "<p>one</p>\n<p>two</p>"},
		{"- first\n- second", "<ul>\n<li>first</li>\n<li>second</li>\n</ul>"},
		{"1. first\n2. second", "<ol>\n<li>first</li>\n<li>second</li>\n</ol>"},
	} {
		got := string(renderMarkdown(c.in))
		if !strings.Contains(got, c.want) {
			t.Errorf("renderMarkdown(%q) = %q, want it to contain %q", c.in, got, c.want)
		}
	}
}

// Authored narrative is text. It never becomes markup, a script, or a
// payload — whatever it is written as.
func TestMarkdownNeverLetsAuthoredTextBecomeMarkup(t *testing.T) {
	for _, in := range []string{
		`<script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
		`**<b>bold</b>**`,
		"`<i>code</i>`",
		`[click](javascript:alert(1))`,
		`[click](data:text/html,<script>alert(1)</script>)`,
		`[click](vbscript:x)`,
		`<a href="https://evil.example">x</a>`,
	} {
		got := string(renderMarkdown(in))
		// The property is that no *active* markup was emitted, not that
		// the characters are gone: an escaped `&lt;img … onerror=…&gt;`
		// is the text an author wrote, rendered as text, and that is
		// exactly right. So the check is on the tags that survive.
		for _, tag := range tagsIn(got) {
			if !allowedTag[tag] {
				t.Errorf("renderMarkdown(%q) emitted the tag %q: %s", in, tag, got)
			}
		}
		for _, href := range hrefsIn(got) {
			if !safeURL(href) {
				t.Errorf("renderMarkdown(%q) emitted an unsafe href %q: %s", in, href, got)
			}
		}
	}
	// The one anchor it does emit is an author's own safe link.
	if got := string(renderMarkdown(`[ok](https://example.com)`)); !strings.Contains(got, `<a href="https://example.com">ok</a>`) {
		t.Errorf("a safe link did not render: %s", got)
	}
}

// An unpaired delimiter is the character it is, not the start of a span
// that swallows the rest of the sentence.
func TestMarkdownLeavesUnpairedDelimitersAlone(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"a ` backtick alone", "a ` backtick alone"},
		{"2 ** 8 is math", "2 ** 8 is math"},
		{"a * b * c is arithmetic", "a * b * c"},
		{"snake_case_name", "snake_case_name"},
	} {
		got := string(renderMarkdown(c.in))
		if !strings.Contains(got, c.want) {
			t.Errorf("renderMarkdown(%q) = %q, want it to contain %q", c.in, got, c.want)
		}
		if strings.Contains(got, "<code>") && !strings.Contains(c.in, "``") {
			t.Errorf("renderMarkdown(%q) opened a code span on an unpaired delimiter: %s", c.in, got)
		}
	}
}

// A year at the start of a sentence is prose, not a numbered list.
func TestMarkdownDoesNotMistakeProseForAList(t *testing.T) {
	got := string(renderMarkdown("2026. A year, not a list item."))
	if strings.Contains(got, "<ol>") {
		t.Errorf("a four-digit prefix became a list: %s", got)
	}
}

// allowedTag is the whole set the renderer may emit.
var allowedTag = map[string]bool{
	"p": true, "/p": true, "strong": true, "/strong": true, "em": true, "/em": true,
	"code": true, "/code": true, "ul": true, "/ul": true, "ol": true, "/ol": true,
	"li": true, "/li": true, "a": true, "/a": true,
}

// tagsIn returns the tag names of every `<…>` in the output. Escaped
// text carries no `<`, so anything found here is markup the renderer
// chose to emit.
func tagsIn(html string) []string {
	var out []string
	for i := 0; i < len(html); i++ {
		if html[i] != '<' {
			continue
		}
		j := strings.IndexByte(html[i:], '>')
		if j < 0 {
			break
		}
		tag := html[i+1 : i+j]
		if sp := strings.IndexAny(tag, " \t"); sp >= 0 {
			tag = tag[:sp]
		}
		out = append(out, tag)
		i += j
	}
	return out
}

func hrefsIn(html string) []string {
	var out []string
	rest := html
	for {
		i := strings.Index(rest, `href="`)
		if i < 0 {
			return out
		}
		rest = rest[i+6:]
		j := strings.IndexByte(rest, '"')
		if j < 0 {
			return out
		}
		out = append(out, rest[:j])
		rest = rest[j:]
	}
}
