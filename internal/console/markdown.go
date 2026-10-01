// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"html"
	"html/template"
	"strings"
)

// Playbook narrative is markdown (UX §6). It is rendered here rather
// than by a markdown library, for two reasons: the subset the playbook
// schema's prose uses is small — paragraphs, bold, italic, inline code,
// links, and bullet or numbered lists — and, more importantly, a
// template author's narrative must never be able to put raw HTML into
// the console. Everything is escaped first and only the tags below are
// emitted afterwards, so there is no path by which authored text becomes
// markup the author chose. A general library would have to be configured
// not to do that; this cannot do it in the first place.
//
// Anything the subset does not recognise stays as the text it is. That
// is the honest failure: an author sees their notation rendered
// literally and fixes it, rather than seeing it silently dropped.

// renderMarkdown turns a narrative into safe HTML.
func renderMarkdown(src string) template.HTML {
	var out strings.Builder
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	para := []string{}
	list := []string{}
	listTag := ""

	flushPara := func() {
		if len(para) == 0 {
			return
		}
		out.WriteString("<p>" + inline(strings.Join(para, " ")) + "</p>\n")
		para = nil
	}
	flushList := func() {
		if len(list) == 0 {
			return
		}
		out.WriteString("<" + listTag + ">\n")
		for _, item := range list {
			out.WriteString("<li>" + inline(item) + "</li>\n")
		}
		out.WriteString("</" + listTag + ">\n")
		list, listTag = nil, ""
	}

	for _, raw := range lines {
		line := strings.TrimRight(raw, " \t")
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			flushPara()
			flushList()
		case strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* "):
			flushPara()
			if listTag == "ol" {
				flushList()
			}
			listTag = "ul"
			list = append(list, strings.TrimSpace(trimmed[2:]))
		case numbered(trimmed) != "":
			flushPara()
			if listTag == "ul" {
				flushList()
			}
			listTag = "ol"
			list = append(list, numbered(trimmed))
		default:
			flushList()
			para = append(para, trimmed)
		}
	}
	flushPara()
	flushList()
	return template.HTML(out.String()) //nolint:gosec // every span is escaped in inline()
}

// numbered returns the text of a numbered-list item, or "" if the line
// is not one. Only "1. " through "99. " count, so a sentence beginning
// with a year is prose, not a list.
func numbered(line string) string {
	i := 0
	for i < len(line) && i < 2 && line[i] >= '0' && line[i] <= '9' {
		i++
	}
	if i == 0 || !strings.HasPrefix(line[i:], ". ") {
		return ""
	}
	return strings.TrimSpace(line[i+2:])
}

// inline renders the span-level subset. The text is escaped first, so
// what follows only ever adds tags around text that can no longer be
// markup itself.
func inline(text string) string {
	s := html.EscapeString(text)
	s = spans(s, "`", "<code>", "</code>")
	s = spans(s, "**", "<strong>", "</strong>")
	s = emphasis(s, '*') // after **bold**, so only unpaired stars remain
	s = emphasis(s, '_')
	return links(s)
}

// spans wraps paired delimiters. An unpaired delimiter is left as the
// character it is — an author's stray backtick reads as a backtick, not
// as the start of a code span that swallows the rest of the sentence.
func spans(s, delim, open, close string) string {
	parts := strings.Split(s, delim)
	if len(parts) < 3 {
		return s
	}
	var b strings.Builder
	for i, p := range parts {
		switch {
		case i == 0:
			b.WriteString(p)
		case i%2 == 1 && i+1 < len(parts):
			b.WriteString(open + p + close)
		default:
			if i%2 == 1 {
				b.WriteString(delim + p) // unpaired: the delimiter is text
			} else {
				b.WriteString(p)
			}
		}
	}
	return b.String()
}

// links renders [text](url) for http, https and in-console paths only.
// Any other scheme — javascript:, data: — is left as the literal text it
// was written as, so a narrative cannot become a script or a payload.
func links(s string) string {
	var b strings.Builder
	for {
		open := strings.Index(s, "[")
		if open < 0 {
			break
		}
		mid := strings.Index(s[open:], "](")
		if mid < 0 {
			break
		}
		mid += open
		end := strings.Index(s[mid:], ")")
		if end < 0 {
			break
		}
		end += mid
		text, url := s[open+1:mid], s[mid+2:end]
		b.WriteString(s[:open])
		if safeURL(url) {
			b.WriteString(`<a href="` + url + `">` + text + `</a>`)
		} else {
			b.WriteString(s[open : end+1]) // as written, and inert
		}
		s = s[end+1:]
	}
	b.WriteString(s)
	return b.String()
}

func safeURL(u string) bool {
	if u == "" || strings.ContainsAny(u, " \t\"'<>") {
		return false
	}
	if strings.HasPrefix(u, "/") || strings.HasPrefix(u, "#") {
		return true
	}
	// &#58; is what EscapeString leaves of a colon's neighbours; the
	// scheme test is on the escaped text, so it must match that.
	return strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://")
}

// emphasis renders *emphasis* and _emphasis_ only where the delimiters
// stand at word boundaries. Inside a word the character is part of the
// word — playbook prose is full of snake_case identifiers and of
// multiplication — and turning half of one into emphasis would be both
// wrong and unreadable.
func emphasis(s string, delim byte) string {
	var b strings.Builder
	i := 0
	for {
		open := indexBoundary(s, i, delim, true)
		if open < 0 {
			break
		}
		close := indexBoundary(s, open+1, delim, false)
		if close < 0 {
			break
		}
		// An empty span is not emphasis, and a run of the delimiter is
		// arithmetic or a leftover of **bold**, not a span: `2 ** 8`
		// stays what it was written as.
		if close <= open+1 || s[open+1] == delim || s[close-1] == delim {
			b.WriteString(s[i : open+1])
			i = open + 1
			continue
		}
		b.WriteString(s[i:open])
		b.WriteString("<em>" + s[open+1:close] + "</em>")
		i = close + 1
	}
	b.WriteString(s[i:])
	return b.String()
}

// indexBoundary finds the next underscore that can open (or close) an
// emphasis span: an opener has no word character before it, a closer has
// none after it.
func indexBoundary(s string, from int, delim byte, opening bool) int {
	for i := from; i < len(s); i++ {
		if s[i] != delim {
			continue
		}
		if opening {
			if (i == 0 || !isWord(s[i-1])) && i+1 < len(s) && !isSpace(s[i+1]) {
				return i
			}
			continue
		}
		if (i+1 == len(s) || !isWord(s[i+1])) && i > 0 && !isSpace(s[i-1]) {
			return i
		}
	}
	return -1
}

func isWord(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' }
