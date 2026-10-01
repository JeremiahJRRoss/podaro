// SPDX-License-Identifier: AGPL-3.0-only

// Package lab implements `podaro lab validate` and `podaro lab plan` (plan
// step S3, roadmap P0's exit gate): schema validation against the frozen
// schemas of each document's apiVersion (v1alpha2, the current contract;
// v1alpha1, frozen history still read), the referential and structural rules of Spec 0001 §9,
// the composition rules of spec 0003 §11, and a deterministic,
// human-reviewable plan (API §6). Every finding carries file:line (UX
// Guide principle 7: the manifest is an interface).
package lab

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// Document is one YAML manifest, kept as a node tree (for file:line
// lookups) and as a JSON-compatible value (for schema validation).
type Document struct {
	// Path is the display path used in every file:line location.
	Path string
	// Root is the parsed node tree (the document's content node).
	Root *yaml.Node
	// Value is the JSON-compatible decoding: string keys only, no
	// timestamps, integers as int, floats as float64.
	Value any
	// Raw is the source text, for line-oriented scans (secret refs).
	Raw []byte
}

var (
	yamlLine = regexp.MustCompile(`line (\d+):`)
	// intLike covers every plain-scalar spelling yaml.v3 resolves as an
	// integer: decimal, 0b binary, 0 / 0o octal, 0x hexadecimal, with
	// underscores.
	intLike = regexp.MustCompile(`^[-+]?(0b[01_]+|0o?[0-7_]+|0x[0-9a-fA-F_]+|[0-9][0-9_]*)$`)
)

// DocumentError is PDR-E100 for one manifest. The location (file, or
// file:line) travels beside the message rather than inside it, so a path
// with whitespace survives into the finding untouched.
type DocumentError struct {
	Loc string
	Err *pdr.Error
}

func (e *DocumentError) Error() string { return e.Err.Error() }

// Unwrap exposes the *pdr.Error for errors.As.
func (e *DocumentError) Unwrap() error { return e.Err }

func docErr(loc string, e *pdr.Error) error { return &DocumentError{Loc: loc, Err: e} }

// LoadDocument reads name from fsys and parses it; display is the path
// reported in locations.
func LoadDocument(fsys fs.FS, name, display string) (*Document, error) {
	raw, err := fs.ReadFile(fsys, name)
	if err != nil {
		e := pdr.New(pdr.CodeLabUnreadable, "%s cannot be read", display)
		e.Cause = err.Error()
		e.Next = "check the path: a template directory holds lab.yaml and playbooks/*.yaml (spec 0003 §1)"
		return nil, docErr(display, e)
	}
	return ParseDocument(raw, display)
}

// ParseDocument parses one YAML document. A second document, an empty
// file, or a syntax error is PDR-E100 with file:line where the parser
// provides one.
func ParseDocument(raw []byte, display string) (*Document, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var root yaml.Node
	if err := dec.Decode(&root); err != nil {
		if errors.Is(err, io.EOF) {
			e := pdr.New(pdr.CodeLabUnreadable, "%s is empty", display)
			e.Next = "a manifest starts with apiVersion: lab.podaro.dev/v1alpha2 and a kind"
			return nil, docErr(display, e)
		}
		loc := display
		if m := yamlLine.FindStringSubmatch(err.Error()); m != nil {
			loc = display + ":" + m[1]
		}
		e := pdr.New(pdr.CodeLabUnreadable, "%s is not valid YAML", loc)
		e.Cause = strings.TrimPrefix(err.Error(), "yaml: ")
		e.Next = "fix the YAML syntax at the printed file:line"
		return nil, docErr(loc, e)
	}
	var extra yaml.Node
	switch err := dec.Decode(&extra); {
	case err == nil:
		loc := display
		if extra.Line > 0 {
			loc = fmt.Sprintf("%s:%d", display, extra.Line)
		}
		e := pdr.New(pdr.CodeLabUnreadable, "%s holds more than one YAML document", loc)
		e.Cause = "content after a '---' separator would be silently ignored"
		e.Next = "one manifest per file: split the documents or remove the separator"
		return nil, docErr(loc, e)
	case !errors.Is(err, io.EOF):
		// Malformed content after a separator: the parser names the line;
		// the finding carries it, and the syntax cause with it.
		loc := display
		if m := yamlLine.FindStringSubmatch(err.Error()); m != nil {
			loc = display + ":" + m[1]
		}
		e := pdr.New(pdr.CodeLabUnreadable, "%s is not valid YAML", loc)
		e.Cause = strings.TrimPrefix(err.Error(), "yaml: ")
		e.Next = "fix the YAML syntax at the printed file:line (and keep one manifest per file)"
		return nil, docErr(loc, e)
	}
	content := &root
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		content = root.Content[0]
	}
	keepTimestampsAsText(content)
	value, err := toJSONValue(content, map[*yaml.Node]bool{})
	if err != nil {
		e := pdr.New(pdr.CodeLabUnreadable, "%s: %v", display, err)
		e.Next = "use plain YAML scalars, sequences, and string-keyed mappings"
		loc := display
		if m := yamlLine.FindStringSubmatch(err.Error()); m != nil {
			loc = display + ":" + m[1] // the conversion names the line; the finding carries it
		}
		return nil, docErr(loc, e)
	}
	return &Document{Path: display, Root: content, Value: value, Raw: raw}, nil
}

// keepTimestampsAsText retags every timestamp-looking plain scalar
// (`date: 2026-09-03`) as a string, so both the JSON-compatible value and
// the typed views decoded from the tree carry the author's text: manifests
// carry no dates, and generator params pass through unchanged (a
// time.Time would re-emit as an RFC 3339 instant).
func keepTimestampsAsText(n *yaml.Node) {
	if n == nil {
		return
	}
	if n.Kind == yaml.ScalarNode && n.Tag == "!!timestamp" {
		n.Tag = "!!str"
	}
	for _, c := range n.Content {
		keepTimestampsAsText(c)
	}
}

// toJSONValue converts a node tree into the value shape JSON Schema
// validation expects: mappings become map[string]any, sequences []any,
// scalars their YAML-resolved Go values — except that timestamps stay the
// literal text (manifests carry no dates). Mapping keys must be strings
// (a numeric or boolean key would decode to a map JSON cannot carry),
// numbers must be finite (.nan/.inf have no JSON form), and an alias that
// leads back to an ancestor is refused rather than followed forever.
func toJSONValue(n *yaml.Node, visiting map[*yaml.Node]bool) (any, error) {
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil, nil
		}
		return toJSONValue(n.Content[0], visiting)
	case yaml.AliasNode:
		if n.Alias == nil {
			return nil, fmt.Errorf("line %d: unresolved alias *%s", n.Line, n.Value)
		}
		if visiting[n.Alias] {
			return nil, fmt.Errorf("line %d: alias *%s refers to a node that contains it", n.Line, n.Value)
		}
		visiting[n.Alias] = true
		defer delete(visiting, n.Alias)
		return toJSONValue(n.Alias, visiting)
	case yaml.MappingNode:
		visiting[n] = true
		defer delete(visiting, n)
		m := make(map[string]any, len(n.Content)/2)
		var merges []*yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind == yaml.AliasNode && k.Alias != nil {
				k = k.Alias
			}
			if k.Kind == yaml.ScalarNode && k.Tag == "!!merge" {
				merges = append(merges, n.Content[i+1]) // `<<: *base` — applied after explicit keys
				continue
			}
			if k.Kind != yaml.ScalarNode || (k.Tag != "!!str" && k.Tag != "") {
				return nil, fmt.Errorf("line %d: mapping keys must be strings (quote %q if it is meant as text)", k.Line, k.Value)
			}
			v, err := toJSONValue(n.Content[i+1], visiting)
			if err != nil {
				return nil, err
			}
			m[k.Value] = v
		}
		// YAML merge keys (`<<`): explicit keys win; among merged mappings
		// the earlier wins — the same result yaml.v3 (and safe_load) gives.
		for _, mn := range merges {
			if err := mergeInto(m, mn, visiting); err != nil {
				return nil, err
			}
		}
		return m, nil
	case yaml.SequenceNode:
		visiting[n] = true
		defer delete(visiting, n)
		s := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := toJSONValue(c, visiting)
			if err != nil {
				return nil, err
			}
			s = append(s, v)
		}
		return s, nil
	case yaml.ScalarNode:
		if n.Tag == "!!timestamp" {
			return n.Value, nil
		}
		var v any
		if err := n.Decode(&v); err != nil {
			return nil, fmt.Errorf("line %d: %v", n.Line, err)
		}
		if (n.Style == 0 && intLike.MatchString(n.Value)) || n.Tag == "!!int" {
			// Written (or explicitly tagged) as an integer: it must decode
			// as one. Beyond uint64 the decoder would hand back a float or
			// a string, silently changing the author's type.
			switch v.(type) {
			case int, int64, uint64:
			default:
				return nil, fmt.Errorf("line %d: %s is beyond the exact integer range (quote it if it is meant as text)", n.Line, n.Value)
			}
		}
		switch t := v.(type) {
		case int64:
			return int(t), nil
		case uint64:
			if t > math.MaxInt64 {
				return t, nil // beyond int64: keep the exact value (JSON carries it; wrapping would not)
			}
			return int(t), nil
		case float32:
			v = float64(t)
		}
		if f, ok := v.(float64); ok && (math.IsNaN(f) || math.IsInf(f, 0)) {
			return nil, fmt.Errorf("line %d: %s is not a finite number (JSON cannot carry it; quote it if it is meant as text)", n.Line, n.Value)
		}
		return v, nil
	}
	return nil, nil
}

// mergeInto applies one `<<` value — a mapping, or a sequence of mappings
// — into m without overriding keys already present.
func mergeInto(m map[string]any, mn *yaml.Node, visiting map[*yaml.Node]bool) error {
	target := mn
	for hops := 0; target.Kind == yaml.AliasNode && target.Alias != nil && hops < 8; hops++ {
		target = target.Alias
	}
	switch target.Kind {
	case yaml.SequenceNode:
		// The same cycle guard as toJSONValue: `<<: &items [*items]` must
		// be refused, not followed forever.
		if visiting[target] {
			return fmt.Errorf("line %d: merge key (<<) refers to a node that contains it", mn.Line)
		}
		visiting[target] = true
		defer delete(visiting, target)
		for _, item := range target.Content {
			if err := mergeInto(m, item, visiting); err != nil {
				return err
			}
		}
		return nil
	case yaml.MappingNode:
		v, err := toJSONValue(mn, visiting)
		if err != nil {
			return err
		}
		for k, val := range v.(map[string]any) {
			if _, taken := m[k]; !taken {
				m[k] = val
			}
		}
		return nil
	}
	return fmt.Errorf("line %d: a merge key (<<) takes a mapping or a list of mappings", mn.Line)
}

// Node walks a JSON-pointer token path and returns the node it lands on
// (the key node when the last token names a mapping key), or nil.
// mergeKey is YAML's merge key. A mapping inherits another's keys with
// `<<: *anchor` (or a sequence of them), and the decoder hands those
// keys to the struct exactly as if they had been written in place — so a
// lookup that reads only the keys written in place answers that a
// present field is absent. It did, and a file that inherited `content`
// and declared `source` passed the check that exists to refuse two
// contents.
const mergeKey = "<<"

// mappingEntry finds one key in a mapping and returns the key node —
// where the author wrote it, in the anchor when that is where it is —
// and its value. Keys written in place win over merged ones, and among
// merged mappings the earlier wins, which is what YAML's merge says.
// depth bounds the recursion, as the alias walk elsewhere does.
func mappingEntry(n *yaml.Node, tok string, depth int) (*yaml.Node, *yaml.Node) {
	for j := 0; j+1 < len(n.Content); j += 2 {
		if n.Content[j].Value == tok {
			return n.Content[j], n.Content[j+1]
		}
	}
	if depth <= 0 {
		return nil, nil
	}
	for j := 0; j+1 < len(n.Content); j += 2 {
		if n.Content[j].Value != mergeKey {
			continue
		}
		for _, m := range mergedMappings(n.Content[j+1], depth) {
			if key, value := mappingEntry(m, tok, depth-1); key != nil {
				return key, value
			}
		}
	}
	return nil, nil
}

// mergedMappings resolves what a `<<` value names: one mapping, an alias
// to one, or a sequence of either.
func mergedMappings(v *yaml.Node, depth int) []*yaml.Node {
	for hops := 0; v != nil && v.Kind == yaml.AliasNode && v.Alias != nil && hops < 8; hops++ {
		v = v.Alias
	}
	switch {
	case v == nil || depth <= 0:
		return nil
	case v.Kind == yaml.MappingNode:
		return []*yaml.Node{v}
	case v.Kind == yaml.SequenceNode:
		var out []*yaml.Node
		for _, item := range v.Content {
			out = append(out, mergedMappings(item, depth-1)...)
		}
		return out
	}
	return nil
}

func (d *Document) Node(ptr []string) *yaml.Node {
	n := d.Root
	if n == nil {
		return nil
	}
	if len(ptr) == 0 {
		return n
	}
	for i, tok := range ptr {
		for hops := 0; n.Kind == yaml.AliasNode && n.Alias != nil && hops < 8; hops++ {
			n = n.Alias
		}
		switch n.Kind {
		case yaml.MappingNode:
			key, next := mappingEntry(n, tok, 8)
			if key == nil {
				return n
			}
			if i == len(ptr)-1 {
				return key // the key: where the author wrote it
			}
			n = next
		case yaml.SequenceNode:
			idx, err := strconv.Atoi(tok)
			if err != nil || idx < 0 || idx >= len(n.Content) {
				return n
			}
			n = n.Content[idx]
		default:
			return n
		}
	}
	return n
}

// Line returns the 1-based line for a pointer path, falling back to the
// nearest ancestor; 0 when the document has no node tree.
func (d *Document) Line(ptr []string) int {
	if n := d.Node(ptr); n != nil {
		return n.Line
	}
	return 0
}

// Has reports whether the document actually writes the key a pointer
// path names. `Node` falls back to the nearest ancestor so a finding can
// always be given a location, which makes it useless for presence on its
// own: the exact hit is the key node, whose value is the last token.
func (d *Document) Has(ptr ...string) bool {
	if len(ptr) == 0 {
		return d.Root != nil
	}
	n := d.Node(ptr)
	return n != nil && n.Kind == yaml.ScalarNode && n.Value == ptr[len(ptr)-1]
}

// Loc renders `file:line` for a pointer path.
func (d *Document) Loc(ptr ...string) string {
	if line := d.Line(ptr); line > 0 {
		return fmt.Sprintf("%s:%d", d.Path, line)
	}
	return d.Path
}

// pointerTokens splits a JSON pointer ("/a/b~1c") into unescaped tokens.
func pointerTokens(p string) []string {
	if p == "" || p == "/" {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i, s := range parts {
		s = strings.ReplaceAll(s, "~1", "/")
		parts[i] = strings.ReplaceAll(s, "~0", "~")
	}
	return parts
}

// Decode fills v from the document's node tree (typed views after the
// schema has accepted the shape).
func (d *Document) Decode(v any) error {
	return d.Root.Decode(v)
}
