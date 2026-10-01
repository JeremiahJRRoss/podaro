// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/lab"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
)

// `podaro lab init --from <template> <dir>` is the authoring loop's first
// command (User Manual §11 and §15, roadmap §9's MVP CLI row, Journey §2
// stage 6): the scaffold that stands between "I want to try my stack" and
// a template that validates. It copies an installed template into a new
// directory and renames it after that directory — the one edit every copy
// needs — and writes the current contract's version, v1alpha2, over a
// source that still declares frozen v1alpha1 (liftAPIVersion). Everything
// else is the author's to change.
//
// The source is the installed catalog (INSTALL §3: `catalog/`, extracted
// by `system install`), or the starter catalog inside the binary when the
// engine has not been installed on this machine yet: `lab validate` and
// `lab plan` work from the binary alone (plan S3), and a scaffolder that
// needed a running service would be a worse front door than they are.
//
// Nothing here reaches the engine: authoring is a filesystem act, and
// this command is the twin of no endpoint — remote authoring arrives with
// `publish` (API §6).

// dnsLabel is the template-name rule: schemas/checkpoint.v1alpha2.json's
// `dnsLabel`, which `metadata.name` $refs (spec 0003 §2). A scaffold is
// named after its directory, so the directory name has to be one.
var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// initResult is the --json twin: what was written, from where, as what.
type initResult struct {
	Path     string   `json:"path"`
	Name     string   `json:"name"`
	From     string   `json:"from"`
	Source   string   `json:"source"` // "catalog" | "binary"
	Files    []string `json:"files"`
	Playbook string   `json:"playbook,omitempty"`
}

func newLabInit() *cobra.Command {
	var from string
	cmd := &cobra.Command{
		Use:   "init <dir>",
		Short: "scaffold a template directory from an installed template",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if from == "" {
				pe := pdr.New(pdr.CodeLabInitTarget, "lab init needs a template to scaffold from")
				pe.Cause = "installed templates: " + strings.Join(installedTemplates(), ", ")
				pe.Next = "podaro lab init --from <template> " + shellPath(args[0])
				return jsonOrErr(pe, exitFor(pe.Code))
			}
			res, err := scaffold(from, args[0])
			if err != nil {
				// Nothing was written when this refuses, and the exit
				// code is the one the code carries — the same under
				// --json as without it.
				code := 1
				if pe, ok := err.(*pdr.Error); ok {
					code = exitFor(pe.Code)
				}
				return jsonOrErr(err, code)
			}
			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{"init": res})
			}
			p := render.Detect(os.Stdout)
			where := "from the installed catalog"
			if res.Source == "binary" {
				where = "from the starter catalog in the binary"
			}
			p.Check(render.Pass, "scaffolded", 22, fmt.Sprintf("%s · %d files %s", res.Path, len(res.Files), where))
			p.Check(render.Pass, "metadata.name", 22, res.Name+"  (was "+res.From+")")
			if res.Playbook != "" {
				p.Check(render.Pass, "playbook", 22, res.Playbook)
			}
			p.Blank()
			p.NextAction("podaro lab validate " + shellPath(res.Path))
			p.Indent("→ then the inner loop:", 24, "podaro up "+shellPath(res.Path)+" --name dev")
			return nil
		},
	}
	cmd.Flags().StringVar(&from, "from", "", "the installed template to scaffold from")
	return cmd
}

// scaffold copies one template directory to a new one and renames it.
// Every refusal happens before the first file is written: a half-written
// scaffold is worse than none, and a tool meant to save work should not
// leave a directory to tidy up.
func scaffold(from, dir string) (*initResult, error) {
	// One cleaning, here, so every path below is derived from the same
	// form. A target written with a trailing separator — `./my-lab/` — is
	// the same directory, but filepath.Dir of it is the target itself
	// rather than its parent: the staging directory would land *inside*
	// the scaffold it is meant to become, the rename could never happen,
	// and the empty target left behind passes the pre-flight, so every
	// re-run failed the same way.
	dir = filepath.Clean(dir)
	name := filepath.Base(dir)
	if !dnsLabel.MatchString(name) {
		pe := pdr.New(pdr.CodeLabInitTarget, "%q cannot be a template name", name)
		pe.Cause = "a scaffold is named after its directory, and metadata.name is a DNS label: lowercase letters, digits and hyphens, starting and ending alphanumeric (spec 0003 §2)"
		pe.Next = "choose a directory name like ./my-lab"
		return nil, pe
	}
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		pe := pdr.New(pdr.CodeLabInitTarget, "%s already holds %d entries", dir, len(entries))
		pe.Cause = "init writes a new template and never merges into an existing one"
		pe.Next = "choose an empty or absent directory"
		return nil, pe
	} else if err != nil && !os.IsNotExist(err) {
		pe := pdr.New(pdr.CodeLabInitTarget, "%s cannot be read: %v", dir, err)
		pe.Cause = "the target has to be readable — and a directory — before anything is written into it"
		pe.Next = "check the path and its permissions"
		return nil, pe
	}

	src, source, err := templateSource(from)
	if err != nil {
		return nil, err
	}
	files, err := readTemplate(src)
	if err != nil {
		return nil, err
	}
	renamed, old, err := renameTemplate(files["lab.yaml"], name)
	if err != nil {
		return nil, err
	}
	files["lab.yaml"] = renamed
	for rel, raw := range files {
		if rel == "lab.yaml" || (strings.HasPrefix(rel, "playbooks/") && (strings.HasSuffix(rel, ".yaml") || strings.HasSuffix(rel, ".yml"))) {
			files[rel] = liftAPIVersion(raw)
		}
	}

	rels := make([]string, 0, len(files))
	for rel := range files {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	if err := publish(dir, rels, files); err != nil {
		return nil, err
	}
	res := &initResult{Path: dir, Name: name, From: old, Source: source, Files: rels}
	for _, rel := range rels {
		if strings.HasPrefix(rel, "playbooks/") {
			res.Playbook = rel
			break
		}
	}
	return res, nil
}

// publish writes the whole scaffold into a staging directory beside the
// target and renames it into place, removing the staging directory if any
// part of it fails.
//
// Writing the files one by one into the target was wrong in a way the
// command's own promise made worse: a write
// that failed halfway — a full filesystem, a revoked permission — left a
// partial template behind, and the refusal an author saw on their re-run
// was "it already holds files", about a directory this command had made
// itself. Either the whole scaffold appears or nothing does.
//
// The staging directory is a sibling so the rename stays on one
// filesystem, and the target — empty or absent, checked before any of this
// — is removed first, because renaming onto an existing directory is not
// portable enough to rely on.
func publish(dir string, rels []string, files map[string][]byte) error {
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return scaffoldWriteError(err)
	}
	staging, err := os.MkdirTemp(parent, "."+filepath.Base(dir)+".podaro-init-")
	if err != nil {
		return scaffoldWriteError(err)
	}
	done := false
	defer func() {
		if !done {
			_ = os.RemoveAll(staging)
		}
	}()
	for _, rel := range rels {
		target := filepath.Join(staging, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return scaffoldWriteError(err)
		}
		if err := writeScaffoldFile(target, files[rel], 0o644); err != nil {
			return scaffoldWriteError(err)
		}
	}
	if err := os.Chmod(staging, 0o755); err != nil {
		return scaffoldWriteError(err)
	}
	if _, err := os.Stat(dir); err == nil {
		if err := os.Remove(dir); err != nil { // empty by the check above
			return scaffoldWriteError(err)
		}
	}
	if err := os.Rename(staging, dir); err != nil {
		return scaffoldWriteError(err)
	}
	done = true
	return nil
}

// writeScaffoldFile is os.WriteFile behind a name, so a test can fail one
// write of many and prove that a half-written scaffold never reaches the
// author's directory.
var writeScaffoldFile = os.WriteFile

func scaffoldWriteError(err error) *pdr.Error {
	pe := pdr.New(pdr.CodeLabInitTarget, "the scaffold could not be written: %v", err)
	pe.Cause = "the target directory is not writable, or the filesystem is full"
	pe.Next = "check the path and its permissions, then re-run"
	return pe
}

// templateSource resolves --from against the installed catalog first and
// the binary's starter catalog second, and refuses with the names that
// are available — the shape the engine's own refusal takes (PDR-E207).
func templateSource(from string) (fs.FS, string, error) {
	notInstalled := func() error {
		pe := pdr.New(pdr.CodeTemplateNotFound, "template %q is not installed", from)
		pe.Cause = "installed templates: " + strings.Join(installedTemplates(), ", ")
		pe.Next = "podaro lab init --from <one of those> <dir>"
		return pe
	}
	if !dnsLabel.MatchString(from) {
		return nil, "", notInstalled() // --from names a template, never a path
	}
	if m := podaro.Retirement(); m.Template(from) {
		// Refused before the catalog is read: an earlier build may have
		// left the retired template in <state>/catalog/, and a copy out of
		// it would put the retired lab back in an author's hands (the
		// reconciliation plan's R3; the review of #46 and #47, D).
		pe := pdr.New(pdr.CodeTemplateRetired, "template %q was retired by the owner on %s", from, m.RetiredOn)
		pe.Cause = "no release carries it · installed templates: " + strings.Join(installedTemplates(), ", ") + " · podaro explain " + pdr.CodeTemplateRetired
		pe.Next = "podaro lab init --from <one of those> <dir>"
		return nil, "", pe
	}
	dir := filepath.Join(config.StateDir(), "catalog", from)
	if fi, err := os.Stat(filepath.Join(dir, "lab.yaml")); err == nil && fi.Mode().IsRegular() {
		return os.DirFS(dir), "catalog", nil
	}
	if sub, err := fs.Sub(podaro.StarterCatalog(), from); err == nil {
		if fi, err := fs.Stat(sub, "lab.yaml"); err == nil && fi.Mode().IsRegular() {
			return sub, "binary", nil
		}
	}
	return nil, "", notInstalled()
}

// installedTemplates lists what --from can name: the installed catalog,
// and the starter templates the binary carries — less any template the
// retirement manifest lists, which an earlier build may have left in the
// catalog and which is never offered (the reconciliation plan's R3).
func installedTemplates() []string {
	seen := map[string]bool{}
	catalog := filepath.Join(config.StateDir(), "catalog")
	if entries, err := os.ReadDir(catalog); err == nil {
		for _, e := range entries {
			if fi, err := os.Stat(filepath.Join(catalog, e.Name(), "lab.yaml")); err == nil && fi.Mode().IsRegular() {
				seen[e.Name()] = true
			}
		}
	}
	starter := podaro.StarterCatalog()
	if entries, err := fs.ReadDir(starter, "."); err == nil {
		for _, e := range entries {
			if fi, err := fs.Stat(starter, e.Name()+"/lab.yaml"); err == nil && fi.Mode().IsRegular() {
				seen[e.Name()] = true
			}
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	offered, _ := podaro.Retirement().Catalog(names)
	return offered
}

// readTemplate reads a template directory into memory: lab.yaml, every
// playbook, and the assets a service names (spec 0003 §9). Nothing is
// interpreted here — the copy is a copy.
func readTemplate(src fs.FS) (map[string][]byte, error) {
	unreadable := func(format string, args ...any) *pdr.Error {
		pe := pdr.New(pdr.CodeLabUnreadable, format, args...)
		pe.Cause = "a template directory holds lab.yaml at its root, playbooks/*.yaml beside it, and any assets they name (spec 0003 §1)"
		pe.Next = "podaro lab init --from <another template> <dir>"
		return pe
	}
	files := map[string][]byte{}
	var irregular string
	err := fs.WalkDir(src, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// A symlink or a device node in a template is not copied and not
		// followed: reading through one would put a file from outside the
		// template into the scaffold, which is the shape the delivery
		// snapshot was taught to refuse at S8's review. The catalog is the
		// operator's own directory, so this is tidiness rather than a
		// wall — and a scaffold that quietly inlined /etc/passwd would be
		// neither.
		if !d.Type().IsRegular() {
			irregular = p
			return fs.SkipAll
		}
		raw, err := fs.ReadFile(src, p)
		if err != nil {
			return err
		}
		files[p] = raw
		return nil
	})
	if irregular != "" {
		return nil, unreadable("the template carries %s, which is not a regular file", irregular)
	}
	if err != nil {
		return nil, unreadable("the template could not be read: %v", err)
	}
	if _, ok := files["lab.yaml"]; !ok {
		return nil, unreadable("the template carries no lab.yaml")
	}
	return files, nil
}

// renameTemplate rewrites metadata.name in the manifest's own bytes and
// returns the name that was there. The edit is textual on purpose: a YAML
// round-trip would drop the schema header line and every comment the
// author is meant to read (UX §7, "the manifest is an interface"), so the
// document is parsed only to find where the name *is* — yaml.Node carries
// each scalar's line and column — and the bytes at that position are
// replaced. The result is re-read and refused unless it now declares the
// new name: a rename nobody checked is how a scaffold ends up a second
// copy of the template it came from.
func renameTemplate(manifest []byte, name string) ([]byte, string, error) {
	site, value, doc, err := nameNode(manifest)
	if err != nil {
		return nil, "", err
	}
	old := value.Value
	if old == name {
		return manifest, old, nil
	}
	refuse := func(why string) *pdr.Error {
		pe := pdr.New(pdr.CodeLabUnreadable, "metadata.name is not a line this scaffold can rewrite: %s", why)
		pe.Cause = "the rename edits the manifest's own bytes so its comments and schema header survive, which needs a scalar this can find the end of — a plain, single-quoted or double-quoted one on a single line"
		pe.Next = "copy the template directory by hand and set metadata.name to " + name
		return pe
	}
	lines := strings.Split(string(manifest), "\n")

	// Which node to edit is the whole question when the name is shared.
	//
	// `name: *label` — the site is an alias, and the scalar it names
	// belongs to whatever declared the anchor (`title: &label vendor-lab`).
	// Editing that scalar would rename the title too, which breaks this
	// command's one promise: the name is its only edit.
	// So the alias itself is replaced, in place, by the new
	// name — the anchor and every other user of it survive untouched.
	//
	// `name: &label vendor-lab` with `*label` somewhere else is the mirror
	// image: the value really is the name's own, but it is shared, and this
	// refuses rather than renaming a key it was not asked about.
	edit := site
	span := func(l string) (int, int, func(string) string, bool) {
		return scalarSpan(l, edit.Column, edit.Style, edit.Anchor, old)
	}
	if site.Kind == yaml.AliasNode {
		span = func(l string) (int, int, func(string) string, bool) {
			return aliasSpan(l, site.Column, site.Value)
		}
	} else if site.Anchor != "" && aliasedElsewhere(doc, site, site) {
		pe := pdr.New(pdr.CodeLabUnreadable, "metadata.name carries the anchor &%s, which other keys alias", site.Anchor)
		pe.Cause = "renaming the value here would rename every key that aliases it, and init's only edit is the template's name"
		pe.Next = "give metadata.name a value of its own in the source template, or copy the directory by hand and set the name to " + name
		return nil, "", pe
	}
	if edit.Line < 1 || edit.Line > len(lines) {
		return nil, "", refuse("its line is outside the document")
	}
	line := lines[edit.Line-1]
	start, end, quoted, ok := span(line)
	if !ok {
		return nil, "", refuse("its line does not carry the name where the parser puts it")
	}
	lines[edit.Line-1] = line[:start] + quoted(name) + line[end:]
	out := []byte(strings.Join(lines, "\n"))
	_, got, _, err := nameNode(out)
	if err != nil {
		return nil, "", err
	}
	if got.Value != name {
		return nil, "", refuse("the document still declares " + got.Value)
	}
	return out, old, nil
}

// liftAPIVersion writes the current contract's version into a manifest
// that declares v1alpha1 — the engine writes v1alpha2 (the reconciliation
// plan's D-R2) — and rewrites a first-line schema header that points at a
// v1alpha1 schema with it. The two versions mean the same for a document
// that names nothing retired, and one that does fails PDR-E106 under
// either, so the lift changes no meaning. Like the rename it is textual,
// so comments survive; a manifest whose apiVersion is not a plain scalar
// this can find is copied as it is — v1alpha1 is still read.
func liftAPIVersion(manifest []byte) []byte {
	var root yaml.Node
	if yaml.Unmarshal(manifest, &root) != nil || root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return manifest
	}
	v := mapValue(root.Content[0], "apiVersion")
	if v == nil || v.Kind != yaml.ScalarNode || v.Anchor != "" || v.Value != lab.APIVersionV1alpha1 {
		return manifest
	}
	lines := strings.Split(string(manifest), "\n")
	if v.Line < 1 || v.Line > len(lines) {
		return manifest
	}
	line := lines[v.Line-1]
	start, end, quoted, ok := scalarSpan(line, v.Column, v.Style, "", v.Value)
	if !ok {
		return manifest
	}
	lines[v.Line-1] = line[:start] + quoted(lab.APIVersion) + line[end:]
	const header = "# yaml-language-server: $schema=https://schemas.podaro.dev/"
	if first := lines[0]; strings.HasPrefix(first, header) && strings.HasSuffix(first, "/v1alpha1.json") {
		lines[0] = strings.TrimSuffix(first, "/v1alpha1.json") + "/v1alpha2.json"
	}
	out := []byte(strings.Join(lines, "\n"))
	var check yaml.Node
	if yaml.Unmarshal(out, &check) != nil || len(check.Content) == 0 {
		return manifest
	}
	if got := mapValue(check.Content[0], "apiVersion"); got == nil || got.Value != lab.APIVersion {
		return manifest
	}
	return out
}

// byteColumn turns a node's column into an index into its line. The two
// are not the same number: the parser counts columns in *characters*,
// while a Go string is indexed in bytes, so any multi-byte rune earlier on
// the line shifts the token further along than the column says. A title or
// description may hold anything — `metadata: {description: café, name:
// *label}` put the alias at column 62 and byte 62, one apart — and
// treating the column as an offset made `lab init` refuse a valid
// template, since the token it found there was not the one it expected.
//
// A column past the end of the line returns -1, which the callers' bounds
// checks refuse like any other span they cannot find.
func byteColumn(line string, column int) int {
	want := column - 1
	if want < 0 {
		return -1
	}
	seen := 0
	for i := range line {
		if seen == want {
			return i
		}
		seen++
	}
	if seen == want {
		return len(line)
	}
	return -1
}

// aliasSpan locates an alias token (`*label`) on its line. The parser
// reports an alias at the `*`, and its value is the anchor's name without
// it, so the token is as long as the two together.
func aliasSpan(line string, column int, anchor string) (start, end int, quote func(string) string, ok bool) {
	start = byteColumn(line, column)
	token := "*" + anchor
	if start < 0 || start+len(token) > len(line) || line[start:start+len(token)] != token {
		return 0, 0, nil, false
	}
	return start, start + len(token), func(s string) string { return s }, true
}

// scalarSpan locates a scalar's raw bytes on its line and returns how to
// write a replacement in the same style.
//
// A quoted name is as valid as a plain one — `name: "vendor-lab"` says the
// same thing to the schema — and refusing to scaffold from a catalog entry
// because its author quoted a string would make valid templates unusable.
// The end of the token is found by the
// style's own rule: a plain scalar is its value verbatim, a single-quoted
// one ends at a quote that is not doubled, a double-quoted one at a quote
// that is not escaped. A folded or literal block (`|`, `>`) spans lines
// and is refused rather than guessed at.
//
// The replacement never needs escaping: a template name is a DNS label
// (spec 0003 §2), so it carries no quote, backslash or newline — it is
// written back inside whichever quotes were there, and the document is
// re-read afterwards either way.
func scalarSpan(line string, column int, style yaml.Style, anchor, value string) (start, end int, quote func(string) string, ok bool) {
	start = byteColumn(line, column)
	if start < 0 || start >= len(line) {
		return 0, 0, nil, false
	}
	// An anchored scalar (`name: &n my-lab`) is reported at its anchor
	// token, not at its value, and an aliased name resolves to exactly
	// such a node. Step over the anchor and
	// the whitespace after it, so the span is the value itself.
	if anchor != "" {
		if tok := "&" + anchor; strings.HasPrefix(line[start:], tok) {
			start += len(tok)
			for start < len(line) && (line[start] == ' ' || line[start] == '\t') {
				start++
			}
			if start >= len(line) {
				return 0, 0, nil, false
			}
		}
	}
	plain := func(s string) string { return s }
	switch style {
	case 0:
		if strings.HasPrefix(line[start:], value) {
			return start, start + len(value), plain, true
		}
	case yaml.SingleQuotedStyle:
		if line[start] != '\'' {
			return 0, 0, nil, false
		}
		for i := start + 1; i < len(line); i++ {
			if line[i] != '\'' {
				continue
			}
			if i+1 < len(line) && line[i+1] == '\'' {
				i++ // a doubled quote is one quote inside the scalar
				continue
			}
			return start, i + 1, func(s string) string { return "'" + s + "'" }, true
		}
	case yaml.DoubleQuotedStyle:
		if line[start] != '"' {
			return 0, 0, nil, false
		}
		for i := start + 1; i < len(line); i++ {
			if line[i] == '\\' {
				i++ // an escape takes the next byte with it
				continue
			}
			if line[i] == '"' {
				return start, i + 1, func(s string) string { return "\"" + s + "\"" }, true
			}
		}
	}
	return 0, 0, nil, false
}

// nameNode finds the metadata.name scalar, with its position.
// nameNode returns three things about metadata.name: the node at the name's
// own site (an alias when the name is written `name: *label`), the scalar
// that site resolves to, and the document, so a caller can tell whether
// editing that scalar would change anything else.
func nameNode(manifest []byte) (site, value, doc *yaml.Node, err *pdr.Error) {
	bad := func(format string, args ...any) *pdr.Error {
		pe := pdr.New(pdr.CodeLabSchema, format, args...)
		pe.Cause = "a scaffold is a copy, so the source manifest has to parse and declare metadata.name (spec 0003 §2) before it is copied"
		pe.Next = "podaro lab validate on the source template"
		return pe
	}
	var root yaml.Node
	if e := yaml.Unmarshal(manifest, &root); e != nil {
		return nil, nil, nil, bad("the template's lab.yaml is not valid YAML: %v", e)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, nil, nil, bad("the template's lab.yaml holds no document")
	}
	metadata := resolveAlias(mapValue(root.Content[0], "metadata"))
	if metadata == nil {
		return nil, nil, nil, bad("the template declares no metadata block")
	}
	site = mapValue(metadata, "name")
	value = resolveAlias(site)
	if site == nil || value == nil || value.Kind != yaml.ScalarNode || value.Value == "" {
		return nil, nil, nil, bad("the template declares no metadata.name")
	}
	return site, value, &root, nil
}

// aliasedElsewhere reports whether any node under root is an alias to
// target other than target's own site — that is, whether rewriting
// target's value would rename more than metadata.name.
func aliasedElsewhere(root, target, site *yaml.Node) bool {
	found := false
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil || found {
			return
		}
		if n.Kind == yaml.AliasNode && n.Alias == target && n != site {
			found = true
			return
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(root)
	return found
}

// mapValue returns the value node for a key of a mapping node.
// mapValue reads one key out of a mapping the way the loader reads it:
// through aliases, and through YAML merge keys (`<<`) when the mapping
// does not carry the key itself. internal/lab/document.go expands merges,
// so a manifest that inherits `metadata` — or the name inside it — from an
// anchor passes `lab validate`; a direct scan of the mapping's own pairs
// would then refuse a template the engine accepts, which is the same trade
// a quoted name was refused on.
//
// Precedence is the loader's and the spec's: the mapping's own keys win
// over every merged one, and among merged mappings an earlier `<<` entry
// wins over a later one.
func mapValue(m *yaml.Node, key string) *yaml.Node {
	m = resolveAlias(m)
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	// The value is returned as it is written — an alias stays an alias —
	// because the rename has to edit the name's own site, not whatever it
	// points at. Callers that need to walk
	// into the value resolve it themselves.
	var merges []*yaml.Node
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := resolveAlias(m.Content[i])
		if k == nil {
			continue
		}
		if k.Kind == yaml.ScalarNode && k.Tag == "!!merge" {
			merges = append(merges, m.Content[i+1])
			continue
		}
		if k.Value == key {
			return m.Content[i+1]
		}
	}
	for _, mn := range merges {
		mn = resolveAlias(mn)
		if mn == nil {
			continue
		}
		if mn.Kind == yaml.SequenceNode { // `<<: [*a, *b]` — earlier wins
			for _, item := range mn.Content {
				if v := mapValue(item, key); v != nil {
					return v
				}
			}
			continue
		}
		if v := mapValue(mn, key); v != nil {
			return v
		}
	}
	return nil
}

// resolveAlias follows an alias to the node it names, with the same hop
// limit internal/lab/document.go uses, so a cycle cannot spin here either.
func resolveAlias(n *yaml.Node) *yaml.Node {
	for hops := 0; n != nil && n.Kind == yaml.AliasNode && n.Alias != nil && hops < 8; hops++ {
		n = n.Alias
	}
	if n != nil && n.Kind == yaml.AliasNode {
		return nil // an unresolvable or too-deep alias is not a value
	}
	return n
}

// shellPath renders a path so the printed command can be copied as it
// stands: a space or a quote in it would otherwise split into arguments,
// and a leading dash would be read as a flag (UX §6: `next` is "a real
// button or copyable command").
func shellPath(p string) string {
	if strings.HasPrefix(p, "-") {
		p = "./" + p // the same directory, no longer a flag
	}
	if p != "" && !strings.ContainsAny(p, " \t\n'\"\\$`&;|<>()*?[]#~!{}") {
		return p
	}
	return "'" + strings.ReplaceAll(p, "'", `'\''`) + "'"
}
