// SPDX-License-Identifier: AGPL-3.0-only

package lab

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	seedpkg "github.com/jeremiahjrross/podaro/internal/seed"
	"github.com/jeremiahjrross/podaro/internal/wire"
	"slices"
)

// Rules are the individually testable checks `lab validate` enforces.
// Each has at least one broken fixture in testdata/broken (the S3
// acceptance: "a deliberately broken fixture set exercises every §9 rule
// with the documented codes").
const (
	RuleUnreadable       = "manifest-unreadable"     // PDR-E100
	RuleSchema           = "schema"                  // PDR-E101
	RuleModuleRef        = "module-ref"              // PDR-E102 · spec 0003 §11.1
	RuleModuleMeta       = "module-meta"             // PDR-E104 · spec 0003 §11.1
	RuleConfigMerge      = "config-merge"            // PDR-E104 · spec 0003 §11.2
	RuleSecretRef        = "secret-ref"              // PDR-E102 · spec 0003 §11.3
	RuleSecretRefPlace   = "secret-ref-placement"    // PDR-E103 · spec 0003 §6, Spec 0002 §2
	RuleSecretKind       = "secret-kind-conflict"    // PDR-E104 · spec 0003 §6
	RuleEULAConflict     = "eula-conflict"           // PDR-E104 · spec 0003 §7
	RuleExecSecretGrant  = "exec-secret-grant"       // PDR-E102 · spec 0003 §6, Spec 0002 §2
	RuleLicenses         = "licenses"                // PDR-E104 · spec 0003 §11.4
	RuleAliasDuplicate   = "alias-duplicate"         // PDR-E104 · spec 0003 §11.6
	RuleAliasShadow      = "alias-shadow"            // PDR-E104 · spec 0003 §11.6
	RuleAliasCollision   = "alias-collision"         // PDR-E104 · spec 0003 §11.6
	RuleAdapterUnknown   = "adapter-unknown"         // PDR-E102 · spec 0003 §10
	RuleGeneratorUnknown = "generator-unknown"       // PDR-E102 · spec 0003 §4, §10
	RuleRetired          = "retired"                 // PDR-E106 · spec 0001 §11, spec 0003 §13 (a retired adapter, generator or module, by the embedded retirement manifest — under v1alpha1 and v1alpha2 alike)
	RuleProfileService   = "profile-service"         // PDR-E102 · spec 0003 §8
	RuleInitService      = "init-service"            // PDR-E102 · spec 0003 §9.1
	RuleInitAuthSecret   = "init-auth-secret"        // PDR-E102 · spec 0003 §6, §9.1
	RuleFilePath         = "file-path"               // PDR-E103 · spec 0003 §9 (a file lands where its clean, absolute path says; the copy never leaves its staging directory)
	RuleFileSource       = "file-source"             // PDR-E103 · spec 0003 §9 (a file's content is written inline or comes from a template asset — one of the two, and the asset is a real file inside the template)
	RuleInitCycle        = "init-cycle"              // PDR-E104 · spec 0003 §9.1 (cross-service init targets order the bring-up; a cycle has none)
	RuleInitHeaderDup    = "init-header-duplicate"   // PDR-E103 · spec 0003 §9.1 (HTTP field names are case-insensitive: one value per field, whatever its case)
	RuleInitAuthUser     = "init-auth-username"      // PDR-E103 · spec 0003 §9.1 (curl's --user and HTTP Basic split the credentials at the first colon)
	RuleInitHost         = "init-host"               // PDR-E103 · spec 0003 §9.1 (an authored Host header is RFC 9110 §7.2's grammar: a name or address, a numeric port at most)
	RuleInitHeaderName   = "init-header-name"        // PDR-E103 · spec 0003 §9.1 (a header name is RFC 9110 §5.1's token; curl reads the first colon as the field's end)
	RuleCheckpointIDDup  = "checkpoint-id-duplicate" // PDR-E103 · spec 0001 §9
	RuleObjectiveHint    = "objective-hint"          // PDR-E103 · spec 0001 §2, §9
	RulePlaybookNameDup  = "playbook-name-duplicate" // PDR-E103 · spec 0001 §5
	RuleStepIDDup        = "step-id-duplicate"       // PDR-E103 · spec 0001 §9
	RuleSeedAction       = "seed-action"             // PDR-E102 · spec 0001 §9
	RuleCheckpointRef    = "checkpoint-ref"          // PDR-E102 · spec 0001 §9
	RuleContext          = "context"                 // PDR-E102 · spec 0001 §9
	RuleReveal           = "reveal"                  // PDR-E102 · spec 0001 §9
	RuleReproAuto        = "repro-auto"              // PDR-E103 · spec 0001 §9
	RuleExecParams       = "exec-params"             // PDR-E103 · spec 0001 §3, Spec 0002 §2 (an exec checkpoint's params are image, args, env, secrets, limits; the engine would skip anything else)
	RuleSeedParams       = "seed-params"             // PDR-E103 · spec 0003 §4 (a built-in generator's params are the ones it reads; the engine would skip anything else)
	RuleAttestParams     = "attest-params"           // PDR-E103 · spec 0001 §3 (an attest checkpoint's params are exactly a non-empty prompt, and it expects nothing)
	RuleUIScheme         = "ui-scheme"               // PDR-E103 · spec 0003 §11 (the gateway proxies http/https)
	RuleNoObjectives     = "no-objectives"           // PDR-W102 · spec 0001 §9 (warning)
)

// proxiableScheme reports whether a ui endpoint's scheme is one the
// gateway proxies: http or https (the schema's default is http).
func proxiableScheme(scheme string) bool {
	return scheme == "" || scheme == "http" || scheme == "https"
}

// Rules lists every rule id, for coverage tests.
var Rules = []string{
	RuleUnreadable, RuleSchema, RuleModuleRef, RuleModuleMeta, RuleConfigMerge,
	RuleSecretRef, RuleSecretRefPlace, RuleSecretKind, RuleEULAConflict, RuleExecSecretGrant, RuleLicenses, RuleAliasDuplicate,
	RuleAliasShadow, RuleAliasCollision, RuleAdapterUnknown, RuleGeneratorUnknown, RuleRetired,
	RuleProfileService, RuleInitService, RuleInitAuthSecret, RuleInitCycle, RuleInitHeaderDup, RuleInitAuthUser, RuleInitHost, RuleInitHeaderName, RuleFilePath, RuleFileSource, RuleCheckpointIDDup, RuleObjectiveHint,
	RulePlaybookNameDup, RuleStepIDDup, RuleSeedAction, RuleCheckpointRef, RuleExecParams, RuleSeedParams, RuleAttestParams,
	RuleContext, RuleReveal, RuleReproAuto, RuleNoObjectives, RuleUIScheme,
}

// Finding is one violation or warning, located at file:line.
type Finding struct {
	Code    string `json:"code"`
	Rule    string `json:"rule"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

// Options select what to validate.
type Options struct {
	// Path is a template directory (holding lab.yaml) or a lab.yaml file.
	Path string
	// Library resolves `use:` references; nil means the embedded library.
	Library *Library
	// Display is the template directory named in messages, findings and
	// the plan; empty means Path. An engine that validates a copy of a
	// template (a delivery snapshot) names the directory the copy was
	// taken from — the one the operator edits — never the copy's own path.
	Display string
}

// display is the template path the envelope and the plan name.
func (o Options) display() string {
	if o.Display != "" {
		return o.Display
	}
	return o.Path
}

// displayDir is the template directory the findings name.
func (o Options) displayDir() string {
	if o.Display != "" {
		return o.Display
	}
	if fi, err := os.Stat(o.Path); err == nil && !fi.IsDir() {
		return filepath.Dir(o.Path)
	}
	return o.Path
}

// Result is the outcome of Validate: the loaded template, its
// composition, its playbooks, and every finding.
type Result struct {
	// Path is the template path as given; Dir the directory it resolved to.
	Path string
	Dir  string
	// Template and Composition are set when the template's shape was
	// accepted (referential rules ran).
	Template    *Template
	Doc         *Document
	Composition *Composition
	Playbooks   []*LoadedPlaybook
	Findings    []Finding
	Warnings    []Finding
}

// LoadedPlaybook is one playbook file with its typed view.
type LoadedPlaybook struct {
	Doc      *Document
	Playbook *Playbook
}

// Valid reports whether no error-level finding was recorded.
func (r *Result) Valid() bool { return len(r.Findings) == 0 }

// Error renders the findings as the one error envelope (API §3): the
// leading code is the first finding's (by file, then line); every finding
// is a detail with its own code and file:line.
func (r *Result) Error() *pdr.Error {
	if r.Valid() {
		return nil
	}
	first := r.Findings[0]
	noun := "problem"
	if len(r.Findings) > 1 {
		noun = "problems"
	}
	e := pdr.New(first.Code, "%s is not a valid lab: %d %s", r.Path, len(r.Findings), noun)
	if entry, ok := pdr.Lookup(first.Code); ok {
		e.Cause = entry.Cause
	}
	e.Next = "fix each detail at its file:line, then re-run: podaro lab validate " + r.Path
	for _, f := range r.Findings {
		e.Details = append(e.Details, pdr.Detail{Code: f.Code, Path: f.Path, Hint: f.Message})
	}
	return e
}

type validation struct {
	opts          Options
	library       *Library
	res           *Result
	doc           *Document
	template      *Template
	libraryFailed bool // the module library root is unreadable: reported once
	// assetLoc remembers where a resolved `source:` asset's text came
	// from, keyed by service and pointer into the merged tree. The text
	// joins that tree so the §11.3 secret pass judges it (round 1), and
	// without this the pass would locate a finding by looking
	// `config.files[i].content` up in a document that says `source:` —
	// missing, and falling back to whichever document declared the file.
	// Where a module declares it, that is the module's own manifest: a
	// file the author did not write the reference into and, for a
	// shipped module, does not own.
	assetLoc map[string]string
}

// assetKey names one file's resolved content in one service.
func assetKey(service string, i int) string {
	return service + "\x00config/files/" + strconv.Itoa(i) + "/content"
}

func (v *validation) fail(code, rule, loc, format string, args ...any) {
	v.res.Findings = append(v.res.Findings, Finding{Code: code, Rule: rule, Path: loc, Message: fmt.Sprintf(format, args...)})
}

func (v *validation) warn(code, rule, loc, format string, args ...any) {
	v.res.Warnings = append(v.res.Warnings, Finding{Code: code, Rule: rule, Path: loc, Message: fmt.Sprintf(format, args...)})
}

// failErr records an unreadable manifest as a finding. The location is
// the DocumentError's own (never parsed out of the message, so paths with
// whitespace survive); the message drops that leading location.
func (v *validation) failErr(rule string, err error) {
	var de *DocumentError
	if errors.As(err, &de) {
		// The message may open with the location (file:line) or with the
		// bare file; either way the finding's path already says it.
		msg := de.Err.Message
		for _, prefix := range []string{de.Loc, strings.TrimRight(strings.TrimRightFunc(de.Loc, unicode.IsDigit), ":")} {
			if prefix != "" && strings.HasPrefix(msg, prefix) {
				msg = strings.TrimPrefix(msg, prefix)
				break
			}
		}
		msg = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(msg), ":"))
		if de.Err.Cause != "" {
			msg += ": " + de.Err.Cause
		}
		v.fail(de.Err.Code, rule, de.Loc, "%s", msg)
		return
	}
	var pe *pdr.Error
	if errors.As(err, &pe) {
		v.fail(pe.Code, rule, "", "%s", pe.Message)
		return
	}
	v.fail(pdr.CodeLabUnreadable, rule, "", "%v", err)
}

// valueAt follows JSON-pointer tokens through a JSON-compatible value;
// nil when the path does not exist.
func valueAt(v any, ptr []string) any {
	for _, tok := range ptr {
		switch t := v.(type) {
		case map[string]any:
			v = t[tok]
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(t) {
				return nil
			}
			v = t[i]
		default:
			return nil
		}
	}
	return v
}

// decodeLoc locates a typed-decode failure: yaml.v3 names the offending
// line (a duplicate mapping key, a value of the wrong kind), and every
// finding carries file:line (API §6).
func decodeLoc(doc *Document, err error) string {
	if m := yamlLine.FindStringSubmatch(err.Error()); m != nil {
		return doc.Path + ":" + m[1]
	}
	return doc.Path
}

// hardError returns the *pdr.Error a caller renders for a manifest that
// could not be loaded at all (the template's own lab.yaml).
func hardError(err error) error {
	var de *DocumentError
	if errors.As(err, &de) {
		return de.Err
	}
	return err
}

// schemaCheck validates a document's shape against the schema of its
// kind and declared version (schemaFor); false when violations exist.
func (v *validation) schemaCheck(doc *Document, kind string) bool {
	violations, err := schemaViolations(schemaFor(kind, doc.Value), doc.Value)
	if err != nil {
		v.fail(pdr.CodeLabSchema, RuleSchema, doc.Path, "schema unavailable: %v", err)
		return false
	}
	for _, sv := range violations {
		where := pointerString(sv.Pointer)
		v.fail(pdr.CodeLabSchema, RuleSchema, doc.Loc(sv.Pointer...), "%s: %s", where, sv.Message)
	}
	return len(violations) == 0
}

// Validate runs every rule over a template directory. The returned error
// is set only when the template itself cannot be read (PDR-E100);
// everything else is reported through the Result.
func Validate(opts Options) (*Result, error) {
	lib := opts.Library
	if lib == nil {
		lib = EmbeddedLibrary()
	}
	dir, labFile, err := resolvePath(opts.Path)
	if err != nil {
		return nil, err
	}
	res := &Result{Path: opts.display(), Dir: dir}
	v := &validation{opts: opts, library: lib, res: res}

	labDisplay := labFile
	if opts.Display != "" {
		labDisplay = filepath.Join(opts.Display, filepath.Base(labFile))
	}
	doc, err := LoadDocument(os.DirFS(dir), filepath.Base(labFile), labDisplay)
	if err != nil {
		return nil, hardError(err)
	}
	res.Doc = doc
	v.doc = doc

	templateOK := v.schemaCheck(doc, KindTemplate)
	var comp *Composition
	if templateOK {
		var t Template
		if err := doc.Decode(&t); err != nil {
			v.fail(pdr.CodeLabSchema, RuleSchema, decodeLoc(doc, err), "cannot decode template: %v", err)
			templateOK = false
		} else {
			v.template = &t
			res.Template = &t
			comp = v.compose()
			res.Composition = comp
			if !v.libraryFailed {
				v.templateRules(comp)
			}
		}
	}

	// An unreadable module library composes nothing: every reference rule
	// would only echo that one real problem, so the playbooks are not
	// judged until the library path is fixed.
	if !v.libraryFailed {
		v.playbooks(dir, comp)
	}

	sort.SliceStable(res.Findings, func(i, j int) bool { return findingLess(res.Findings[i], res.Findings[j]) })
	sort.SliceStable(res.Warnings, func(i, j int) bool { return findingLess(res.Warnings[i], res.Warnings[j]) })
	return res, nil
}

// resolvePath accepts a template directory or its lab.yaml.
func resolvePath(p string) (dir, labFile string, err error) {
	if p == "" {
		e := pdr.New(pdr.CodeLabUnreadable, "no template path given")
		e.Next = "podaro lab validate <template-dir>"
		return "", "", e
	}
	fi, statErr := os.Stat(p)
	if statErr != nil {
		e := pdr.New(pdr.CodeLabUnreadable, "cannot read %s", p)
		e.Cause = statErr.Error()
		e.Next = "check the path: a template directory holds lab.yaml and playbooks/*.yaml (spec 0003 §1)"
		return "", "", e
	}
	if fi.IsDir() {
		return p, filepath.Join(p, "lab.yaml"), nil
	}
	return filepath.Dir(p), p, nil
}

func findingLess(a, b Finding) bool {
	fa, la := splitLoc(a.Path)
	fb, lb := splitLoc(b.Path)
	if fa != fb {
		return fa < fb
	}
	if la != lb {
		return la < lb
	}
	if a.Rule != b.Rule {
		return a.Rule < b.Rule
	}
	return a.Message < b.Message
}

func splitLoc(loc string) (string, int) {
	i := strings.LastIndex(loc, ":")
	if i < 0 {
		return loc, 0
	}
	n, err := strconv.Atoi(loc[i+1:])
	if err != nil {
		return loc, 0
	}
	return loc[:i], n
}

// templateRules applies the template-side rules once the composition
// exists (spec 0003 §11 and the template half of spec 0001 §9).
func (v *validation) templateRules(c *Composition) {
	t := v.template
	doc := v.doc

	// The files pass runs first: it resolves every `source:` into the
	// content it names, and the §11.3 secret pass below judges the
	// references that content carries. Resolved after it, a Pack's
	// `${secret:…}` would reach create unjudged (plan S8).
	// §9 config files land where their path says: absolute and clean, so
	// the engine's copy-in (which stages each file under a private
	// directory before `podman cp`) can never be walked out of it.
	for _, svcName := range sortedKeys(c.Services) {
		cs := c.Services[svcName]
		if cs.Module == nil || cs.Module.Config == nil {
			continue
		}
		overridden := lookupMap(doc.Value, "services", svcName, "config")["files"] != nil
		for i := range cs.Module.Config.Files {
			f := &cs.Module.Config.Files[i]
			at := func(field string) string {
				ptr := []string{"config", "files", strconv.Itoa(i), field}
				if overridden {
					return doc.Loc(append([]string{"services", svcName}, ptr...)...)
				}
				return c.Modules[cs.moduleName()].Doc.Loc(ptr...)
			}
			// has answers whether the author wrote a key at all, in the
			// document `at` would point at.
			has := func(field string) bool {
				ptr := []string{"config", "files", strconv.Itoa(i), field}
				if overridden {
					return doc.Has(append([]string{"services", svcName}, ptr...)...)
				}
				return c.Modules[cs.moduleName()].Doc.Has(ptr...)
			}
			if err := runtime.ValidateFilePath(f.Path); err != nil {
				v.fail(pdr.CodeLabStructure, RuleFilePath, at("path"), "service %q: %v (spec 0003 §9)", svcName, err)
			}
			// A file's content is written inline or comes from a template
			// asset (spec 0003 §9, plan S8). Both would leave two contents
			// and no rule for which lands; declaring neither is the
			// schema's own refusal, where it reads as the missing key it
			// is.
			// Presence, not emptiness: an empty file is a file a
			// template may ship, so `content: ""` beside a `source:` is
			// two contents declared and the reader has to say which one
			// the author meant. The value cannot answer that; the
			// document can.
			switch {
			case f.Source != "" && has("content"):
				v.fail(pdr.CodeLabStructure, RuleFileSource, at("source"),
					"service %q: file %s declares both content and source — they are two contents, and only one can land (spec 0003 §9)", svcName, f.Path)
			case f.Source != "":
				content, err := readAsset(v.res.Dir, f.Source)
				if err != nil {
					v.fail(pdr.CodeLabStructure, RuleFileSource, at("source"),
						"service %q: file %s: %v (spec 0003 §9)", svcName, f.Path, err)
					continue
				}
				f.Content = content
				if v.assetLoc == nil {
					v.assetLoc = map[string]string{}
				}
				// The content is read from res.Dir; the location names
				// opts.displayDir(), as every other finding does. For a
				// delivery snapshot those differ — the engine reads its
				// private copy and names the operator's template — and
				// pointing at the snapshot sends them to a directory
				// discarded after admission.
				v.assetLoc[assetKey(svcName, i)] = filepath.Join(v.opts.displayDir(), f.Source)
				// And into the tree §11.3 walks. The comment above this
				// pass has said since S8 that the secret pass judges what
				// an asset carries; it judges `doc.Value` and
				// `cs.Merged`, and the resolved text was in neither — so
				// a Pack's `${secret:missing}` passed `lab validate` and
				// failed at create. One
				// tree, one pass, and the comment is true.
				setMergedFileContent(cs.Merged, i, content)
			}
		}
	}

	// §11.4 licenses: equals the composed EULA set.
	declared := append([]string(nil), t.Licenses...)
	sort.Strings(declared)
	if strings.Join(declared, ",") != strings.Join(c.eulaIDs(), ",") {
		loc := doc.Loc("licenses")
		if len(t.Licenses) == 0 {
			loc = doc.Loc("services")
		}
		v.fail(pdr.CodeLabComposition, RuleLicenses, loc,
			"licenses [%s] must equal the EULAs the composition declares [%s]",
			strings.Join(declared, ", "), strings.Join(c.eulaIDs(), ", "))
	}

	// §11.3 every ${secret:<name>} reference resolves — checked on the
	// *effective* values: the template (its service config: blocks aside)
	// and each service's merged module, so an override that replaces a
	// module string is judged by what create will render, and each
	// unresolved reference points at the line that wrote it.
	// References belong only where create renders them: module config/init
	// strings and an inline service's env/command (spec 0003 §6). Seeds and
	// checkpoints receive secrets through declared grants (Spec 0002 §2),
	// so a reference anywhere else would reach the plan unrendered.
	seenRefs := map[string]bool{}
	v.walkSecretRefs(doc.Value, nil, c, seenRefs,
		func(ptr []string) string { return doc.Loc(ptr...) },
		func(ptr []string) bool { return len(ptr) == 3 && ptr[0] == "services" && ptr[2] == "config" },
		func(ptr []string) bool {
			return len(ptr) >= 3 && ptr[0] == "services" && (ptr[2] == "env" || ptr[2] == "command")
		})
	for _, svcName := range sortedKeys(c.Services) {
		cs := c.Services[svcName]
		if cs.Merged == nil {
			continue
		}
		cm := c.Modules[cs.moduleName()]
		v.walkSecretRefs(cs.Merged, nil, c, seenRefs,
			func(ptr []string) string { return v.mergedLoc(cs, cm, ptr) },
			nil,
			initRenderedPlacement)
	}

	// Exec secret grants (Spec 0002 §2: declared names only).
	for _, seedName := range sortedKeys(t.Seeds) {
		seed := t.Seeds[seedName]
		if seed.Generator.Exec != nil {
			v.execGrants(doc, c, seed.Generator.Exec.Secrets, "seeds", seedName, "generator", "exec", "secrets")
		} else if v.retiredGenerator(doc, seed.Generator.Name, "seeds", seedName, "generator") {
			continue
		} else if !c.generatorKnown(seed.Generator.Name) {
			v.fail(pdr.CodeLabReference, RuleGeneratorUnknown, doc.Loc("seeds", seedName, "generator"),
				"generator %q is neither built-in (%s) nor a composed module's alias (%s)",
				seed.Generator.Name, joinOrNone(sortedKeys(builtinGenerators)), joinOrNone(sortedKeys(c.Generators)))
		} else if known, builtin := seedpkg.GeneratorParams[seed.Generator.Name]; builtin {
			// A built-in generator's params are the ones it reads (spec 0003
			// §4): the engine refuses anything else before delivery, and the
			// author learns it here, at file:line.
			for _, k := range sortedKeys(seed.Params) {
				if !slices.Contains(known, k) {
					v.fail(pdr.CodeLabStructure, RuleSeedParams, doc.Loc("seeds", seedName, "params", k),
						"seed %s: params.%s is not a parameter the %s generator reads — %s (spec 0003 §4); the engine would skip it and deliver something other than authored", seedName, k, seed.Generator.Name, strings.Join(known, ", "))
				}
			}
		}
	}
	for _, name := range sortedKeys(c.Modules) {
		m := c.Modules[name]
		for i, a := range m.Module.Adapters {
			v.execGrants(m.Doc, c, a.Exec.Secrets, "adapters", strconv.Itoa(i), "exec", "secrets")
		}
		for i, a := range m.Module.Generators {
			v.execGrants(m.Doc, c, a.Exec.Secrets, "generators", strconv.Itoa(i), "exec", "secrets")
		}
		// A ui endpoint is what the gateway proxies as `<service>-<instance>`
		// (User Manual §5), and only http or https can be: a tcp ui
		// endpoint would be given a hostname no request could ever reach.
		for i, e := range m.Module.Endpoints {
			if e.Purpose == "ui" && !proxiableScheme(e.Scheme) {
				v.fail(pdr.CodeLabStructure, RuleUIScheme, m.Doc.Loc("endpoints", strconv.Itoa(i), "scheme"),
					"ui endpoint on port %d has scheme %q — the gateway proxies http or https only (tcp is for raw ports)", e.Port, e.Scheme)
			}
		}
	}
	for _, cs := range c.Services {
		for i, e := range cs.Svc.Endpoints {
			if e.Purpose == "ui" && !proxiableScheme(e.Scheme) {
				v.fail(pdr.CodeLabStructure, RuleUIScheme, doc.Loc("services", cs.Name, "endpoints", strconv.Itoa(i), "scheme"),
					"ui endpoint on port %d has scheme %q — the gateway proxies http or https only (tcp is for raw ports)", e.Port, e.Scheme)
			}
		}
	}

	// Template-level checkpoints: unique ids, known adapters, hints on
	// explicit objectives (spec 0001 §2, §9).
	seen := map[string]int{}
	for i, cp := range t.Checkpoints {
		idx := strconv.Itoa(i)
		if prev, dup := seen[cp.ID]; dup {
			v.fail(pdr.CodeLabStructure, RuleCheckpointIDDup, doc.Loc("checkpoints", idx, "id"),
				"checkpoint id %q is already used at %s", cp.ID, doc.Loc("checkpoints", strconv.Itoa(prev), "id"))
		} else {
			seen[cp.ID] = i
		}
		v.checkpointRules(doc, c, cp, "baseline", "checkpoints", idx)
	}

	// §8 profiles override envelopes of services that exist.
	for _, pName := range sortedKeys(t.Profiles) {
		for _, svcName := range sortedKeys(t.Profiles[pName].Resources) {
			if _, ok := t.Services[svcName]; !ok {
				v.fail(pdr.CodeLabReference, RuleProfileService, doc.Loc("profiles", pName, "resources", svcName),
					"profile %q sizes service %q, which the template does not declare (services: %s)",
					pName, svcName, joinOrNone(sortedKeys(t.Services)))
			}
		}
	}

	// §9.1 init requests target composed services.
	for _, svcName := range sortedKeys(c.Services) {
		cs := c.Services[svcName]
		if cs.Module == nil || cs.Module.Init == nil {
			continue
		}
		overridden := lookupMap(doc.Value, "services", svcName, "config", "init")["requests"] != nil
		for i, req := range cs.Module.Init.Requests {
			reqLoc := func(field ...string) string {
				ptr := append([]string{"init", "requests", strconv.Itoa(i)}, field...)
				if overridden {
					return doc.Loc(append([]string{"services", svcName, "config"}, ptr...)...)
				}
				return c.Modules[cs.moduleName()].Doc.Loc(ptr...)
			}
			if req.Service != "" {
				if _, ok := t.Services[req.Service]; !ok {
					v.fail(pdr.CodeLabReference, RuleInitService, reqLoc("service"),
						"init request targets service %q, which the template does not declare (services: %s)",
						req.Service, joinOrNone(sortedKeys(t.Services)))
				}
			}
			if req.Auth != nil && req.Auth.Secret != "" && !c.hasSecret(req.Auth.Secret) {
				v.fail(pdr.CodeLabReference, RuleInitAuthSecret, reqLoc("auth", "secret"),
					"init request authenticates with secret %q, which no composed module or the template declares (declared: %s)",
					req.Auth.Secret, c.secretNames())
			}
			// A username carries no colon: curl's --user and HTTP Basic
			// (RFC 7617 §2) split the credentials at the first one, so
			// `admin:tenant` with password `pw` would authenticate as
			// `admin` with password `tenant:pw`.
			// A placeholder's own colon is not one: a reference there is
			// misplaced and reported as such (secret-ref-placement).
			if req.Auth != nil && strings.Contains(secretRef.ReplaceAllString(req.Auth.Username, ""), ":") {
				v.fail(pdr.CodeLabStructure, RuleInitAuthUser, reqLoc("auth", "username"),
					"init request's auth.username carries a colon: curl's --user and HTTP Basic (RFC 7617 §2) split the credentials at the first one, so the username cannot be sent as written (spec 0003 §9.1)")
			}
			// A request's header names are one set of case-insensitive
			// fields: mapping keys are case-sensitive, so `Content-Type`
			// beside `content-type` is the same field declared twice, and
			// the helper would send two values of a single-valued one.
			seen := map[string]string{}
			for _, name := range sortedKeys(req.Headers) {
				// A field name is one token (RFC 9110 §5.1): the helper's curl
				// reads the first colon of a header line as the field's end,
				// so a name with a colon, a space or another separator would
				// send a different header than declared.
				if !wire.ValidFieldName(name) {
					v.fail(pdr.CodeLabStructure, RuleInitHeaderName, reqLoc("headers", name),
						"init request's header name %q is not a legal HTTP field name — one token of letters, digits and !#$%%&'*+-.^_`|~ (RFC 9110 §5.1); curl would read its first colon as the field's end (spec 0003 §9.1)", name)
					continue
				}
				lower := strings.ToLower(name)
				if first, ok := seen[lower]; ok {
					v.fail(pdr.CodeLabStructure, RuleInitHeaderDup, reqLoc("headers", name),
						"init request declares header %q twice (%q and %q): HTTP field names are case-insensitive, one value per field (spec 0003 §9.1)",
						lower, first, name)
					continue
				}
				seen[lower] = name
				// An authored Host is sent as written by the helper's curl, so
				// it is judged by the wire's grammar here — a name or an IP
				// address, a numeric port at most — as the seed and checkpoint
				// paths judge theirs; a value that carries a secret reference
				// is judged at render, once rendered.
				if lower == "host" && !secretRef.MatchString(req.Headers[name]) && !wire.ValidHost(req.Headers[name]) {
					v.fail(pdr.CodeLabStructure, RuleInitHost, reqLoc("headers", name),
						"init request's Host header is not a legal HTTP host: a host name or an IP address with an optional numeric port, 1 to 65535 (RFC 9110 §7.2; spec 0003 §9.1)")
				}
			}
		}
	}

	// §9.1 an init request that targets another service orders the
	// bring-up — the target must run before the owner's init — so a cycle
	// of such targets has no order at all (composition rule).
	deps := InitDependencies(c)
	for _, cycle := range initCycles(deps) {
		owner, target := cycle[0], cycle[1]
		cs := c.Services[owner]
		idx := deps[owner][target]
		ptr := []string{"init", "requests", strconv.Itoa(idx), "service"}
		loc := c.Modules[cs.moduleName()].Doc.Loc(ptr...)
		if lookupMap(doc.Value, "services", owner, "config", "init")["requests"] != nil {
			loc = doc.Loc(append([]string{"services", owner, "config"}, ptr...)...)
		}
		v.fail(pdr.CodeLabComposition, RuleInitCycle, loc,
			"init of service %q targets %q, whose init leads back to it (%s → %s) — no bring-up order can start both; an init may only target services that need nothing from it (spec 0003 §9.1)",
			owner, target, strings.Join(cycle, " → "), owner)
	}
}

// InitDependencies maps each composed service to the other services its
// init requests target (target → index of the first request naming it):
// the bring-up order the engine honors — a target runs before its
// dependants' init (spec 0003 §9.1).
func InitDependencies(c *Composition) map[string]map[string]int {
	deps := map[string]map[string]int{}
	for _, name := range sortedKeys(c.Services) {
		cs := c.Services[name]
		if cs.Module == nil || cs.Module.Init == nil {
			continue
		}
		for i, req := range cs.Module.Init.Requests {
			if req.Service == "" || req.Service == name {
				continue
			}
			if _, ok := c.Services[req.Service]; !ok {
				continue // reported by RuleInitService
			}
			if deps[name] == nil {
				deps[name] = map[string]int{}
			}
			if _, seen := deps[name][req.Service]; !seen {
				deps[name][req.Service] = i
			}
		}
	}
	return deps
}

// initCycles finds every elementary cycle in the dependency graph, each
// once, as the path from its smallest node back around; nodes and edges
// are walked in name order so the report is deterministic.
func initCycles(deps map[string]map[string]int) [][]string {
	var cycles [][]string
	seenCycle := map[string]bool{}
	var walk func(start, node string, path []string, onPath map[string]bool)
	walk = func(start, node string, path []string, onPath map[string]bool) {
		for _, next := range sortedIntKeys(deps[node]) {
			if next == start {
				key := strings.Join(path, "\x00")
				if !seenCycle[key] {
					seenCycle[key] = true
					cycles = append(cycles, append([]string(nil), path...))
				}
				continue
			}
			if onPath[next] || next < start {
				continue // a cycle through a smaller node is reported from there
			}
			onPath[next] = true
			walk(start, next, append(path, next), onPath)
			delete(onPath, next)
		}
	}
	for _, start := range sortedDepKeys(deps) {
		walk(start, start, []string{start}, map[string]bool{start: true})
	}
	return cycles
}

func sortedDepKeys(m map[string]map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedIntKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (cs *composedService) moduleName() string {
	if m := useRef.FindStringSubmatch(cs.Use); m != nil {
		return m[1]
	}
	return ""
}

// walkSecretRefs checks every ${secret:<name>} in the string values under
// value: a reference outside an allowed subtree is misplaced (it would
// never be rendered), and one whose name is not in the composed set is
// unresolved. skip prunes subtrees judged elsewhere; seen deduplicates a
// module composed by several services.
func (v *validation) walkSecretRefs(value any, ptr []string, c *Composition, seen map[string]bool, loc func([]string) string, skip, allowed func([]string) bool) {
	if skip != nil && skip(ptr) {
		return
	}
	switch t := value.(type) {
	case map[string]any:
		for _, k := range sortedKeys(t) {
			kptr := append(append([]string{}, ptr...), k)
			// A key is text too, and no key is ever rendered (an env name, a
			// config key, a param name): a placeholder there is misplaced
			// wherever it sits, so it is judged with the never-allowed
			// predicate, not the value-oriented one.
			v.secretRefsInText(k, kptr, c, seen, loc, keyNeverRendered)
			v.walkSecretRefs(t[k], kptr, c, seen, loc, skip, allowed)
		}
	case []any:
		for i, item := range t {
			v.walkSecretRefs(item, append(append([]string{}, ptr...), strconv.Itoa(i)), c, seen, loc, skip, allowed)
		}
	case string:
		v.secretRefsInText(t, ptr, c, seen, loc, allowed)
	}
}

// initRenderedPlacement is the placement predicate for a module's strings:
// only what create renders. Under config that is an env value, a command
// or args element and a file's content — never a file's path or mode,
// which name the file and would reach the container as text;
// under init a request's path, header values
// and body — never the init image or a request's service, method,
// scheme, auth or until (round 35).
func initRenderedPlacement(ptr []string) bool {
	if len(ptr) >= 2 && ptr[0] == "config" {
		switch ptr[1] {
		case "env", "command", "args":
			return true
		case "files":
			return len(ptr) >= 4 && ptr[3] == "content"
		}
		return false
	}
	return len(ptr) >= 4 && ptr[0] == "init" && ptr[1] == "requests" && (ptr[3] == "path" || ptr[3] == "headers" || ptr[3] == "body")
}

// keyNeverRendered is the placement predicate for mapping keys: create
// renders string values, never the keys that name them.
func keyNeverRendered([]string) bool { return false }

// secretRefsInText judges every ${secret:…} placeholder in one string:
// placement first (allowed), then the name's syntax, then resolution.
func (v *validation) secretRefsInText(t string, ptr []string, c *Composition, seen map[string]bool, loc func([]string) string, allowed func([]string) bool) {
	// An unterminated placeholder (`${secret:token`) is not a reference
	// create could render, and must not reach a plan as text either.
	if strings.Contains(secretRef.ReplaceAllString(t, ""), "${secret:") {
		where := loc(ptr)
		if key := strings.Join(ptr, "/") + "\x00<unterminated>"; !seen[key] {
			seen[key] = true
			if allowed != nil && !allowed(ptr) {
				v.fail(pdr.CodeLabStructure, RuleSecretRefPlace, where,
					"an unterminated ${secret: placeholder is not rendered here — references belong in module config/init strings or an inline service's env/command (spec 0003 §6)")
			} else {
				v.fail(pdr.CodeLabReference, RuleSecretRef, where,
					"unterminated ${secret: placeholder — a reference is written ${secret:<name>} (spec 0003 §6); declared: %s", c.secretNames())
			}
		}
	}
	for _, m := range secretRef.FindAllStringSubmatch(t, -1) {
		where := loc(ptr)
		key := strings.Join(ptr, "/") + "\x00" + m[1] // by field, not by line: flow style packs fields onto one line
		if seen[key] {
			continue
		}
		seen[key] = true
		if allowed != nil && !allowed(ptr) {
			v.fail(pdr.CodeLabStructure, RuleSecretRefPlace, where,
				"${secret:%s} is not rendered here — references belong in module config/init strings or an inline service's env/command (spec 0003 §6); seeds and checkpoints receive secrets through declared grants (Spec 0002 §2)", m[1])
			continue
		}
		if !secretName.MatchString(m[1]) {
			v.fail(pdr.CodeLabReference, RuleSecretRef, where,
				"${secret:%s} is not a valid reference — secret names are lowercase DNS labels (spec 0003 §6); declared: %s", m[1], c.secretNames())
			continue
		}
		if !c.hasSecret(m[1]) {
			v.fail(pdr.CodeLabReference, RuleSecretRef, where,
				"${secret:%s} names no declared secret (declared: %s)", m[1], c.secretNames())
		}
	}
}

// mergedLoc locates a pointer into a service's merged module: the
// template's config: override when it wrote that value, else the module
// file (spec 0003 §11 rule 2 — maps merge, arrays and scalars replace).
func (v *validation) mergedLoc(cs *composedService, cm *composedModule, ptr []string) string {
	// A resolved asset's text is in no document: it is in the asset, and
	// that is the file an author can fix.
	if loc, ok := v.assetLoc[cs.Name+"\x00"+strings.Join(ptr, "/")]; ok {
		return loc
	}
	if len(ptr) > 0 {
		var over []string
		switch ptr[0] {
		case "config":
			over = append([]string{"services", cs.Name, "config"}, ptr[1:]...)
		case "init":
			over = append([]string{"services", cs.Name, "config", "init"}, ptr[1:]...)
		}
		if over != nil {
			if got, ok := lookupValue(v.doc.Value, over); ok {
				if want, ok := lookupValue(cs.Merged, ptr); ok && fmt.Sprint(got) == fmt.Sprint(want) {
					return v.doc.Loc(over...)
				}
			}
		}
	}
	if cm != nil {
		return cm.Doc.Loc(ptr...)
	}
	return v.doc.Loc("services", cs.Name)
}

// lookupValue walks maps and sequences by pointer tokens.
func lookupValue(value any, ptr []string) (any, bool) {
	for _, tok := range ptr {
		switch t := value.(type) {
		case map[string]any:
			next, ok := t[tok]
			if !ok {
				return nil, false
			}
			value = next
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(t) {
				return nil, false
			}
			value = t[i]
		default:
			return nil, false
		}
	}
	return value, true
}

// execGrants checks exec `secrets:` grants against the composed set.
func (v *validation) execGrants(doc *Document, c *Composition, grants []string, ptr ...string) {
	for j, name := range grants {
		if !c.hasSecret(name) {
			v.fail(pdr.CodeLabReference, RuleExecSecretGrant, doc.Loc(append(ptr, strconv.Itoa(j))...),
				"exec secret grant %q names no declared secret (declared: %s)", name, c.secretNames())
		}
	}
}

// checkpointRules applies the per-checkpoint rules shared by template-level
// and step-inline checkpoints. defaultClass is the location default
// (spec 0001 §1). Returns the resolved class.
func (v *validation) checkpointRules(doc *Document, c *Composition, cp Checkpoint, defaultClass string, ptr ...string) string {
	class := cp.Class
	if class == "" {
		class = defaultClass
	}
	if class == "objective" && strings.TrimSpace(cp.Hint) == "" {
		v.fail(pdr.CodeLabStructure, RuleObjectiveHint, doc.Loc(append(ptr, "id")...),
			"objective checkpoint %q has no hint — hints are the teaching assistant (spec 0001 §2)", cp.ID)
	}
	if c == nil {
		return class
	}
	if v.retiredAdapter(doc, cp.Adapter, append(ptr, "adapter")...) {
		return class
	}
	if !c.adapterKnown(cp.Adapter) {
		v.fail(pdr.CodeLabReference, RuleAdapterUnknown, doc.Loc(append(ptr, "adapter")...),
			"adapter %q is neither built-in (%s) nor a composed module's alias (%s)",
			cp.Adapter, joinOrNone(sortedKeys(builtinAdapters)), joinOrNone(sortedKeys(c.Adapters)))
	}
	if cp.Adapter == "attest" {
		// An attest checkpoint's params are exactly a non-empty prompt, and
		// it expects nothing (spec 0001 §3): a typo or an empty prompt would
		// present generic self-confirmation of a condition never shown.
		for _, k := range sortedKeys(cp.Params) {
			if k != "prompt" {
				v.fail(pdr.CodeLabStructure, RuleAttestParams, doc.Loc(append(append([]string{}, ptr...), "params", k)...),
					"attest checkpoint %s: params.%s is not a parameter the attest adapter reads — prompt only (spec 0001 §3)", cp.ID, k)
			}
		}
		if p, isString := cp.Params["prompt"].(string); !isString || strings.TrimSpace(p) == "" {
			at := append(append([]string{}, ptr...), "params", "prompt")
			if _, has := cp.Params["prompt"]; !has {
				at = append(append([]string{}, ptr...), "adapter")
			}
			v.fail(pdr.CodeLabStructure, RuleAttestParams, doc.Loc(at...),
				"attest checkpoint %s: params.prompt must be a non-empty string naming what the human confirms (spec 0001 §3)", cp.ID)
		}
		for _, k := range sortedKeys(cp.Expect) {
			v.fail(pdr.CodeLabStructure, RuleAttestParams, doc.Loc(append(append([]string{}, ptr...), "expect", k)...),
				"attest checkpoint %s: expect.%s — the attest adapter judges by the human's confirmation alone and expects nothing (spec 0001 §3)", cp.ID, k)
		}
	}
	if cp.Adapter == "exec" {
		v.execParamRules(doc, cp.Params, "exec checkpoint "+cp.ID, append(append([]string{}, ptr...), "params")...)
		if grants, ok := cp.Params["secrets"].([]any); ok {
			names := make([]string, 0, len(grants))
			for _, g := range grants {
				names = append(names, fmt.Sprint(g))
			}
			v.execGrants(doc, c, names, append(ptr, "params", "secrets")...)
		}
	}
	// A playbook's inline checkpoint is not rendered by create: a
	// ${secret:…} placeholder in its params or expect is misplaced
	// (checkpoints receive secrets through declared grants, Spec 0002 §2).
	// Template-level checkpoints are covered by the template walk.
	return class
}

// execSpecKeys are the fields an exec spec carries (spec 0001 §3, Spec
// 0002 §2): image, args, env, secrets, limits.
var execSpecKeys = []string{"args", "env", "image", "limits", "secrets"}

// execParamRules refuses a key an exec checkpoint's params do not carry:
// the engine reads image, args, env, secrets and limits and would skip
// anything else — a typo such as `arg` or `environment` — pulling and
// running the extension without the authored configuration.
// The checkpoint schema leaves the params
// object open (frozen), so the lint carries the rule; a seed's
// `generator.exec` and a module alias's `exec` are closed by the template
// schema already.
func (v *validation) execParamRules(doc *Document, params map[string]any, what string, ptr ...string) {
	for _, k := range sortedKeys(params) {
		if !slices.Contains(execSpecKeys, k) {
			v.fail(pdr.CodeLabStructure, RuleExecParams, doc.Loc(append(append([]string{}, ptr...), k)...),
				"%s: params.%s is not a field of an exec spec — image, args, env, secrets, limits (spec 0001 §3, Spec 0002 §2); the engine would skip it and run the extension without it", what, k)
		}
	}
}

// playbooks loads and checks every playbooks/*.yaml (spec 0001 §9).
func (v *validation) playbooks(dir string, c *Composition) {
	pbDir := filepath.Join(dir, "playbooks")
	entries, err := os.ReadDir(pbDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return // no playbooks is legal (Manual §11's minimal lab has none)
		}
		v.fail(pdr.CodeLabUnreadable, RuleUnreadable, filepath.ToSlash(filepath.Join(v.opts.displayDir(), "playbooks")),
			"cannot read the playbooks directory: %v", err)
		return
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && (strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	templateIDs := map[string]bool{}
	templateObjectives := map[string]bool{}
	services := map[string]bool{}
	seeds := map[string]bool{}
	if v.template != nil {
		for _, cp := range v.template.Checkpoints {
			templateIDs[cp.ID] = true
			if cp.Class == "objective" {
				templateObjectives[cp.ID] = true
			}
		}
		for s := range v.template.Services {
			services[s] = true
		}
		for s := range v.template.Seeds {
			seeds[s] = true
		}
	}
	pbNames := map[string]string{}
	inlineIDs := map[string]string{} // inline checkpoint id → where it was declared, across every playbook
	never := func([]string) bool { return false }
	for _, name := range names {
		display := path.Join(filepath.ToSlash(v.opts.displayDir()), "playbooks", name)
		doc, err := LoadDocument(os.DirFS(pbDir), name, display)
		if err != nil {
			v.failErr(RuleUnreadable, err)
			continue
		}
		if !v.schemaCheck(doc, KindPlaybook) {
			continue
		}
		var pb Playbook
		if err := doc.Decode(&pb); err != nil {
			v.fail(pdr.CodeLabSchema, RuleSchema, decodeLoc(doc, err), "cannot decode playbook: %v", err)
			continue
		}
		v.res.Playbooks = append(v.res.Playbooks, &LoadedPlaybook{Doc: doc, Playbook: &pb})
		if prev, dup := pbNames[pb.Metadata.Name]; dup {
			v.fail(pdr.CodeLabStructure, RulePlaybookNameDup, doc.Loc("metadata", "name"),
				"playbook name %q is already used by %s", pb.Metadata.Name, prev)
		} else {
			pbNames[pb.Metadata.Name] = doc.Path
		}
		if v.template == nil {
			continue // shape checked; references need a decodable template
		}
		// Nothing in a playbook is rendered by create: a ${secret:…}
		// placeholder anywhere in it — a title, a step body, an inline
		// checkpoint's params, expect, hint, or evidence — is misplaced
		// (checkpoints receive secrets through declared grants, Spec 0002
		// §2), and none may reach a plan.
		if c != nil {
			v.walkSecretRefs(doc.Value, nil, c, map[string]bool{}, func(p []string) string { return doc.Loc(p...) }, nil, never)
		}
		v.playbookRules(doc, &pb, c, templateIDs, templateObjectives, services, seeds, inlineIDs)
	}
}

// playbookRules checks one playbook. inlineIDs is shared across the
// template's playbooks: checkpoints are flattened per instance and
// addressed by id (API §7), so an inline id is unique template-wide, not
// per file.
func (v *validation) playbookRules(doc *Document, pb *Playbook, c *Composition, templateIDs, templateObjectives, services, seeds map[string]bool, inlineIDs map[string]string) {
	stepIDs := map[string]int{}
	objectives := 0
	for i, step := range pb.Steps {
		idx := strconv.Itoa(i)
		if prev, dup := stepIDs[step.ID]; dup {
			v.fail(pdr.CodeLabStructure, RuleStepIDDup, doc.Loc("steps", idx, "id"),
				"step id %q is already used at %s", step.ID, doc.Loc("steps", strconv.Itoa(prev), "id"))
		} else {
			stepIDs[step.ID] = i
		}
		if ctx := step.Context; ctx != "" && ctx != "overview" && !services[ctx] {
			v.fail(pdr.CodeLabReference, RuleContext, doc.Loc("steps", idx, "context"),
				"context %q names no template service (services: %s, or overview)", ctx, joinOrNone(sortedKeys(services)))
		}
		for j, a := range step.Actions {
			jdx := strconv.Itoa(j)
			if a.Seed != "" && !seeds[a.Seed] {
				v.fail(pdr.CodeLabReference, RuleSeedAction, doc.Loc("steps", idx, "actions", jdx, "seed"),
					"seed %q is not declared by the template (seeds: %s)", a.Seed, joinOrNone(sortedKeys(seeds)))
			}
			if a.Reveal != "" && (c == nil || !c.hasSecret(a.Reveal)) {
				declared := "none"
				if c != nil {
					declared = c.secretNames()
				}
				v.fail(pdr.CodeLabReference, RuleReveal, doc.Loc("steps", idx, "actions", jdx, "reveal"),
					"reveal %q names no declared secret (declared: %s)", a.Reveal, declared)
			}
		}
		cp := step.Checkpoint
		if cp == nil {
			continue
		}
		if cp.Ref != "" {
			if !templateIDs[cp.Ref] {
				v.fail(pdr.CodeLabReference, RuleCheckpointRef, doc.Loc("steps", idx, "checkpoint", "ref"),
					"checkpoint ref %q resolves to no template-level checkpoint (declared: %s)", cp.Ref, joinOrNone(sortedKeys(templateIDs)))
			} else if templateObjectives[cp.Ref] {
				objectives++ // a shared checkpoint declared objective counts where it is used
			}
			continue
		}
		if templateIDs[cp.ID] {
			v.fail(pdr.CodeLabStructure, RuleCheckpointIDDup, doc.Loc("steps", idx, "checkpoint", "id"),
				"inline checkpoint id %q collides with a template-level checkpoint — reference it with {ref: %s} or rename", cp.ID, cp.ID)
		} else if prev, dup := inlineIDs[cp.ID]; dup {
			v.fail(pdr.CodeLabStructure, RuleCheckpointIDDup, doc.Loc("steps", idx, "checkpoint", "id"),
				"checkpoint id %q is already used at %s — ids are unique across a template's playbooks", cp.ID, prev)
		} else {
			inlineIDs[cp.ID] = doc.Loc("steps", idx, "checkpoint", "id")
		}
		if class := v.checkpointRules(doc, c, *cp, "objective", "steps", idx, "checkpoint"); class == "objective" {
			objectives++
		}
	}
	if objectives == 0 {
		v.warn(pdr.CodePlaybookNoObjectives, RuleNoObjectives, doc.Loc("metadata", "name"),
			"playbook %q has zero objective checkpoints — nothing to verify: is this a playbook or a document?", pb.Metadata.Name)
	}
	if len(pb.Metadata.Modes) == 1 && pb.Metadata.Modes[0] == "repro" && len(pb.Steps) > 0 && !pb.Steps[0].Auto {
		v.fail(pdr.CodeLabStructure, RuleReproAuto, doc.Loc("steps", "0", "id"),
			"a repro-only playbook must open with an auto step — the first non-auto step is the breakpoint (spec 0001 §6)")
	}
}

// setMergedFileContent writes a resolved asset into the merged module
// tree, where §11.3's secret pass reads it. A tree that does not hold
// the file is left alone: the pass has nothing to judge there either,
// and inventing a node would give a finding a location no author wrote.
func setMergedFileContent(merged map[string]any, i int, content string) {
	cfg, ok := merged["config"].(map[string]any)
	if !ok {
		return
	}
	files, ok := cfg["files"].([]any)
	if !ok || i < 0 || i >= len(files) {
		return
	}
	if entry, ok := files[i].(map[string]any); ok {
		entry["content"] = content
	}
}

// maxAssetBytes bounds one template asset. Assets are configuration a
// lab ships — a dashboard, a rules file, a pipeline definition — not payloads:
// they are rendered into memory, carried into the container by the
// engine's copy-in, and kept in every delivery snapshot.
const maxAssetBytes = 256 << 10

// readAsset reads a template asset named by a file's `source:` (spec
// 0003 §9, plan S8). The path is relative to the template directory and
// stays inside it: an absolute path, a `..` element or a symlink would
// read something the template does not ship, and a delivery snapshot —
// which copies the template's own tree — would not carry it.
func readAsset(dir, source string) (string, error) {
	clean := path.Clean(source)
	if source == "" || clean != strings.TrimSuffix(source, "/") || !fs.ValidPath(clean) || path.IsAbs(clean) || strings.Contains(source, "\\") {
		return "", fmt.Errorf("source %q is not a clean relative path inside the template", source)
	}
	// Every component below the template directory, and not the leaf
	// alone: `os.Lstat` on the whole path reports the leaf, and the
	// operating system follows an intermediate link when it opens the
	// file — so `assets/external -> /etc` with `source:
	// assets/external/passwd` read a file outside the template while the
	// leaf looked like an ordinary one.
	full := dir
	info := os.FileInfo(nil)
	for _, part := range strings.Split(clean, "/") {
		full = filepath.Join(full, part)
		i, err := os.Lstat(full)
		if err != nil {
			return "", fmt.Errorf("source %s: %v", clean, err)
		}
		if i.Mode()&os.ModeSymlink != 0 {
			where := clean
			if rel, err := filepath.Rel(dir, full); err == nil {
				where = filepath.ToSlash(rel)
			}
			return "", fmt.Errorf("source %s is a symbolic link; an asset is a file the template ships", where)
		}
		info = i
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("source %s is not a regular file", clean)
	}
	if info.Size() > maxAssetBytes {
		return "", fmt.Errorf("source %s is %d bytes; an asset is at most %d", clean, info.Size(), maxAssetBytes)
	}
	raw, err := os.ReadFile(full)
	if err != nil {
		return "", fmt.Errorf("source %s: %v", clean, err)
	}
	if !utf8.Valid(raw) {
		return "", fmt.Errorf("source %s is not text; a file's content is rendered as text", clean)
	}
	return string(raw), nil
}
