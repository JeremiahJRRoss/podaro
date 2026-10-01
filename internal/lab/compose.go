// SPDX-License-Identifier: AGPL-3.0-only

package lab

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"regexp"
	"sort"
	"strconv"

	"gopkg.in/yaml.v3"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

var (
	useRef = regexp.MustCompile(`^modules/([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)@([A-Za-z0-9][A-Za-z0-9.-]*)$`)
	// secretRef matches the complete placeholder syntax; the captured name
	// is validated separately (a malformed name is a finding, never a
	// token that slips through into a plan).
	secretRef  = regexp.MustCompile(`\$\{secret:([^}]*)\}`)
	secretName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
)

// composedModule is one module the template composes (once per name, even
// when several services use it).
type composedModule struct {
	Name     string
	Version  string
	Doc      *Document
	Module   *Module
	Services []string
}

// composedService is a service with its effective module (config merged
// per spec 0003 §11 rule 2) when it uses one.
type composedService struct {
	Name   string
	Svc    Service
	Use    string
	Module *Module        // effective (merged) module; nil for inline services
	Merged map[string]any // the merged generic module value (schema re-validated)
}

type eulaDecl struct {
	EULA       EULA
	RequiredBy []string
	declaredBy string // the first service to declare it; later ones must match
}

type aliasOwner struct {
	Module string
	Exec   ExecSpec
}

// Composition is what validate resolves and plan renders: services with
// their effective modules, and the composed sets of secrets, EULAs, and
// alias names (spec 0003 §11).
type Composition struct {
	Services   map[string]*composedService
	Modules    map[string]*composedModule
	Secrets    map[string][]string // name → declared by (sorted: "template" and module names)
	Kinds      map[string]string   // secret name → kind
	kindOwner  map[string]string   // secret name → who declared the kind first
	EULAs      map[string]*eulaDecl
	Adapters   map[string]aliasOwner
	Generators map[string]aliasOwner
}

// compose resolves every service. Findings go to v; a nil return means the
// composition could not be built at all.
func (v *validation) compose() *Composition {
	// An unusable module library is one PDR-E100 at its path whether or
	// not the template references a module (the flag was given; it is
	// wrong).
	var le *LibraryError
	if err := v.library.Check(); errors.As(err, &le) {
		v.libraryFailed = true
		v.fail(pdr.CodeLabUnreadable, RuleUnreadable, le.Dir, "cannot read the module library: %v", le.Err)
	}
	c := &Composition{
		Services:   map[string]*composedService{},
		Modules:    map[string]*composedModule{},
		Secrets:    map[string][]string{},
		Kinds:      map[string]string{},
		kindOwner:  map[string]string{},
		EULAs:      map[string]*eulaDecl{},
		Adapters:   map[string]aliasOwner{},
		Generators: map[string]aliasOwner{},
	}
	t := v.template
	for name, kind := range t.Secrets {
		c.Secrets[name] = append(c.Secrets[name], "template")
		c.Kinds[name] = kindOrDefault(kind.Kind)
		c.kindOwner[name] = "template"
	}
	services := sortedKeys(t.Services)
	for _, svcName := range services {
		svc := t.Services[svcName]
		cs := &composedService{Name: svcName, Svc: svc, Use: svc.Use}
		c.Services[svcName] = cs
		if svc.Use == "" {
			if svc.EULA != nil {
				if by, conflict := c.addEULA(*svc.EULA, svcName); conflict {
					v.fail(pdr.CodeLabComposition, RuleEULAConflict, v.doc.Loc("services", svcName, "eula"),
						"EULA %q is declared here differently from service %s — one EULA id is one set of terms: name, url, and env must match (spec 0003 §7)",
						svc.EULA.ID, by)
				}
			}
			continue
		}
		m := useRef.FindStringSubmatch(svc.Use)
		if m == nil { // the schema pattern makes this unreachable; keep the guard
			v.fail(pdr.CodeLabReference, RuleModuleRef, v.doc.Loc("services", svcName, "use"),
				"%s: unparseable module reference", svc.Use)
			continue
		}
		modName, modVersion := m[1], m[2]
		if v.retiredModule(modName, svc.Use, "services", svcName, "use") {
			continue
		}
		cm, ok := c.Modules[modName]
		if !ok {
			cm = v.loadModule(c, modName)
			if cm == nil {
				continue
			}
			c.Modules[modName] = cm
		}
		cm.Services = append(cm.Services, svcName)
		if cm.Module.Metadata.Name != modName || cm.Module.Metadata.Version != modVersion {
			v.fail(pdr.CodeLabComposition, RuleModuleMeta, v.doc.Loc("services", svcName, "use"),
				"%s does not match the installed module's metadata %s@%s",
				svc.Use, cm.Module.Metadata.Name, cm.Module.Metadata.Version)
		}
		if eula := moduleEULA(cm.Module); eula != nil {
			if by, conflict := c.addEULA(*eula, svcName); conflict {
				v.fail(pdr.CodeLabComposition, RuleEULAConflict, v.doc.Loc("services", svcName, "use"),
					"EULA %q as declared by modules/%s differs from service %s's declaration — one EULA id is one set of terms: name, url, and env must match (spec 0003 §7)",
					eula.ID, cm.Name, by)
			}
		}
		merged, effective := v.mergeConfig(cs, cm)
		cs.Merged = merged
		cs.Module = effective
	}
	for _, name := range sortedKeys(c.Secrets) {
		sort.Strings(c.Secrets[name])
	}
	return c
}

// loadModule reads, schema-validates, and alias-checks one module file.
func (v *validation) loadModule(c *Composition, modName string) *composedModule {
	present, err := v.library.Has(modName)
	var le *LibraryError
	if errors.As(err, &le) {
		// The library itself is unreadable: one PDR-E100 at its root, not
		// a misleading "not installed" per module.
		if !v.libraryFailed {
			v.libraryFailed = true
			v.fail(pdr.CodeLabUnreadable, RuleUnreadable, le.Dir, "cannot read the module library: %v", le.Err)
		}
		return nil
	}
	if err != nil {
		v.fail(pdr.CodeLabUnreadable, RuleUnreadable, path.Join(v.library.display, modName, "module.yaml"),
			"cannot read the installed module: %v", err)
		return nil
	}
	if !present {
		v.fail(pdr.CodeLabReference, RuleModuleRef, v.useLoc(modName),
			"modules/%s is not in the installed module library (installed: %s)", modName, joinOrNone(v.library.Names()))
		return nil
	}
	doc, err := v.library.Load(modName)
	if err != nil {
		v.failErr(RuleUnreadable, err)
		return nil
	}
	if !v.schemaCheck(doc, KindModule) {
		return nil
	}
	var mod Module
	if err := doc.Decode(&mod); err != nil {
		v.fail(pdr.CodeLabSchema, RuleSchema, decodeLoc(doc, err), "cannot decode module: %v", err)
		return nil
	}
	cm := &composedModule{Name: modName, Version: mod.Metadata.Version, Doc: doc, Module: &mod}
	v.moduleAliasSanity(doc, &mod, modName)
	// Composition scope (spec 0003 §11 rule 6, "or each other"): two
	// different modules may not claim one alias name.
	seen := map[string]bool{} // one namespace across both alias kinds
	for _, kind := range []struct {
		key    string
		list   []Alias
		owners map[string]aliasOwner
	}{
		{"adapters", mod.Adapters, c.Adapters},
		{"generators", mod.Generators, c.Generators},
	} {
		for i, a := range kind.list {
			if seen[a.Name] {
				continue // the intra-module duplicate (either kind) is already reported
			}
			seen[a.Name] = true
			// One namespace (spec 0003 §11 rule 6): an adapter alias and a
			// generator alias collide across modules just as two adapters do.
			if owner, taken := c.Adapters[a.Name]; taken && owner.Module != modName {
				v.fail(pdr.CodeLabComposition, RuleAliasCollision, doc.Loc(kind.key, strconv.Itoa(i), "name"),
					"%s alias %q is already an adapter alias of module %s — aliases share one namespace", kind.key, a.Name, owner.Module)
				continue
			}
			if owner, taken := c.Generators[a.Name]; taken && owner.Module != modName {
				v.fail(pdr.CodeLabComposition, RuleAliasCollision, doc.Loc(kind.key, strconv.Itoa(i), "name"),
					"%s alias %q is already a generator alias of module %s — aliases share one namespace", kind.key, a.Name, owner.Module)
				continue
			}
			kind.owners[a.Name] = aliasOwner{Module: modName, Exec: a.Exec}
		}
	}
	for _, name := range sortedKeys(mod.Secrets) {
		s := mod.Secrets[name]
		c.Secrets[name] = append(c.Secrets[name], modName)
		kind := kindOrDefault(s.Kind)
		prev, shared := c.Kinds[name]
		if !shared {
			c.Kinds[name] = kind
			c.kindOwner[name] = modName
			continue
		}
		if prev == kind {
			continue
		}
		// One instance-scoped secret, two generation policies: the
		// template author reconciles it (spec 0003 §6 — shared by name
		// means shared by kind).
		// "here" is always the kind written at the finding's location.
		loc, here, there, other := doc.Loc("secrets", name), kind, prev, "modules/"+c.kindOwner[name]
		if c.kindOwner[name] == "template" {
			loc, here, there, other = v.doc.Loc("secrets", name), prev, kind, "modules/"+modName
		}
		v.fail(pdr.CodeLabComposition, RuleSecretKind, loc,
			"secret %q is declared as kind %s here but as kind %s by %s — a shared secret has one kind",
			name, here, there, other)
	}
	return cm
}

// useLoc finds the first service line that references a module name.
func (v *validation) useLoc(modName string) string {
	for _, svcName := range sortedKeys(v.template.Services) {
		if m := useRef.FindStringSubmatch(v.template.Services[svcName].Use); m != nil && m[1] == modName {
			return v.doc.Loc("services", svcName, "use")
		}
	}
	return v.doc.Loc("services")
}

// mergeConfig applies the service's config: block onto the module
// (maps merge per key, arrays and scalars replace — spec 0003 §11 rule 2),
// re-validates the result against the module schema, and returns the
// effective module.
func (v *validation) mergeConfig(cs *composedService, cm *composedModule) (map[string]any, *Module) {
	base, _ := cm.Doc.Value.(map[string]any)
	merged := deepMerge(base, nil)
	override := lookupMap(v.doc.Value, "services", cs.Name, "config")
	if len(override) == 0 {
		return merged, cm.Module
	}
	configPart := map[string]any{}
	for k, val := range override {
		if k == "init" {
			// Maps merge; anything else replaces (spec 0003 §11 rule 2) and
			// then fails the module schema, which is the honest outcome for
			// a scalar, list, or null where an init block belongs.
			if initOver, ok := val.(map[string]any); ok {
				initBase, _ := merged["init"].(map[string]any)
				merged["init"] = deepMerge(initBase, initOver)
			} else {
				merged["init"] = val
			}
			continue
		}
		configPart[k] = val
	}
	if len(configPart) > 0 {
		configBase, _ := merged["config"].(map[string]any)
		merged["config"] = deepMerge(configBase, configPart)
	}
	violations, err := schemaViolations(schemaFor(KindModule, merged), merged)
	if err != nil {
		v.fail(pdr.CodeLabSchema, RuleSchema, v.doc.Loc("services", cs.Name, "config"), "schema unavailable: %v", err)
		return merged, cm.Module
	}
	if len(violations) > 0 {
		for _, sv := range violations {
			v.fail(pdr.CodeLabComposition, RuleConfigMerge, v.doc.Loc("services", cs.Name, "config"),
				"config merged onto modules/%s is not a valid module: %s: %s", cm.Name, pointerString(sv.Pointer), sv.Message)
		}
		return merged, cm.Module
	}
	raw, err := yaml.Marshal(merged)
	if err != nil {
		return merged, cm.Module
	}
	var effective Module
	if err := yaml.Unmarshal(raw, &effective); err != nil {
		v.fail(pdr.CodeLabComposition, RuleConfigMerge, v.doc.Loc("services", cs.Name, "config"),
			"config merged onto modules/%s cannot be decoded: %v", cm.Name, err)
		return merged, cm.Module
	}
	return merged, &effective
}

// addEULA records that svc requires EULA e. The first declaration of an
// id is kept; a later one must be identical (name, url, env) — a shared
// id is one set of terms — else the first declarer is returned with
// conflict=true and the caller reports it.
func (c *Composition) addEULA(e EULA, svc string) (declaredBy string, conflict bool) {
	d, ok := c.EULAs[e.ID]
	if !ok {
		d = &eulaDecl{EULA: e, declaredBy: svc}
		c.EULAs[e.ID] = d
	} else if e.Name != d.EULA.Name || e.URL != d.EULA.URL || !maps.Equal(e.Env, d.EULA.Env) {
		conflict = true
	}
	d.RequiredBy = append(d.RequiredBy, svc)
	sort.Strings(d.RequiredBy)
	return d.declaredBy, conflict
}

func moduleEULA(m *Module) *EULA {
	if m.License == nil {
		return nil
	}
	return m.License.EULA
}

// deepMerge returns base with over applied: maps merge per key, arrays and
// scalars replace. Neither input is modified.
func deepMerge(base, over map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		if bm, ok := out[k].(map[string]any); ok {
			if om, ok := v.(map[string]any); ok {
				out[k] = deepMerge(bm, om)
				continue
			}
		}
		out[k] = v
	}
	return out
}

// lookupMap walks string keys through nested maps.
func lookupMap(v any, keys ...string) map[string]any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	m, _ := v.(map[string]any)
	return m
}

func kindOrDefault(k string) string {
	if k == "" {
		return "password"
	}
	return k
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func pointerString(tokens []string) string {
	if len(tokens) == 0 {
		return "(root)"
	}
	s := ""
	for _, t := range tokens {
		s += "/" + t
	}
	return s
}

func joinOrNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	s := ""
	for i, it := range items {
		if i > 0 {
			s += ", "
		}
		s += it
	}
	return s
}

// secretNames renders the composed secret set for messages.
func (c *Composition) secretNames() string {
	return joinOrNone(sortedKeys(c.Secrets))
}

func (c *Composition) hasSecret(name string) bool {
	_, ok := c.Secrets[name]
	return ok
}

func (c *Composition) adapterKnown(name string) bool {
	if builtinAdapters[name] {
		return true
	}
	_, ok := c.Adapters[name]
	return ok
}

func (c *Composition) generatorKnown(name string) bool {
	if builtinGenerators[name] {
		return true
	}
	_, ok := c.Generators[name]
	return ok
}

func (c *Composition) eulaIDs() []string {
	return sortedKeys(c.EULAs)
}

func describeUse(svc Service) string {
	if svc.Use != "" {
		return svc.Use
	}
	return fmt.Sprintf("inline image %s", svc.Image)
}

// moduleAliasSanity applies the per-module half of spec 0003 §11 rule 6 —
// no duplicate alias names within one module, no shadowing of the
// built-in registries — for one module file, composed by a template or
// not. The schema's arrays cannot enforce either.
func (v *validation) moduleAliasSanity(doc *Document, mod *Module, modName string) {
	seen := map[string]string{} // alias name → the kind that declared it first; one namespace
	for _, kind := range []struct {
		key  string
		list []Alias
	}{
		{"adapters", mod.Adapters},
		{"generators", mod.Generators},
	} {
		for i, a := range kind.list {
			loc := doc.Loc(kind.key, strconv.Itoa(i), "name")
			if first, dup := seen[a.Name]; dup {
				if first == kind.key {
					v.fail(pdr.CodeLabComposition, RuleAliasDuplicate, loc,
						"%s alias %q is declared twice in module %s", kind.key, a.Name, modName)
				} else {
					v.fail(pdr.CodeLabComposition, RuleAliasDuplicate, loc,
						"%s alias %q is already a %s alias of module %s — aliases share one namespace", kind.key, a.Name, first, modName)
				}
				continue
			}
			seen[a.Name] = kind.key
			switch {
			case builtinAdapters[a.Name]:
				v.fail(pdr.CodeLabComposition, RuleAliasShadow, loc,
					"%s alias %q shadows the built-in adapter of that name", kind.key, a.Name)
			case builtinGenerators[a.Name]:
				v.fail(pdr.CodeLabComposition, RuleAliasShadow, loc,
					"%s alias %q shadows the built-in generator of that name", kind.key, a.Name)
			}
		}
	}
}

// ValidateLibrary checks every module of a library on its own: schema
// shape, metadata matching its directory, and the per-module alias rules
// that composition would otherwise enforce only for modules some template
// uses. Findings are sorted by file then line; none means the library is
// sound.
func ValidateLibrary(lib *Library) []Finding {
	v := &validation{library: lib, res: &Result{}}
	var le *LibraryError
	if err := lib.Check(); errors.As(err, &le) {
		// No findings would have meant "sound"; an unreadable root is the
		// opposite, reported once at its path.
		v.fail(pdr.CodeLabUnreadable, RuleUnreadable, le.Dir, "cannot read the module library: %v", le.Err)
		return v.res.Findings
	}
	entries, err := fs.ReadDir(lib.fsys, ".")
	if err != nil {
		v.fail(pdr.CodeLabUnreadable, RuleUnreadable, lib.display, "cannot read the module library: %v", err)
		return v.res.Findings
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		present, err := lib.Has(e.Name())
		if err != nil {
			v.fail(pdr.CodeLabUnreadable, RuleUnreadable, path.Join(lib.display, e.Name(), "module.yaml"),
				"cannot read the installed module: %v", err)
			continue
		}
		if present {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		doc, err := lib.Load(name)
		if err != nil {
			v.failErr(RuleUnreadable, err)
			continue
		}
		if !v.schemaCheck(doc, KindModule) {
			continue
		}
		var mod Module
		if err := doc.Decode(&mod); err != nil {
			v.fail(pdr.CodeLabSchema, RuleSchema, decodeLoc(doc, err), "cannot decode module: %v", err)
			continue
		}
		if mod.Metadata.Name != name {
			v.fail(pdr.CodeLabComposition, RuleModuleMeta, doc.Loc("metadata", "name"),
				"module directory %s declares metadata.name %q — use: references resolve by directory", name, mod.Metadata.Name)
		}
		v.moduleAliasSanity(doc, &mod, name)
	}
	sort.SliceStable(v.res.Findings, func(i, j int) bool { return findingLess(v.res.Findings[i], v.res.Findings[j]) })
	return v.res.Findings
}
