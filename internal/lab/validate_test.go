// SPDX-License-Identifier: AGPL-3.0-only

package lab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// The broken fixture set (plan S3 acceptance): every rule has at least one
// fixture that trips it with the documented code at the expected file:line.
var brokenFixtures = []struct {
	dir      string
	testLib  bool     // resolve modules against testdata/modules
	code     string   // leading envelope code
	rules    []string // every rule expected among the findings
	locs     []string // file:line suffixes expected among the findings
	warnRule string   // for valid fixtures that must warn
}{
	{dir: "manifest-unreadable", code: pdr.CodeLabUnreadable, rules: []string{RuleUnreadable}, locs: []string{"playbooks/bad.yaml:3"}},
	{dir: "schema", code: pdr.CodeLabSchema, rules: []string{RuleSchema}, locs: []string{"lab.yaml:4"}},
	{dir: "module-ref", code: pdr.CodeLabReference, rules: []string{RuleModuleRef}, locs: []string{"lab.yaml:6"}},
	{dir: "module-meta", testLib: true, code: pdr.CodeLabComposition, rules: []string{RuleModuleMeta}, locs: []string{"lab.yaml:6"}},
	{dir: "config-merge", code: pdr.CodeLabComposition, rules: []string{RuleConfigMerge}, locs: []string{"lab.yaml:8"}},
	{dir: "config-merge-init", code: pdr.CodeLabComposition, rules: []string{RuleConfigMerge}, locs: []string{"lab.yaml:8"}},
	// An exec checkpoint's image is digest-pinned: the checkpoint schema's exec conditional holds the image under params.
	{dir: "nested-exec-image", code: pdr.CodeLabSchema, rules: []string{RuleSchema}, locs: []string{"lab.yaml:11"}},
	// A retired adapter and a retired module, named as the retirement manifest spells them, in a v1alpha1
	// document: both refused as retired (PDR-E106), neither as an unknown name (spec 0001 §11, spec 0003 §13).
	{dir: "retired-adapter", code: pdr.CodeLabRetired, rules: []string{RuleRetired}, locs: []string{"lab.yaml:10", "lab.yaml:13"}},
	{dir: "secret-ref", code: pdr.CodeLabReference, rules: []string{RuleSecretRef}, locs: []string{"lab.yaml:10"}},
	{dir: "secret-ref-placement", code: pdr.CodeLabStructure, rules: []string{RuleSecretRefPlace}, locs: []string{"lab.yaml:11", "lab.yaml:15"}},
	// A reference under init that create never renders — here an auth username — is misplaced.
	{dir: "secret-ref-init-place", testLib: true, code: pdr.CodeLabStructure, rules: []string{RuleSecretRefPlace}, locs: []string{"init-ref-place/module.yaml:14"}},
	// A reference in a config file's path — the file's name, never rendered — is misplaced; the same line's content reference is fine.
	{dir: "secret-ref-file-path", testLib: true, code: pdr.CodeLabStructure, rules: []string{RuleSecretRefPlace}, locs: []string{"file-ref-place/module.yaml:13"}},
	{dir: "secret-kind-conflict", code: pdr.CodeLabComposition, rules: []string{RuleSecretKind}, locs: []string{"lab.yaml:7"}},
	{dir: "eula-conflict", code: pdr.CodeLabComposition, rules: []string{RuleEULAConflict}, locs: []string{"lab.yaml:11"}},
	{dir: "exec-secret-grant", testLib: true, code: pdr.CodeLabReference, rules: []string{RuleExecSecretGrant}, locs: []string{"lab.yaml:9", "grant-bad/module.yaml:11"}},
	{dir: "licenses", code: pdr.CodeLabComposition, rules: []string{RuleLicenses}, locs: []string{"lab.yaml:5"}},
	{dir: "alias-duplicate", testLib: true, code: pdr.CodeLabComposition, rules: []string{RuleAliasDuplicate}, locs: []string{"dup-alias/module.yaml:12"}},
	{dir: "alias-shadow", testLib: true, code: pdr.CodeLabComposition, rules: []string{RuleAliasShadow}, locs: []string{"shadow/module.yaml:11"}},
	{dir: "alias-collision", testLib: true, code: pdr.CodeLabComposition, rules: []string{RuleAliasCollision}, locs: []string{"judge-b/module.yaml:11"}},
	{dir: "alias-cross-kind", testLib: true, code: pdr.CodeLabComposition, rules: []string{RuleAliasDuplicate, RuleAliasShadow}, locs: []string{"alias-cross/module.yaml:13", "alias-cross/module.yaml:14"}},
	{dir: "alias-collision-cross", testLib: true, code: pdr.CodeLabComposition, rules: []string{RuleAliasCollision}, locs: []string{"gen-kafka/module.yaml:11"}},
	{dir: "secret-ref-malformed", code: pdr.CodeLabReference, rules: []string{RuleSecretRef}, locs: []string{"lab.yaml:11"}},
	{dir: "yaml-duplicate-key", code: pdr.CodeLabSchema, rules: []string{RuleSchema}, locs: []string{"playbooks/p.yaml:10"}},
	{dir: "yaml-trailing-malformed", code: pdr.CodeLabUnreadable, rules: []string{RuleUnreadable}, locs: []string{"playbooks/p.yaml:11"}},
	{dir: "yaml-key-not-string-playbook", code: pdr.CodeLabUnreadable, rules: []string{RuleUnreadable}, locs: []string{"playbooks/p.yaml:9"}},
	{dir: "secret-ref-in-key", code: pdr.CodeLabStructure, rules: []string{RuleSecretRefPlace}, locs: []string{"lab.yaml:13"}},
	{dir: "secret-ref-in-env-key", code: pdr.CodeLabStructure, rules: []string{RuleSecretRefPlace}, locs: []string{"lab.yaml:11"}},
	{dir: "secret-ref-same-line", testLib: true, code: pdr.CodeLabStructure, rules: []string{RuleSecretRefPlace}, locs: []string{"oneline/module.yaml:2"}},
	{dir: "secret-ref-unterminated", code: pdr.CodeLabReference, rules: []string{RuleSecretRef}, locs: []string{"lab.yaml:11"}},
	{dir: "secret-ref-in-playbook", code: pdr.CodeLabStructure, rules: []string{RuleSecretRefPlace}, locs: []string{"playbooks/p.yaml:4", "playbooks/p.yaml:9", "playbooks/p.yaml:10", "playbooks/p.yaml:11", "playbooks/p.yaml:12"}},
	{dir: "ui-scheme", testLib: true, code: pdr.CodeLabStructure, rules: []string{RuleUIScheme}, locs: []string{"ui-tcp/module.yaml:10"}},
	{dir: "adapter-unknown", code: pdr.CodeLabReference, rules: []string{RuleAdapterUnknown}, locs: []string{"lab.yaml:9"}},
	{dir: "generator-unknown", code: pdr.CodeLabReference, rules: []string{RuleGeneratorUnknown}, locs: []string{"lab.yaml:8"}},
	{dir: "profile-service", code: pdr.CodeLabReference, rules: []string{RuleProfileService}, locs: []string{"lab.yaml:10"}},
	{dir: "init-service", testLib: true, code: pdr.CodeLabReference, rules: []string{RuleInitService}, locs: []string{"init-target/module.yaml:13"}},
	{dir: "init-auth-secret", testLib: true, code: pdr.CodeLabReference, rules: []string{RuleInitAuthSecret}, locs: []string{"init-auth/module.yaml:13"}},
	{dir: "init-cycle", testLib: true, code: pdr.CodeLabComposition, rules: []string{RuleInitCycle}, locs: []string{"init-cycle-a/module.yaml:14"}},
	// A request's header names are one set of case-insensitive fields.
	{dir: "init-header-dup", testLib: true, code: pdr.CodeLabStructure, rules: []string{RuleInitHeaderDup}, locs: []string{"init-header-dup/module.yaml:17"}},
	// A username carries no colon: curl's --user splits the credentials at the first one.
	{dir: "init-auth-colon", testLib: true, code: pdr.CodeLabStructure, rules: []string{RuleInitAuthUser}, locs: []string{"init-auth-colon/module.yaml:18"}},
	// An authored Host header is a legal host.
	{dir: "init-host", testLib: true, code: pdr.CodeLabStructure, rules: []string{RuleInitHost}, locs: []string{"init-host/module.yaml:16"}},
	// A header name is one token.
	{dir: "init-header-name", testLib: true, code: pdr.CodeLabStructure, rules: []string{RuleInitHeaderName}, locs: []string{"init-header-name/module.yaml:16"}},
	{dir: "file-path", testLib: true, code: pdr.CodeLabStructure, rules: []string{RuleFilePath}, locs: []string{"file-path-a/module.yaml:11", "file-path-a/module.yaml:12"}},
	// A file's content is inline or comes from a template asset — one of
	// the two, and the asset is a real file inside the template (plan S8).
	{dir: "file-source", code: pdr.CodeLabStructure, rules: []string{RuleFileSource}, locs: []string{"lab.yaml:12", "lab.yaml:14", "lab.yaml:16"}},
	// An exec checkpoint's params carry image, args, env, secrets, limits and nothing else.
	{dir: "exec-params", code: pdr.CodeLabStructure, rules: []string{RuleExecParams}, locs: []string{"lab.yaml:13"}},
	// A built-in generator's params are the ones it reads; an attest checkpoint's are exactly a prompt.
	{dir: "seed-params", code: pdr.CodeLabStructure, rules: []string{RuleSeedParams}, locs: []string{"lab.yaml:15", "lab.yaml:20"}},
	{dir: "attest-params", code: pdr.CodeLabStructure, rules: []string{RuleAttestParams}, locs: []string{"lab.yaml:10", "lab.yaml:12", "lab.yaml:16", "lab.yaml:22"}},
	{dir: "playbooks-unreadable", code: pdr.CodeLabUnreadable, rules: []string{RuleUnreadable}, locs: []string{"playbooks-unreadable/playbooks"}},
	{dir: "checkpoint-id-duplicate", code: pdr.CodeLabStructure, rules: []string{RuleCheckpointIDDup}, locs: []string{"lab.yaml:12", "playbooks/p.yaml:10"}},
	{dir: "checkpoint-id-dup-across", code: pdr.CodeLabStructure, rules: []string{RuleCheckpointIDDup}, locs: []string{"playbooks/b.yaml:10"}},
	{dir: "objective-hint", code: pdr.CodeLabStructure, rules: []string{RuleObjectiveHint}, locs: []string{"lab.yaml:8", "playbooks/p.yaml:10"}},
	{dir: "playbook-name-duplicate", code: pdr.CodeLabStructure, rules: []string{RulePlaybookNameDup}, locs: []string{"playbooks/b.yaml:4"}},
	{dir: "step-id-duplicate", code: pdr.CodeLabStructure, rules: []string{RuleStepIDDup}, locs: []string{"playbooks/p.yaml:10"}},
	{dir: "seed-action", code: pdr.CodeLabReference, rules: []string{RuleSeedAction}, locs: []string{"playbooks/p.yaml:10"}},
	{dir: "checkpoint-ref", code: pdr.CodeLabReference, rules: []string{RuleCheckpointRef}, locs: []string{"playbooks/p.yaml:9"}},
	{dir: "context", code: pdr.CodeLabReference, rules: []string{RuleContext}, locs: []string{"playbooks/p.yaml:8"}},
	{dir: "reveal", code: pdr.CodeLabReference, rules: []string{RuleReveal}, locs: []string{"playbooks/p.yaml:10"}},
	{dir: "repro-auto", code: pdr.CodeLabStructure, rules: []string{RuleReproAuto}, locs: []string{"playbooks/p.yaml:6"}},
	{dir: "no-objectives", warnRule: RuleNoObjectives, locs: []string{"playbooks/p.yaml:4"}},
}

func testLibrary() *Library { return DirLibrary(filepath.Join("testdata", "modules")) }

func TestBrokenFixturesTripEveryRule(t *testing.T) {
	covered := map[string]bool{}
	for _, fx := range brokenFixtures {
		t.Run(fx.dir, func(t *testing.T) {
			opts := Options{Path: filepath.Join("testdata", "broken", fx.dir)}
			if fx.testLib {
				opts.Library = testLibrary()
			}
			res, err := Validate(opts)
			if err != nil {
				t.Fatalf("Validate returned a hard error: %v", err)
			}
			findings := res.Findings
			if fx.warnRule != "" {
				if !res.Valid() {
					t.Fatalf("expected a valid lab with a warning, got findings %v", res.Findings)
				}
				findings = res.Warnings
				covered[fx.warnRule] = true
				assertRules(t, findings, []string{fx.warnRule})
				assertLocs(t, findings, fx.locs)
				return
			}
			if res.Valid() {
				t.Fatalf("expected findings, lab reported valid")
			}
			e := res.Error()
			if e.Code != fx.code {
				t.Errorf("envelope code %s, want %s (%s)", e.Code, fx.code, e.Message)
			}
			if len(e.Details) != len(res.Findings) {
				t.Errorf("envelope lists %d details for %d findings", len(e.Details), len(res.Findings))
			}
			for _, r := range fx.rules {
				covered[r] = true
			}
			assertRules(t, findings, fx.rules)
			assertLocs(t, findings, fx.locs)
		})
	}
	for _, r := range Rules {
		if !covered[r] {
			t.Errorf("rule %q has no broken fixture", r)
		}
	}
}

func assertRules(t *testing.T, findings []Finding, want []string) {
	t.Helper()
	got := map[string]bool{}
	for _, f := range findings {
		got[f.Rule] = true
	}
	for _, r := range want {
		if !got[r] {
			t.Errorf("rule %q not among findings: %v", r, findings)
		}
	}
	wantSet := map[string]bool{}
	for _, r := range want {
		wantSet[r] = true
	}
	for r := range got {
		if !wantSet[r] {
			t.Errorf("unexpected rule %q among findings: %v", r, findings)
		}
	}
}

func assertLocs(t *testing.T, findings []Finding, suffixes []string) {
	t.Helper()
	for _, want := range suffixes {
		found := false
		for _, f := range findings {
			if strings.HasSuffix(f.Path, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("no finding located at …%s: %v", want, findings)
		}
	}
	for _, f := range findings {
		if _, line := splitLoc(f.Path); line == 0 && strings.HasSuffix(f.Path, ".yaml") {
			t.Errorf("finding in a manifest without a line number: %+v", f)
		}
	}
}

func TestFindingsAreSortedByFileThenLine(t *testing.T) {
	// A fixture with several findings: a single one is always sorted.
	res, err := Validate(Options{Path: filepath.Join("testdata", "broken", "attest-params")})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) < 2 {
		t.Fatalf("the fixture must hold several findings for the order to mean anything: %v", res.Findings)
	}
	for i := 1; i < len(res.Findings); i++ {
		if findingLess(res.Findings[i], res.Findings[i-1]) {
			t.Fatalf("findings not sorted: %v", res.Findings)
		}
	}
}

// A template whose lab.yaml cannot become a JSON value is PDR-E100 as a
// hard error (there is no document to report findings against): a
// self-referential alias is refused rather than followed forever, and a
// non-string mapping key is refused rather than silently stringified.
func TestUnconvertibleTemplateIsUnreadable(t *testing.T) {
	cases := []struct{ dir, want string }{
		{"yaml-alias-cycle", "alias *loop refers to a node that contains it"},
		{"yaml-key-not-string", "lab.yaml: line 11: mapping keys must be strings"},
		{"yaml-nonfinite", "lab.yaml: line 11: .nan is not a finite number"},
		{"yaml-merge-cycle", "refers to a node that contains it"},
		{"yaml-int-overflow", "lab.yaml: line 11: 18446744073709551617 is beyond the exact integer range"},
		{"yaml-int-overflow-hex", "lab.yaml: line 11: 0x10000000000000000 is beyond the exact integer range"},
		{"yaml-int-overflow-tagged", "lab.yaml: line 11: "}, // an explicit !!int that cannot be one is refused by the decoder itself
	}
	for _, tc := range cases {
		_, err := Validate(Options{Path: filepath.Join("testdata", "broken", tc.dir)})
		pe, ok := err.(*pdr.Error)
		if !ok || pe.Code != pdr.CodeLabUnreadable || !strings.Contains(pe.Message, "lab.yaml") || !strings.Contains(pe.Message, tc.want) {
			t.Fatalf("%s: want PDR-E100 containing %q, got %v", tc.dir, tc.want, err)
		}
	}
}

// A playbook whose only objective is a template-level checkpoint reached
// through ref: counts it (no PDR-W102) and the plan agrees.
func TestObjectiveReachedThroughRefCounts(t *testing.T) {
	res, err := Validate(Options{Path: filepath.Join("testdata", "valid-ref-objective")})
	if err != nil || !res.Valid() {
		t.Fatalf("%v %v", err, res)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("unexpected warnings (the ref'd objective must count): %v", res.Warnings)
	}
	plan, err := BuildPlan(res, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Playbooks) != 1 || plan.Playbooks[0].Objectives != 1 {
		t.Errorf("plan objectives = %+v", plan.Playbooks)
	}
	if len(plan.Checkpoints.Objective) != 1 || len(plan.Checkpoints.Baseline) != 1 {
		t.Errorf("checkpoints by class = %+v", plan.Checkpoints)
	}
}

// A module that is present but unreadable is PDR-E100, not "not installed".
func TestUnreadableModuleIsNotMissing(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "plain"), []byte("a file where the module directory should be"), 0o644); err != nil {
		t.Fatal(err)
	}
	lab := t.TempDir()
	if err := os.WriteFile(filepath.Join(lab, "lab.yaml"), []byte("apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: x }\nservices:\n  web: { use: modules/plain@1.0 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Validate(Options{Path: lab, Library: DirLibrary(dir)})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range res.Findings {
		got = append(got, f.Rule+"@"+f.Path)
	}
	if len(res.Findings) != 1 || res.Findings[0].Rule != RuleUnreadable || res.Findings[0].Code != pdr.CodeLabUnreadable || !strings.HasSuffix(res.Findings[0].Path, "plain/module.yaml") {
		t.Fatalf("findings = %v", got)
	}
}

func TestUnreadableTemplateIsAHardError(t *testing.T) {
	for _, p := range []string{filepath.Join("testdata", "does-not-exist"), "testdata"} {
		_, err := Validate(Options{Path: p})
		pe, ok := err.(*pdr.Error)
		if !ok || pe.Code != pdr.CodeLabUnreadable {
			t.Errorf("%s: want PDR-E100, got %v", p, err)
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte("apiVersion: x\nkind: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Validate(Options{Path: dir})
	pe, ok := err.(*pdr.Error)
	if !ok || pe.Code != pdr.CodeLabUnreadable || !strings.Contains(pe.Message, "lab.yaml:") {
		t.Errorf("want PDR-E100 with file:line, got %v", err)
	}
}

// The catalog template is the normative example (spec 0003 §12): valid,
// warning-free, and composed of installed modules. It is the one template
// the starter catalog holds since the golden lab was retired
// (2026-09-23).
func TestCatalogTemplatesValidate(t *testing.T) {
	for _, name := range []string{"grafana-prometheus-intro"} {
		res, err := Validate(Options{Path: filepath.Join("..", "..", "scenarios", name)})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !res.Valid() {
			t.Fatalf("%s: %v", name, res.Error())
		}
		if len(res.Warnings) != 0 {
			t.Errorf("%s: unexpected warnings %v", name, res.Warnings)
		}
		if len(res.Playbooks) != 1 {
			t.Errorf("%s: expected one playbook, got %d", name, len(res.Playbooks))
		}
	}
}

// The catalog template's obligations (the reference playbook, spec 0001
// §10; hack/ready_test.sh's "baseline 4/4"): four baselines, its one seed,
// no EULA — the starter catalog runs no proprietary software — and the one
// secret its Grafana module declares.
func TestCatalogTemplateObligations(t *testing.T) {
	res, err := Validate(Options{Path: filepath.Join("..", "..", "scenarios", "grafana-prometheus-intro")})
	if err != nil || !res.Valid() {
		t.Fatalf("catalog template invalid: %v %v", err, res)
	}
	if n := len(res.Template.Checkpoints); n != 4 {
		t.Errorf("baselines = %d, want 4", n)
	}
	if got := strings.Join(sortedKeys(res.Template.Seeds), ","); got != "query-load" {
		t.Errorf("seeds = %s", got)
	}
	if got := res.Composition.eulaIDs(); len(got) != 0 {
		t.Errorf("EULAs = %v, want none", got)
	}
	if got := sortedKeys(res.Composition.Secrets); strings.Join(got, ",") != "grafana" {
		t.Errorf("secrets = %v", got)
	}
}

// A9 (the reconciliation plan §4): the retained modules move to v1alpha2
// and their license.spdx values — the licence of the product each module
// runs, not the licence of the file — stay as they were: Prometheus is
// Apache-2.0, Grafana AGPL-3.0-only. The files' own SPDX headers are
// first-party and read AGPL-3.0-only with no copyright line (R4's header
// pass, ADR-0004 D1–D2); the product licences never change with them.
func TestCatalogModulesKeepTheirProductLicenses(t *testing.T) {
	want := map[string]string{"grafana": "AGPL-3.0-only", "prometheus": "Apache-2.0"}
	lib := EmbeddedLibrary()
	names := lib.Names()
	if strings.Join(names, ",") != "grafana,prometheus" {
		t.Fatalf("the embedded module library holds %v", names)
	}
	for _, name := range names {
		doc, err := lib.Load(name)
		if err != nil {
			t.Fatal(err)
		}
		var m Module
		if err := doc.Decode(&m); err != nil {
			t.Fatal(err)
		}
		if m.APIVersion != APIVersion {
			t.Errorf("modules/%s declares %s, want %s", name, m.APIVersion, APIVersion)
		}
		if m.License == nil || m.License.SPDX != want[name] {
			t.Errorf("modules/%s: license.spdx %+v, want %s", name, m.License, want[name])
		}
		if !strings.HasPrefix(string(doc.Raw), "# yaml-language-server: $schema=https://schemas.podaro.dev/module/v1alpha2.json\n"+
			"# SPDX-License-Identifier: AGPL-3.0-only\n") {
			t.Errorf("modules/%s: the header does not name the v1alpha2 module schema and the file's own licence, AGPL-3.0-only", name)
		}
		if strings.Contains(string(doc.Raw), "SPDX-FileCopyrightText") || strings.Contains(string(doc.Raw), "Copyright") {
			t.Errorf("modules/%s: a first-party file carries a copyright line (ADR-0004 D2)", name)
		}
	}
}

// Manual §11's minimal example is normative and must validate untouched.
func TestManualMinimalExampleValidates(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "public-docs", "USERMANUAL.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	marker := "```yaml\n# yaml-language-server: $schema=https://schemas.podaro.dev/lab/v1alpha2.json"
	start := strings.Index(doc, marker)
	if start < 0 {
		t.Fatal("USERMANUAL.md §11 minimal example not found")
	}
	body := doc[start+len("```yaml\n"):]
	body = body[:strings.Index(body, "```")]
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Validate(Options{Path: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid() {
		t.Fatalf("Manual §11 example invalid: %v", res.Error())
	}
	if len(res.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", res.Warnings)
	}
}

// Every installed module is schema-valid on its own, whether or not a
// catalog template composes it.
func TestEmbeddedLibraryModulesAreSchemaValid(t *testing.T) {
	lib := EmbeddedLibrary()
	names := lib.Names()
	if len(names) < 2 {
		t.Fatalf("embedded library holds %d modules: %v", len(names), names)
	}
	for _, name := range names {
		doc, err := lib.Load(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		violations, err := schemaViolations(schemaFor(KindModule, doc.Value), doc.Value)
		if err != nil {
			t.Fatal(err)
		}
		if len(violations) > 0 {
			t.Errorf("%s: %v", name, violations)
		}
		var m Module
		if err := doc.Decode(&m); err != nil {
			t.Errorf("%s: decode: %v", name, err)
		}
		if m.Metadata.Name != name {
			t.Errorf("%s: metadata.name is %q", name, m.Metadata.Name)
		}
		if !strings.HasPrefix(m.Image.Digest, "sha256:") {
			t.Errorf("%s: image not digest-pinned", name)
		}
	}
}

// The installed library passes the standalone module rules — every
// module, composed by a catalog template or not (the review finding, kept as a property of the Go validator).
func TestEmbeddedLibraryPassesStandaloneRules(t *testing.T) {
	if findings := ValidateLibrary(EmbeddedLibrary()); len(findings) != 0 {
		t.Errorf("embedded library findings: %v", findings)
	}
	// The fixture library deliberately breaks them; standalone validation
	// sees the per-module faults without any template composing them.
	got := map[string]bool{}
	for _, f := range ValidateLibrary(testLibrary()) {
		got[f.Rule] = true
	}
	for _, want := range []string{RuleAliasDuplicate, RuleAliasShadow, RuleModuleMeta} {
		if !got[want] {
			t.Errorf("standalone library validation missed %s (got %v)", want, got)
		}
	}
	if got[RuleAliasCollision] {
		t.Error("collisions are a composition-scope rule; standalone validation must not report them")
	}
}

func TestAliasesResolveAndExpandInThePlan(t *testing.T) {
	res, err := Validate(Options{Path: filepath.Join("testdata", "valid-aliases"), Library: testLibrary()})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid() {
		t.Fatalf("%v", res.Error())
	}
	plan, err := BuildPlan(res, "")
	if err != nil {
		t.Fatal(err)
	}
	var wheres []string
	for _, e := range plan.Exec {
		wheres = append(wheres, e.Where)
	}
	sort.Strings(wheres)
	want := []string{
		"checkpoint c (alias kafka-lag from modules/judge-a)",
		"checkpoint count-judge",
		"checkpoint judge-exec",
		"checkpoint lag-ok (alias kafka-lag from modules/judge-a)",
		"seed exec-seed",
		"seed orders (alias kafka-orders from modules/judge-a)",
	}
	if strings.Join(wheres, "|") != strings.Join(want, "|") {
		t.Errorf("exec images = %v, want %v", wheres, want)
	}
	if plan.Profile != nil {
		t.Errorf("no profile declared, plan picked %v", plan.Profile)
	}
	if len(plan.Licenses) != 1 || plan.Licenses[0].ID != "custom-terms" {
		t.Errorf("licenses = %v", plan.Licenses)
	}
}

// An override that replaces a module string carrying ${secret:…} is judged
// on the effective value: a module that reads a sibling's secret validates
// without the sibling once the template supplies its own credential.
func TestOverrideReplacingSecretReferenceIsJudgedOnEffectiveConfig(t *testing.T) {
	res, err := Validate(Options{Path: filepath.Join("testdata", "valid-override"), Library: testLibrary()})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid() {
		t.Fatalf("expected valid, got %v", res.Error())
	}
	if got := sortedKeys(res.Composition.Secrets); strings.Join(got, ",") != "dashboard-login" {
		t.Errorf("composed secrets = %v", got)
	}
	// And a reference the override introduces is located in lab.yaml, at
	// the line that wrote it — not in the module file.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(`apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: x }
services:
  dashboard:
    use: modules/sibling-secret@1.0
    config:
      env:
        STORE_PASSWORD: "${secret:missing}"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err = Validate(Options{Path: dir, Library: testLibrary()})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range res.Findings {
		if f.Rule == RuleSecretRef && strings.HasSuffix(f.Path, "lab.yaml:9") && strings.Contains(f.Message, "${secret:missing}") {
			found = true
		}
		if f.Rule == RuleSecretRef && strings.Contains(f.Path, "module.yaml") {
			t.Errorf("module-located secret finding for a template-written value: %+v", f)
		}
	}
	if !found {
		t.Errorf("expected ${secret:missing} at lab.yaml:9, got %v", res.Findings)
	}
}

func TestDeepMergeMapsMergeArraysReplace(t *testing.T) {
	base := map[string]any{
		"config": map[string]any{"env": map[string]any{"A": "1", "B": "2"}, "args": []any{"x"}},
		"init":   map[string]any{"requests": []any{1, 2, 3}, "waits_for": "healthy"},
	}
	over := map[string]any{
		"config": map[string]any{"env": map[string]any{"B": "3"}, "args": []any{"y", "z"}},
	}
	got := deepMerge(base, over)
	env := got["config"].(map[string]any)["env"].(map[string]any)
	if env["A"] != "1" || env["B"] != "3" {
		t.Errorf("env merge wrong: %v", env)
	}
	if args := got["config"].(map[string]any)["args"].([]any); len(args) != 2 {
		t.Errorf("arrays must replace: %v", args)
	}
	if base["config"].(map[string]any)["env"].(map[string]any)["B"] != "2" {
		t.Error("deepMerge mutated its input")
	}
	if len(got["init"].(map[string]any)["requests"].([]any)) != 3 {
		t.Error("untouched keys must survive")
	}
}

func TestDocumentLineLookup(t *testing.T) {
	doc, err := ParseDocument([]byte("a:\n  b:\n    - x\n    - y: 1\n  c: 2\n"), "t.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"t.yaml:1": {"a"},
		"t.yaml:2": {"a", "b"},
		"t.yaml:3": {"a", "b", "0"},
		"t.yaml:4": {"a", "b", "1", "y"},
		"t.yaml:5": {"a", "c"},
	}
	for want, ptr := range cases {
		if got := doc.Loc(ptr...); got != want {
			t.Errorf("Loc(%v) = %s, want %s", ptr, got, want)
		}
	}
	if got := doc.Loc("a", "nope"); got != "t.yaml:2" {
		t.Errorf("missing key should fall back to the enclosing mapping: %s", got)
	}
	if got := pointerTokens("/a/b~1c/0"); strings.Join(got, "|") != "a|b/c|0" {
		t.Errorf("pointerTokens = %v", got)
	}
}

// A module alias's params are open extension input: an object under
// `left` that names something unknown is not a nested adapter, so neither
// the validator nor the plan interprets it (no built-in nests another; the
// two composites that did were retired with the golden lab, 2026-09-23).
func TestAliasParamsAreOpen(t *testing.T) {
	res, err := Validate(Options{Path: filepath.Join("testdata", "valid-alias-open-params"), Library: DirLibrary(filepath.Join("testdata", "modules"))})
	if err != nil || !res.Valid() {
		t.Fatalf("%v %v", err, res)
	}
	plan, err := BuildPlan(res, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range plan.Exec {
		if strings.Contains(x.Where, "·") {
			t.Errorf("plan advertises a nested executable under an alias adapter: %+v", x)
		}
	}
}

// A manifest that exists but cannot be read keeps its path as the
// finding's location (the file-location contract), for modules and for
// playbooks alike.
func TestUnreadableFileKeepsItsPath(t *testing.T) {
	// modules/dirfile/module.yaml is a directory: stat succeeds, read fails.
	res, err := Validate(Options{Path: filepath.Join("testdata", "broken", "module-file-unreadable"), Library: DirLibrary(filepath.Join("testdata", "modules"))})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != pdr.CodeLabUnreadable || !strings.HasSuffix(res.Findings[0].Path, filepath.Join("dirfile", "module.yaml")) {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if os.Geteuid() == 0 {
		t.Log("running as root: the permission-denied playbook case cannot be exercised")
		return
	}
	lab := t.TempDir()
	if err := os.WriteFile(filepath.Join(lab, "lab.yaml"), []byte("apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: x }\nservices:\n  web: { image: docker.io/library/nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, endpoints: [ { purpose: ui, port: 80 } ] }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(lab, "playbooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lab, "playbooks", "p.yaml"), []byte("kind: Playbook\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	res, err = Validate(Options{Path: lab})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != pdr.CodeLabUnreadable || !strings.HasSuffix(res.Findings[0].Path, filepath.Join("playbooks", "p.yaml")) {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

// The secret-kind finding names the kind written at its own location as
// "here": the template's token at the template line, the module's
// password as the other party.
func TestSecretKindMessageMatchesLocation(t *testing.T) {
	res, err := Validate(Options{Path: filepath.Join("testdata", "broken", "secret-kind-conflict")})
	if err != nil {
		t.Fatal(err)
	}
	var msg string
	for _, f := range res.Findings {
		if f.Rule == RuleSecretKind {
			msg = f.Message
		}
	}
	if !strings.Contains(msg, "kind token here") || !strings.Contains(msg, "kind password by modules/grafana") {
		t.Fatalf("message = %q", msg)
	}
}

// Locations are structured data, never parsed back out of a message:
// paths with whitespace reach the finding whole, for an unreadable module
// and for a playbook that fails to parse; and the playbooks directory is
// located under the resolved template directory even when validate was
// given the lab.yaml file form.
func TestLocationsSurviveWhitespaceAndFileForm(t *testing.T) {
	lib := filepath.Join(t.TempDir(), "my modules")
	if err := os.MkdirAll(filepath.Join(lib, "plain", "module.yaml"), 0o755); err != nil { // module.yaml as a directory
		t.Fatal(err)
	}
	lab := filepath.Join(t.TempDir(), "my lab")
	if err := os.MkdirAll(filepath.Join(lab, "playbooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lab, "lab.yaml"), []byte("apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: x }\nservices:\n  web: { use: modules/plain@1.0 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lab, "playbooks", "my playbook.yaml"), []byte("kind: Playbook\nsteps: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Validate(Options{Path: lab, Library: DirLibrary(lib)})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(lib, "plain", "module.yaml"), filepath.Join(lab, "playbooks", "my playbook.yaml") + ":"}
	for _, w := range want {
		found := false
		for _, f := range res.Findings {
			if f.Code == pdr.CodeLabUnreadable && strings.HasPrefix(f.Path, w) {
				found = true
			}
		}
		if !found {
			t.Errorf("no PDR-E100 finding located at %q in %+v", w, res.Findings)
		}
	}
	res, err = Validate(Options{Path: filepath.Join("testdata", "broken", "playbooks-unreadable", "lab.yaml")})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Path != "testdata/broken/playbooks-unreadable/playbooks" {
		t.Fatalf("file form: findings = %+v", res.Findings)
	}
}

// Generator params pass through unchanged: an unquoted YAML date stays the
// author's text in the typed view and in the plan's JSON, never an RFC
// 3339 instant.
func TestDateParamsPassThroughUnchanged(t *testing.T) {
	res, err := Validate(Options{Path: filepath.Join("testdata", "valid-date-param")})
	if err != nil || !res.Valid() {
		t.Fatalf("%v %v", err, res)
	}
	plan, err := BuildPlan(res, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Seeds) != 1 || plan.Seeds[0].Params["date"] != "2026-09-03" || plan.Seeds[0].Params["at"] != "2026-09-03T10:00:00Z" {
		t.Fatalf("seed params = %#v", plan.Seeds)
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"date":"2026-09-03"`) || strings.Contains(string(raw), "T00:00:00Z") {
		t.Fatalf("plan JSON rewrites the date: %s", raw)
	}
}

// YAML merge keys (`<<: *base`) expand into ordinary mappings before the
// schema sees them — explicit keys win — so a manifest the S2 gate
// (safe_load) accepted keeps its status (frozen-schema compatibility).
func TestMergeKeysExpand(t *testing.T) {
	res, err := Validate(Options{Path: filepath.Join("testdata", "valid-merge-key")})
	if err != nil || !res.Valid() {
		t.Fatalf("%v %v", err, res)
	}
	plan, err := BuildPlan(res, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Services) != 2 || plan.Services[1].Name != "web2" || plan.Services[1].Image.Digest != plan.Services[0].Image.Digest {
		t.Fatalf("services = %+v", plan.Services)
	}
	if plan.Services[1].Embed != "newtab" || plan.Services[0].Embed != "iframe" {
		t.Fatalf("explicit keys must win over merged ones: %+v", plan.Services)
	}
}

// An unsigned integer beyond int64 keeps its exact value through the JSON
// view, the typed view, and the plan — never wrapped negative.
func TestBigUnsignedIntegersStayExact(t *testing.T) {
	res, err := Validate(Options{Path: filepath.Join("testdata", "valid-big-int")})
	if err != nil || !res.Valid() {
		t.Fatalf("%v %v", err, res)
	}
	plan, err := BuildPlan(res, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"big":18446744073709551615`) {
		t.Fatalf("plan JSON lost the value: %s", raw)
	}
}

// A `--modules` directory that does not exist is one PDR-E100 at that
// path, never a "not installed" per referenced module.
func TestMissingLibraryRootIsUnreadable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no such modules")
	res, err := Validate(Options{Path: filepath.Join("testdata", "valid-aliases"), Library: DirLibrary(missing)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != pdr.CodeLabUnreadable || res.Findings[0].Path != missing {
		t.Fatalf("findings = %+v", res.Findings)
	}
	// The same when the template references no module at all: the flag
	// was given, and it is wrong.
	res, err = Validate(Options{Path: filepath.Join("testdata", "valid-merge-key"), Library: DirLibrary(missing)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != pdr.CodeLabUnreadable || res.Findings[0].Path != missing {
		t.Fatalf("inline-only template: findings = %+v", res.Findings)
	}
	// A root that exists but cannot be listed (here: a regular file) is
	// the same single finding.
	file := filepath.Join(t.TempDir(), "modules.txt")
	if err := os.WriteFile(file, []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err = Validate(Options{Path: filepath.Join("testdata", "valid-merge-key"), Library: DirLibrary(file)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Code != pdr.CodeLabUnreadable || res.Findings[0].Path != file {
		t.Fatalf("file as library root: findings = %+v", res.Findings)
	}
}

// ValidateLibrary never answers "sound" for a library it could not read:
// an unreadable root is one PDR-E100 at its path, and a module whose
// module.yaml cannot be statted is PDR-E100 at that file.
func TestValidateLibraryReportsUnreadableRoots(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no such modules")
	got := ValidateLibrary(DirLibrary(missing))
	if len(got) != 1 || got[0].Code != pdr.CodeLabUnreadable || got[0].Path != missing {
		t.Fatalf("missing root: %+v", got)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "plain"), []byte("a file where the module directory should be"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "broken", "module.yaml"), 0o755); err != nil { // module.yaml as a directory
		t.Fatal(err)
	}
	got = ValidateLibrary(DirLibrary(dir))
	if len(got) != 1 || got[0].Code != pdr.CodeLabUnreadable || !strings.HasSuffix(got[0].Path, filepath.Join("broken", "module.yaml")) {
		t.Fatalf("unreadable module: %+v", got)
	}
}

// Display names the template the findings, the envelope and the plan
// point at: an engine validating a copy of a template (a delivery
// snapshot) names the directory the copy was taken from — the one the
// operator edits — and the copy's own path appears nowhere.
func TestDisplayNamesTheSourceNotTheCopy(t *testing.T) {
	src := filepath.Join("testdata", "broken", "playbook-name-duplicate")
	copyDir := filepath.Join(t.TempDir(), "snapshot")
	copyFixture(t, src, copyDir)
	res, err := Validate(Options{Path: copyDir, Display: src, Library: testLibrary()})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("the broken fixture must yield findings")
	}
	for _, f := range res.Findings {
		if !strings.HasPrefix(filepath.ToSlash(f.Path), filepath.ToSlash(src)+"/") || strings.Contains(f.Path, copyDir) {
			t.Fatalf("finding located in the copy, not the source: %+v", f)
		}
	}
	pe := res.Error()
	if !strings.Contains(pe.Message, src) || !strings.Contains(pe.Next, src) || strings.Contains(pe.Message, copyDir) || strings.Contains(pe.Next, copyDir) {
		t.Fatalf("envelope must name the source: %s · %s", pe.Message, pe.Next)
	}
	// Without Display the copy is named, as before.
	res, err = Validate(Options{Path: copyDir, Library: testLibrary()})
	if err != nil {
		t.Fatal(err)
	}
	if pe := res.Error(); !strings.Contains(pe.Message, copyDir) {
		t.Fatalf("without Display the path given is named: %s", pe.Message)
	}
	// The plan names the source too.
	valid := filepath.Join("..", "..", "hack", "fixtures", "hello-nginx")
	validCopy := filepath.Join(t.TempDir(), "snapshot")
	copyFixture(t, valid, validCopy)
	plan, _, err := MakePlan(PlanOptions{Options: Options{Path: validCopy, Display: valid}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Template.Path != valid {
		t.Fatalf("plan names %q, want the source %q", plan.Template.Path, valid)
	}
}

// copyFixture copies a template directory (files only, as the engine's
// snapshot does).
func copyFixture(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}
