// SPDX-License-Identifier: AGPL-3.0-only

package lab

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// copyTree copies a template directory, applying edit to every YAML file.
func copyTree(t *testing.T, src string, edit func(rel string, raw []byte) []byte) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.HasSuffix(p, ".yaml") {
			raw = edit(filepath.ToSlash(rel), raw)
		}
		return os.WriteFile(target, raw, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

// toV1alpha1 writes a v1alpha2 document back as v1alpha1: its apiVersion
// and its schema header line, nothing else.
func toV1alpha1(_ string, raw []byte) []byte {
	s := strings.ReplaceAll(string(raw), "apiVersion: "+APIVersionV1alpha2, "apiVersion: "+APIVersionV1alpha1)
	return []byte(strings.Replace(s, "/v1alpha2.json\n", "/v1alpha1.json\n", 1))
}

// Dual-read (the reconciliation plan's D-R2): a v1alpha1 copy of the
// retained catalog template validates unchanged, and plans exactly as the
// v1alpha2 original does — the two versions mean the same for a document
// that names nothing retired.
func TestAV1alpha1CopyOfTheCatalogTemplateValidatesUnchanged(t *testing.T) {
	orig := filepath.Join("..", "..", "scenarios", "grafana-prometheus-intro")
	raw, err := os.ReadFile(filepath.Join(orig, "lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "apiVersion: "+APIVersionV1alpha2) {
		t.Fatalf("the catalog template must declare the current contract, %s", APIVersionV1alpha2)
	}
	old := copyTree(t, orig, toV1alpha1)
	got, err := os.ReadFile(filepath.Join(old, "lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "apiVersion: "+APIVersionV1alpha1) || !strings.HasPrefix(string(got), "# yaml-language-server: $schema=https://schemas.podaro.dev/lab/v1alpha1.json\n") {
		t.Fatalf("the copy is not a v1alpha1 document:\n%s", got)
	}
	plans := map[string][]byte{}
	for _, dir := range []string{orig, old} {
		plan, res, err := MakePlan(PlanOptions{Options: Options{Path: dir}})
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		if !res.Valid() || len(res.Warnings) != 0 {
			t.Fatalf("%s: findings %v, warnings %v", dir, res.Findings, res.Warnings)
		}
		js, err := json.Marshal(plan)
		if err != nil {
			t.Fatal(err)
		}
		plans[dir] = bytes.ReplaceAll(js, []byte(dir), []byte("<dir>"))
	}
	if !bytes.Equal(plans[orig], plans[old]) {
		t.Errorf("the v1alpha1 copy plans differently:\n%s\n%s", plans[orig], plans[old])
	}
}

// The retired-name rule applies to both versions: the negative fixture
// written as v1alpha2 fails exactly as its v1alpha1 original does.
func TestTheRetiredNameRuleAppliesToBothVersions(t *testing.T) {
	orig := filepath.Join("testdata", "broken", "retired-adapter")
	lifted := copyTree(t, orig, func(_ string, raw []byte) []byte {
		return bytes.ReplaceAll(raw, []byte(APIVersionV1alpha1), []byte(APIVersionV1alpha2))
	})
	m := podaro.Retirement()
	for _, dir := range []string{orig, lifted} {
		res, err := Validate(Options{Path: dir})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Findings) != 2 {
			t.Fatalf("%s: want the two retired names, got %v", dir, res.Findings)
		}
		named := map[string]bool{}
		for _, f := range res.Findings {
			if f.Code != pdr.CodeLabRetired || f.Rule != RuleRetired {
				t.Errorf("%s: %+v is not PDR-E106", dir, f)
			}
			if !strings.Contains(f.Message, "retired by the owner on "+m.RetiredOn) || !strings.Contains(f.Message, "hack/retirement.json") {
				t.Errorf("%s: the finding does not cite the retirement record: %s", dir, f.Message)
			}
			for _, x := range m.Modules {
				if strings.Contains(f.Message, `module "`+x.Name+`"`) {
					named["module"] = true
				}
			}
			for _, a := range m.Adapters.Product {
				if strings.Contains(f.Message, `adapter "`+a+`"`) && strings.Contains(f.Message, "judge it with http, container or an exec adapter of your own") {
					named["adapter"] = true
				}
			}
		}
		if !named["module"] || !named["adapter"] {
			t.Errorf("%s: both retired identifiers must be named, got %v", dir, res.Findings)
		}
		if e := res.Error(); e.Code != pdr.CodeLabRetired {
			t.Errorf("%s: envelope %s, want PDR-E106", dir, e.Code)
		}
	}
}

// Every retired adapter, composite and generator the manifest records is
// refused as retired, never as an unknown name — read from the embedded
// manifest, so this test spells none of them.
func TestEveryRetiredNameIsRefusedAsRetired(t *testing.T) {
	m := podaro.Retirement()
	adapters := append(append([]string(nil), m.Adapters.Product...), m.Adapters.Composites...)
	if len(adapters) == 0 || len(m.Generators) == 0 || len(m.Modules) == 0 {
		t.Fatalf("the embedded manifest records nothing: %+v", m)
	}
	var b strings.Builder
	b.WriteString("apiVersion: " + APIVersion + "\nkind: Template\nmetadata: { name: fixture }\nservices:\n  prometheus: { use: modules/prometheus@3.13 }\n")
	b.WriteString("seeds:\n")
	for i, g := range m.Generators {
		b.WriteString("  s" + string(rune('a'+i)) + ": { generator: " + g + ", count: 1 }\n")
	}
	b.WriteString("checkpoints:\n")
	for i, a := range adapters {
		b.WriteString("  - { id: c" + string(rune('a'+i)) + ", adapter: " + a + " }\n")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Validate(Options{Path: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != len(adapters)+len(m.Generators) {
		t.Fatalf("want one finding per retired name (%d), got %v", len(adapters)+len(m.Generators), res.Findings)
	}
	for _, f := range res.Findings {
		if f.Code != pdr.CodeLabRetired || f.Rule != RuleRetired {
			t.Errorf("%+v is not PDR-E106", f)
		}
	}
}
