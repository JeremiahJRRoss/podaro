// SPDX-License-Identifier: AGPL-3.0-only

package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// assetLab writes a template whose one service declares a config file
// from the given YAML fragment, and returns the template directory.
func assetLab(t *testing.T, fileYAML string) string {
	t.Helper()
	dir := t.TempDir()
	manifest := "# SPDX-License-Identifier: AGPL-3.0-only\n" +
		"apiVersion: lab.podaro.dev/v1alpha1\n" +
		"kind: Template\n" +
		"metadata: { name: assets, version: 1.0.0, title: Asset fixture }\n" +
		"services:\n" +
		"  a:\n" +
		"    use: modules/prometheus@3.13\n" +
		"    config:\n" +
		"      files:\n" + fileYAML
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func findings(t *testing.T, dir string) []Finding {
	t.Helper()
	res, err := Validate(Options{Path: dir})
	if err != nil {
		return nil
	}
	return res.Findings
}

func mentions(fs []Finding, rule, substr string) bool {
	for _, f := range fs {
		if f.Rule == rule && strings.Contains(f.Message, substr) {
			return true
		}
	}
	return false
}

// An asset is a file the template ships, and `os.Lstat` on the whole
// path answers about the leaf alone: the operating system follows an
// intermediate link when it opens the file. `assets/external -> /etc`
// with `source: assets/external/passwd` therefore read a file outside
// the template while the leaf looked like an ordinary one.
func TestAnAssetPathIsRefusedWhenAnAncestorIsALink(t *testing.T) {
	dir := assetLab(t, "        - path: /etc/one.yml\n          source: assets/external/secret.txt\n")
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("not the template's\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "assets", "external")); err != nil {
		t.Skipf("this filesystem does not make symbolic links: %v", err)
	}
	// The fixture is the case it claims: the leaf really is a regular
	// file, and really is outside the template.
	if info, err := os.Lstat(filepath.Join(dir, "assets", "external", "secret.txt")); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("the fixture's leaf is not a regular file: %v %v", info, err)
	}

	fs := findings(t, dir)
	if !mentions(fs, RuleFileSource, "symbolic link") {
		t.Errorf("a source reached through a symlinked ancestor was accepted; findings: %v", fs)
	}
	for _, f := range fs {
		if strings.Contains(f.Message, "not the template's") {
			t.Errorf("the refusal quotes what it read: %q", f.Message)
		}
	}
}

// An empty file is a file a template may ship, so `content: ""` beside a
// `source:` is two contents declared — and the value cannot say which
// the author meant, only the document can. The schema allows both keys
// on purpose, so that validate can say why.
func TestAnEmptyContentBesideASourceIsStillTwoContents(t *testing.T) {
	dir := assetLab(t, "        - path: /etc/one.yml\n          content: \"\"\n          source: assets/one.yml\n")
	if err := os.WriteFile(filepath.Join(dir, "assets", "one.yml"), []byte("from the asset\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs := findings(t, dir)
	if !mentions(fs, RuleFileSource, "declares both content and source") {
		t.Errorf("an empty content beside a source was not caught; findings: %v", fs)
	}
	for _, f := range fs {
		if f.Code != pdr.CodeLabStructure && f.Rule == RuleFileSource {
			t.Errorf("the finding carries %s, not the structure code", f.Code)
		}
	}
}

// The files pass resolves a `source:` so that §11.3 can judge what the
// asset carries. It judged the template document and the merged module,
// and the resolved text was in neither — so a Pack's ${secret:missing}
// passed `lab validate` and failed at create instead.
func TestASecretReferenceInsideAnAssetIsResolvedAtValidate(t *testing.T) {
	dir := assetLab(t, "        - path: /etc/one.yml\n          source: assets/one.yml\n")
	if err := os.WriteFile(filepath.Join(dir, "assets", "one.yml"),
		[]byte("token: ${secret:missing}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs := findings(t, dir)
	if !mentions(fs, RuleSecretRef, "${secret:missing}") {
		t.Errorf("an unresolved reference inside an asset reached create unjudged; findings: %v", fs)
	}

	// And a declared one is not a finding: the pass judges the reference,
	// it does not forbid assets from carrying any.
	ok := assetLab(t, "        - path: /etc/one.yml\n          source: assets/one.yml\n")
	if err := os.WriteFile(filepath.Join(ok, "lab.yaml"), []byte(
		"# SPDX-License-Identifier: AGPL-3.0-only\napiVersion: lab.podaro.dev/v1alpha1\nkind: Template\n"+
			"metadata: { name: assets, version: 1.0.0, title: Asset fixture }\n"+
			"secrets:\n  declared: { kind: token }\n"+
			"services:\n  a:\n    use: modules/prometheus@3.13\n    config:\n      files:\n"+
			"        - path: /etc/one.yml\n          source: assets/one.yml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ok, "assets", "one.yml"),
		[]byte("token: ${secret:declared}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, f := range findings(t, ok) {
		if f.Rule == RuleSecretRef || f.Rule == RuleSecretRefPlace {
			t.Errorf("a declared reference inside an asset was refused: %s %s", f.Rule, f.Message)
		}
	}
}
