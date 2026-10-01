// SPDX-License-Identifier: AGPL-3.0-only

package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Round 1 put a resolved asset's text into the merged tree so the §11.3
// secret pass would judge it, and left the *location* machinery behind.
// A finding about `config.files[i].content` is located by looking that
// pointer up in the template — which says `source:`, not `content:` — and
// when the lookup misses, the fallback is the document that declared the
// file. Where a MODULE declares the `source:`, that fallback is the
// module's own manifest: the author is sent to a file that does not
// contain the reference and, for a shipped module, that they do not own.
//
// (Where the template declares the `source:` the fallback already lands
// on the template's own file entry, which is why this case needs a
// module that ships one.)
func TestASecretFindingInsideAnAssetNamesTheAssetTheAuthorCanFix(t *testing.T) {
	mods := t.TempDir()
	if err := os.MkdirAll(filepath.Join(mods, "withsource"), 0o755); err != nil {
		t.Fatal(err)
	}
	module := "# SPDX-License-Identifier: AGPL-3.0-only\n" +
		"apiVersion: lab.podaro.dev/v1alpha1\nkind: Module\n" +
		"metadata:\n  name: withsource\n  version: \"1.0.0\"\n  title: Module that ships a source\n" +
		"image:\n  repository: docker.io/library/nginx\n  tag: \"1.27\"\n" +
		"  digest: sha256:1111111111111111111111111111111111111111111111111111111111111111\n" +
		"license:\n  spdx: Apache-2.0\n" +
		"config:\n  files:\n    - path: /etc/one.yml\n      source: assets/one.yml\n"
	if err := os.WriteFile(filepath.Join(mods, "withsource", "module.yaml"), []byte(module), 0o644); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	manifest := "# SPDX-License-Identifier: AGPL-3.0-only\n" +
		"apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\n" +
		"metadata: { name: assets, version: 1.0.0, title: Asset fixture }\n" +
		"services:\n  a:\n    use: modules/withsource@1.0.0\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "assets", "one.yml"),
		[]byte("token: ${secret:missing}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Validate(Options{Path: dir, Library: DirLibrary(mods)})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range res.Findings {
		if f.Rule != RuleSecretRef || !strings.Contains(f.Message, "${secret:missing}") {
			continue
		}
		found = true
		// The premise is round 1's fix: the pass judges the asset at all.
		// This case is about where it says the text is.
		if strings.Contains(f.Path, "module.yaml") {
			t.Errorf("the finding sends the author to the module manifest, which does not carry the reference: %s", f.Path)
		}
		if !strings.Contains(f.Path, filepath.Join("assets", "one.yml")) {
			t.Errorf("the finding does not name the asset the text is in: %s", f.Path)
		}
	}
	if !found {
		t.Fatalf("no finding for the asset's unresolved reference: %v", res.Findings)
	}
}
