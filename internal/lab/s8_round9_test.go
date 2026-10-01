// SPDX-License-Identifier: AGPL-3.0-only

package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Round 8 gave a resolved asset's text the asset's own location, and
// built it from the directory the content is READ from. When the engine
// validates a delivery snapshot those are two different places: it
// passes the private snapshot as Path and the editable source as
// Display, and every other finding names the display one. So the asset
// location alone pointed into a staging directory that is discarded
// after admission — a path the operator cannot open, let alone fix.
func TestAnAssetLocationNamesTheDirectoryTheOperatorCanOpen(t *testing.T) {
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

	snapshot := t.TempDir() // what the engine reads: the private copy
	manifest := "# SPDX-License-Identifier: AGPL-3.0-only\n" +
		"apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\n" +
		"metadata: { name: assets, version: 1.0.0, title: Asset fixture }\n" +
		"services:\n  a:\n    use: modules/withsource@1.0.0\n"
	if err := os.WriteFile(filepath.Join(snapshot, "lab.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(snapshot, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapshot, "assets", "one.yml"),
		[]byte("token: ${secret:missing}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	display := filepath.Join(t.TempDir(), "the-authors-template")

	res, err := Validate(Options{Path: snapshot, Display: display, Library: DirLibrary(mods)})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range res.Findings {
		if f.Rule != RuleSecretRef || !strings.Contains(f.Message, "${secret:missing}") {
			continue
		}
		found = true
		if strings.HasPrefix(f.Path, snapshot) {
			t.Errorf("the finding names the snapshot the operator never sees: %s", f.Path)
		}
		if !strings.HasPrefix(f.Path, display) {
			t.Errorf("the finding does not name the template the operator can open: %s", f.Path)
		}
	}
	if !found {
		t.Fatalf("no finding for the asset's unresolved reference: %v", res.Findings)
	}

	// And the premise: every other finding already names the display
	// directory, which is the convention this one broke.
	other := Options{Path: snapshot, Display: display, Library: DirLibrary(mods)}
	if got := other.displayDir(); got != display {
		t.Fatalf("displayDir is %q, not the display directory", got)
	}
}
