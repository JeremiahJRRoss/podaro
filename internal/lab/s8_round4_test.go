// SPDX-License-Identifier: AGPL-3.0-only

package lab

import (
	"os"
	"path/filepath"
	"testing"
)

// Round 1 made the both-contents check ask the document whether
// `content` was written, because an empty value is a file a template may
// ship and only the document can say what the author meant. `Document.Has`
// read the keys written in place and no others — and YAML's merge key
// (`<<: *anchor`) puts a key into a mapping just as surely: the decoder
// hands it to the struct either way. So a file that inherited `content`
// and declared `source` passed the check, and then had the inherited
// content silently overwritten by the asset — the two contents and no
// rule for which lands that this check exists to refuse.
func TestAnInheritedContentBesideASourceIsStillTwoContents(t *testing.T) {
	// The premise, proved on its own: a merge key really does give the
	// second file a content, so the case below is about two contents and
	// not about one.
	base := mergeLab(t, "")
	files := composedFiles(t, base)
	if len(files) != 2 || files[1].Content != "inherited\n" {
		t.Fatalf("the fixture's merge did not carry a content: %+v", files)
	}

	dir := mergeLab(t, "          source: assets/one.yml\n")
	if err := os.WriteFile(filepath.Join(dir, "assets", "one.yml"), []byte("from the asset\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Validate(Options{Path: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !mentions(res.Findings, RuleFileSource, "declares both content and source") {
		t.Errorf("a content inherited through a merge key beside a source was not caught; findings: %v", res.Findings)
		// And this is what passing it costs: the asset landed on top of
		// the content the author inherited, with nothing said.
		if got := composedFiles(t, dir); len(got) == 2 {
			t.Errorf("the inherited content was overwritten by the asset: %q", got[1].Content)
		}
	}
}

// mergeLab writes a template whose second file inherits its content from
// the first through YAML's merge key, plus whatever extra keys are given.
func mergeLab(t *testing.T, extra string) string {
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
		"      files:\n" +
		"        - &base\n" +
		"          path: /etc/base.yml\n" +
		"          content: \"inherited\\n\"\n" +
		"        - <<: *base\n" +
		"          path: /etc/one.yml\n" + extra
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func composedFiles(t *testing.T, dir string) []File {
	t.Helper()
	res, err := Validate(Options{Path: dir})
	if err != nil {
		t.Fatal(err)
	}
	if res.Composition == nil || res.Composition.Services["a"] == nil ||
		res.Composition.Services["a"].Module == nil || res.Composition.Services["a"].Module.Config == nil {
		t.Fatalf("the fixture's shape was refused: %v", res.Findings)
	}
	return res.Composition.Services["a"].Module.Config.Files
}
