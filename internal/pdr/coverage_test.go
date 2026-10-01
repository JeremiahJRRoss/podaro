// SPDX-License-Identifier: AGPL-3.0-only

package pdr

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var codeLiteral = regexp.MustCompile(`PDR-[EW]\d{3}`)

// Every code this engine can emit has a registry entry — the same-change
// rule made executable over the source rather than over a
// hand-kept list, which is what plan S9 asks for: `podaro explain` is
// only as good as the registry behind it, and a code with no entry is a
// dead end at exactly the moment an operator needs an explanation.
//
// The scan reads every non-test Go file under internal/ and cmd/, so a
// code emitted as a bare literal is caught as surely as one behind a
// constant. Test files are excluded: they name codes that must *not* be
// registered — the unknown-code cases that prove the refusal path.
func TestEveryEmittedCodeHasARegistryEntry(t *testing.T) {
	root := filepath.Join("..", "..")
	found := map[string][]string{}
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			for _, code := range codeLiteral.FindAllString(string(raw), -1) {
				found[code] = append(found[code], rel)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", dir, err)
		}
	}
	if len(found) < 40 {
		t.Fatalf("the scan found only %d codes in the source; it is not reading the tree", len(found))
	}
	var missing []string
	for code, files := range found {
		if _, ok := Lookup(code); !ok {
			sort.Strings(files)
			missing = append(missing, code+" ("+files[0]+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("codes emitted with no registry entry — add one in the same change: %s", strings.Join(missing, ", "))
	}
	// The other direction is a weaker claim and deliberately a warning:
	// a registered code no source file names may be emitted through a
	// variable, or may be waiting for the step that emits it.
	for _, code := range Codes() {
		if _, ok := found[code]; !ok {
			t.Logf("registered but not named in the source: %s", code)
		}
	}
}
