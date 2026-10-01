// SPDX-License-Identifier: AGPL-3.0-only

package podaro

import (
	"io/fs"
	"os"
	"sort"
	"strings"
	"testing"
)

// The binary carries every legal file the release tarball does (the plan's
// R5 task 5), byte for byte as the tree has it, and nothing a tarball
// build adds (RELEASE-MANIFEST.json is written per release and cannot be
// inside the binary whose digest it records).
func TestTheLegalFilesAreEmbeddedAsTheTreeHasThem(t *testing.T) {
	var got []string
	err := fs.WalkDir(LegalFiles(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		got = append(got, path)
		embedded, err := fs.ReadFile(LegalFiles(), path)
		if err != nil {
			return err
		}
		onDisk, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if string(embedded) != string(onDisk) {
			t.Errorf("the embedded %s differs from the tree's", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	want := []string{"LICENSE", "LICENSES/Apache-2.0.txt", "NOTICE", "SOURCE", "SOURCE-AND-BUILD.md", "THIRD-PARTY-NOTICES.md", "TRADEMARKS.md"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("embedded legal files %v, want %v", got, want)
	}
}

// SOURCE is one line, a location and nothing else: an https URL with no
// credential in it, no query and no fragment — it is printed on a page
// anyone who can reach the console may read.
func TestSourceIsOneHTTPSLocation(t *testing.T) {
	raw, err := os.ReadFile("SOURCE")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), "\n") != 1 || !strings.HasSuffix(string(raw), "\n") {
		t.Fatalf("SOURCE must be exactly one line: %q", raw)
	}
	u := SourceURL()
	if !strings.HasPrefix(u, "https://") || strings.ContainsAny(u, "@?# \t") || strings.HasSuffix(u, "/") {
		t.Fatalf("SOURCE = %q: want an https location with no userinfo, query, fragment or trailing slash", u)
	}
}
