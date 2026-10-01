// SPDX-License-Identifier: AGPL-3.0-only

package podaro

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

// TestVendoredAssetsMatchManifest is ADR-0003's pin made executable: every
// vendored console asset listed in console/VENDOR.md hashes to its row,
// and every file under console/assets that looks vendored has a row.
func TestVendoredAssetsMatchManifest(t *testing.T) {
	raw, err := os.ReadFile("console/VENDOR.md")
	if err != nil {
		t.Fatal(err)
	}
	row := regexp.MustCompile("(?m)^\\| `([^`]+)` \\|.*\\| `([0-9a-f]{64})` \\|$")
	pinned := map[string]string{}
	for _, m := range row.FindAllStringSubmatch(string(raw), -1) {
		pinned[m[1]] = m[2]
	}
	if len(pinned) < 8 {
		t.Fatalf("VENDOR.md lists %d assets", len(pinned))
	}
	assets := ConsoleAssets()
	for name, want := range pinned {
		data, err := fs.ReadFile(assets, "assets/"+name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s: sha256 %s, VENDOR.md says %s — update the pin in the same commit", name, got, want)
		}
	}
	_ = fs.WalkDir(assets, "assets", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel := strings.TrimPrefix(path, "assets/")
		if strings.HasSuffix(rel, ".woff2") || strings.HasSuffix(rel, ".min.js") {
			if _, ok := pinned[rel]; !ok {
				t.Errorf("%s is vendored but not pinned in console/VENDOR.md", rel)
			}
		}
		return nil
	})
	// The stylesheet's font URLs carry their fonts' pins: assets are
	// cached for a day under their URL, the stylesheet's own cache key
	// cannot reach into its subresources, and a font upgraded under the
	// same name would otherwise serve old bytes for a day.
	// A new pin therefore changes the URL, here, or
	// this fails.
	css, err := fs.ReadFile(assets, "assets/console.css")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range pinned {
		if !strings.HasSuffix(name, ".woff2") {
			continue
		}
		if !strings.Contains(string(css), `url("`+name+`?v=`+want[:12]+`")`) {
			t.Errorf("console.css does not reference %s keyed by its pin %s", name, want[:12])
		}
	}
	if unkeyed := regexp.MustCompile(`url\("fonts/[^"?]+"\)`).FindAllString(string(css), -1); len(unkeyed) > 0 {
		t.Errorf("console.css references fonts without their pins: %v", unkeyed)
	}
}

// TestConsoleRevisionFollowsTheBundle: the asset URLs' cache key is the
// bundle's content, so it must move on any byte and on a rename, and
// stay put otherwise — and the embedded bundle's revision is twelve hex
// characters, the same every time it is asked (a release number does not move on an in-place upgrade of a dev build, and a day's cache then serves the old script to new markup).
func TestConsoleRevisionFollowsTheBundle(t *testing.T) {
	bundle := func(js, css string) fstest.MapFS {
		return fstest.MapFS{"assets/console.js": {Data: []byte(js)}, "assets/console.css": {Data: []byte(css)}}
	}
	a, same, changed := bundle("a", "b"), bundle("a", "b"), bundle("a", "c")
	renamed := fstest.MapFS{"assets/theme.js": {Data: []byte("a")}, "assets/console.css": {Data: []byte("b")}}
	if revisionOf(a, "assets") != revisionOf(same, "assets") {
		t.Fatal("the same bundle has two revisions")
	}
	if revisionOf(a, "assets") == revisionOf(changed, "assets") {
		t.Fatal("one byte changed and the revision did not")
	}
	if revisionOf(a, "assets") == revisionOf(renamed, "assets") {
		t.Fatal("a file was renamed and the revision did not change")
	}
	if rev := ConsoleRevision(); !regexp.MustCompile(`^[0-9a-f]{12}$`).MatchString(rev) || rev != ConsoleRevision() {
		t.Fatalf("ConsoleRevision() = %q", rev)
	}
	if rev, want := ConsoleRevision(), revisionOf(ConsoleAssets(), "assets"); rev != want {
		t.Fatalf("ConsoleRevision() = %q, the bundle digests to %q", rev, want)
	}
}

// TestEmbedded lists what the binary carries under scenarios/ and modules/
// and holds it to exactly the retained catalog: one template and the two
// modules it composes. The retired lab and its five modules left the tree
// with R2 of the reconciliation plan (the owner's mission of 2026-09-23,
// §7), and this is the check that none of them is built into the binary
// again; `go test -v -run TestEmbedded` prints the listing the
// reconciliation's A2 evidence records.
func TestEmbedded(t *testing.T) {
	for _, tree := range []struct {
		root string
		fsys fs.FS
		want []string
	}{
		{"scenarios", StarterCatalog(), []string{"grafana-prometheus-intro"}},
		{"modules", ModuleLibrary(), []string{"grafana", "prometheus"}},
	} {
		entries, err := fs.ReadDir(tree.fsys, ".")
		if err != nil {
			t.Fatalf("%s: %v", tree.root, err)
		}
		var got []string
		for _, e := range entries {
			got = append(got, e.Name())
		}
		if strings.Join(got, " ") != strings.Join(tree.want, " ") {
			t.Errorf("the binary embeds %s/ %v, want exactly %v", tree.root, got, tree.want)
		}
		err = fs.WalkDir(tree.fsys, ".", func(path string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				t.Logf("%s/%s", tree.root, path)
			}
			return err
		})
		if err != nil {
			t.Fatalf("%s: %v", tree.root, err)
		}
	}
}

// The retirement manifest is embedded byte for byte (hack/reconciliation_check.py's
// check 5 allows a retired name in a binary only inside an identical copy of
// it) and parses into the names the retired-name diagnostics read — PDR-E106,
// PDR-E107 and R3's catalog filter take them from here, never from a table.
func TestRetirementManifestIsEmbedded(t *testing.T) {
	onDisk, err := os.ReadFile("hack/retirement.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(RetirementManifestBytes()) != string(onDisk) {
		t.Fatal("the embedded retirement manifest differs from hack/retirement.json")
	}
	m := Retirement()
	if m.RetiredOn != "2026-09-23" || len(m.Scenarios) == 0 || len(m.Modules) == 0 ||
		len(m.Adapters.Product) == 0 || len(m.Adapters.Composites) == 0 || len(m.Generators) == 0 {
		t.Fatalf("the manifest parsed into less than it records: %+v", m)
	}
	for _, s := range m.Scenarios {
		if !m.Template(s.Name) {
			t.Errorf("Template(%q) = false", s.Name)
		}
	}
	for _, x := range m.Modules {
		if !m.Module(x.Name) {
			t.Errorf("Module(%q) = false", x.Name)
		}
	}
	for _, a := range append(append([]string(nil), m.Adapters.Product...), m.Adapters.Composites...) {
		if _, ok := m.Adapter(a); !ok {
			t.Errorf("Adapter(%q) = false", a)
		}
	}
	for _, g := range m.Generators {
		if !m.Generator(g) {
			t.Errorf("Generator(%q) = false", g)
		}
	}
	// The retained registries are never retired.
	for _, keep := range []string{"grafana-prometheus-intro", "grafana", "prometheus", "http", "container", "attest", "exec", "web-logs", "http-requests"} {
		_, adapter := m.Adapter(keep)
		if m.Template(keep) || m.Module(keep) || adapter || m.Generator(keep) {
			t.Errorf("%q is retained, and the manifest must not retire it", keep)
		}
	}
}

// Catalog is the reconciliation plan's R3 filter: every surface that
// offers templates reads the installed names through it. A retired name
// is split out, whatever else the catalog holds and in whatever order;
// the rest keep their order; a catalog without one comes back whole.
func TestTheCatalogFilterSplitsOutWhatTheManifestRetired(t *testing.T) {
	m := Retirement()
	retired := m.Scenarios[0].Name
	offered, out := m.Catalog([]string{"grafana-prometheus-intro", retired, "mine", "another"})
	if !reflect.DeepEqual(offered, []string{"grafana-prometheus-intro", "mine", "another"}) || !reflect.DeepEqual(out, []string{retired}) {
		t.Fatalf("Catalog split %v into %v and %v", []string{"grafana-prometheus-intro", retired, "mine", "another"}, offered, out)
	}
	offered, out = m.Catalog([]string{"grafana-prometheus-intro"})
	if !reflect.DeepEqual(offered, []string{"grafana-prometheus-intro"}) || out != nil {
		t.Fatalf("a catalog with nothing retired: %v %v", offered, out)
	}
	if offered, out = m.Catalog(nil); offered != nil || out != nil {
		t.Fatalf("an empty catalog: %v %v", offered, out)
	}
}
