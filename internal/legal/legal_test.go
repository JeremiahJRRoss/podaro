// SPDX-License-Identifier: AGPL-3.0-only

package legal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/brand"
)

// The owner's two formulations (Amendment 1; the mission §3, §5), exactly —
// hack/reconciliation_check.py's checks 9 and 10 hold NOTICE to the same
// words, and `podaro legal` and /legal print what NOTICE says.
const (
	formulation1 = "Copyright © 2026 Jeremiah Ross, to the extent copyright subsists in first-party material and such copyright is owned by Jeremiah Ross. No copyright is claimed in AI-generated material that is not eligible for copyright protection under applicable law."
	formulation2 = "To the extent copyright subsists, copyrightable first-party material owned by Jeremiah Ross is licensed under AGPL-3.0-only."
)

func TestTheSummaryCarriesNOTICEsStatementsVerbatim(t *testing.T) {
	info, err := Build("")
	if err != nil {
		t.Fatal(err)
	}
	if info.Copyright != formulation1 {
		t.Errorf("copyright statement:\n got %q\nwant %q", info.Copyright, formulation1)
	}
	if info.Licensing != formulation2 {
		t.Errorf("licensing grant:\n got %q\nwant %q", info.Licensing, formulation2)
	}
	if info.License != "AGPL-3.0-only" {
		t.Errorf("license = %q", info.License)
	}
	if !strings.Contains(info.Trademarks, "TRADEMARKS.md") || !strings.Contains(info.Trademarks, "grants no trademark rights") {
		t.Errorf("trademark pointer = %q", info.Trademarks)
	}
	// Never a bare copyright claim, never a registered mark, never "official" said of this build.
	// The forms are assembled at run time, so this file spells none of them for the
	// reconciliation's checks to read (hack/spdx_check_test.sh does the same).
	all := strings.Join([]string{info.Copyright, info.Licensing, info.Trademarks, info.Source.Offer}, " ")
	for _, bad := range []string{"All rights" + " reserved", "\u00ae", "registered" + " trademark", "Copyright © 2026 Jeremiah" + " Ross."} {
		if strings.Contains(all, bad) {
			t.Errorf("the summary carries %q", bad)
		}
	}
	if strings.Contains(strings.ToLower(info.Source.Offer), "official") {
		t.Errorf("the source offer calls the build official: %q", info.Source.Offer)
	}
	if info.Product != brand.Name || info.Title != brand.Title || info.Version != podaro.Version() {
		t.Errorf("product line = %q · %q · %q", info.Product, info.Title, info.Version)
	}
}

// The offer is bound to the build: an unreleased build says so and names
// no tag; a release build names its tag in the repository SOURCE names.
// The binary carries no commit (P1-close-out step 7), so the version is
// what decides.
func TestTheSourceOfferIsBoundToTheBuild(t *testing.T) {
	info, err := Build("")
	if err != nil {
		t.Fatal(err)
	}
	src := info.Source
	if src.Repository != podaro.SourceURL() || info.Releases.URL != podaro.SourceURL()+"/releases" {
		t.Errorf("repository %q · releases %q · SOURCE %q", src.Repository, info.Releases.URL, podaro.SourceURL())
	}
	if !strings.Contains(info.Releases.Verify, "sha256sum --ignore-missing -c SHA256SUMS") {
		t.Errorf("no verification instruction: %q", info.Releases.Verify)
	}
	if Unreleased(podaro.Version()) {
		if src.Build != "unreleased" || src.URL != "" || src.Tag != "" ||
			!strings.Contains(src.Offer, "obtain its source from whoever gave you this binary") {
			t.Errorf("an unreleased build's offer: %+v", src)
		}
	} else {
		want := podaro.SourceURL() + "/tree/v" + podaro.Version()
		if src.Build != "release" || src.URL != want || src.Tag != "v"+podaro.Version() || !strings.Contains(src.Offer, want) {
			t.Errorf("a release build's offer: %+v (want %s)", src, want)
		}
	}
	for version, unreleased := range map[string]bool{"0.0.1-dev": true, "0.2.0-dev": true, "0.1.0": false, "0.1.0-alpha.1": false} {
		if Unreleased(version) != unreleased {
			t.Errorf("Unreleased(%q) = %v", version, !unreleased)
		}
	}
	// The operator's statement is carried beside the build's own offer, never in place of it.
	withOperator, err := Build("https://git.example.com/fork/podaro")
	if err != nil {
		t.Fatal(err)
	}
	if withOperator.Source.Operator != "https://git.example.com/fork/podaro" || withOperator.Source.Offer != src.Offer {
		t.Errorf("operator statement: %+v", withOperator.Source)
	}
}

// The third-party summary is the notices file's component table, and it
// lists what the binary really carries — the Go runtime, a module the CLI
// is built on, the console's scripts and fonts, the embedded data.
func TestTheThirdPartySummaryIsTheNoticesTable(t *testing.T) {
	info, err := Build("")
	if err != nil {
		t.Fatal(err)
	}
	if len(info.ThirdParty) < 20 {
		t.Fatalf("%d components; THIRD-PARTY-NOTICES.md lists more", len(info.ThirdParty))
	}
	seen := map[string]string{}
	for _, c := range info.ThirdParty {
		if c.Name == "" || c.License == "" || c.How == "" {
			t.Errorf("an incomplete row: %+v", c)
		}
		seen[c.Name] = c.License
	}
	for name, lic := range map[string]string{
		"the Go standard library and runtime": "BSD-3-Clause",
		"github.com/spf13/cobra":              "Apache-2.0",
		"modernc.org/sqlite":                  "BSD-3-Clause",
	} {
		if seen[name] != lic {
			t.Errorf("%s: %q, want %q", name, seen[name], lic)
		}
	}
	var fonts, alpine bool
	for name, lic := range seen {
		fonts = fonts || (strings.Contains(name, "@ibm/plex-mono") && lic == "OFL-1.1")
		alpine = alpine || (strings.Contains(name, "@alpinejs/csp") && lic == "MIT")
	}
	if !fonts || !alpine {
		t.Errorf("the console's assets are missing from the summary (fonts %v, alpine %v)", fonts, alpine)
	}
	if strings.Join(info.Files, " ") != "LICENSE LICENSES/Apache-2.0.txt NOTICE SOURCE SOURCE-AND-BUILD.md THIRD-PARTY-NOTICES.md TRADEMARKS.md" {
		t.Errorf("files = %v", info.Files)
	}
}

// --licenses prints every embedded licence text: the AGPL first, NOTICE,
// the texts under LICENSES/, and the third-party notices — whose texts
// include the fonts' OFL.
func TestTextsAreEveryEmbeddedLicence(t *testing.T) {
	texts, err := Texts()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, x := range texts {
		names = append(names, x.Name)
		if x.Text == "" {
			t.Errorf("%s is empty", x.Name)
		}
	}
	if strings.Join(names, " ") != "LICENSE NOTICE LICENSES/Apache-2.0.txt THIRD-PARTY-NOTICES.md" {
		t.Fatalf("texts = %v", names)
	}
	if !strings.Contains(texts[0].Text, "GNU AFFERO GENERAL PUBLIC LICENSE") || !strings.Contains(texts[2].Text, "Apache License") {
		t.Error("LICENSE is not the AGPL, or LICENSES/Apache-2.0.txt is not the Apache text")
	}
	if !strings.Contains(texts[3].Text, "SIL OPEN FONT LICENSE") {
		t.Error("the third-party notices lack the fonts' licence")
	}
}

// The notices beside the binary follow it: rewritten from the running
// binary's copies when the installer placed them (an upgrade replaced the
// binary under them), removed with it at uninstall, and never added to —
// or taken from — a directory whose NOTICE is not Podaro's.
func TestTheNoticesBesideTheBinaryFollowIt(t *testing.T) {
	bin := t.TempDir()
	exe := filepath.Join(bin, "podaro")
	if err := os.WriteFile(exe, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A directory the installer never placed notices in: nothing is added.
	if changed, err := RefreshBeside(exe); err != nil || changed {
		t.Fatalf("RefreshBeside on a bare directory = %v, %v", changed, err)
	}
	if _, err := os.Stat(filepath.Join(bin, "NOTICE")); !os.IsNotExist(err) {
		t.Fatal("a NOTICE appeared beside a binary nobody placed notices beside")
	}
	// Another program's files by the same names are never ours.
	for _, name := range BesideFiles() {
		_ = os.WriteFile(filepath.Join(bin, name), []byte("someone else's "+name+"\n"), 0o644)
	}
	if changed, err := RefreshBeside(exe); err != nil || changed {
		t.Fatalf("RefreshBeside rewrote another program's files: %v, %v", changed, err)
	}
	if had, err := RemoveBeside(bin); err != nil || had {
		t.Fatalf("RemoveBeside took another program's files: %v, %v", had, err)
	}
	// The installer's copies of an older release — one made before the
	// rename, whose NOTICE still opens with the former title: rewritten to
	// this binary's.
	for _, name := range BesideFiles() {
		body := "an older release's " + name + "\n"
		if name == "NOTICE" {
			body = "Podaro DemoStudio\n\nan older release's NOTICE\n"
		}
		_ = os.WriteFile(filepath.Join(bin, name), []byte(body), 0o644)
	}
	if changed, err := RefreshBeside(exe); err != nil || !changed {
		t.Fatalf("RefreshBeside = %v, %v, want the older copies rewritten", changed, err)
	}
	for _, name := range BesideFiles() {
		got, _ := os.ReadFile(filepath.Join(bin, name))
		want, _ := os.ReadFile(filepath.Join("..", "..", name))
		if string(got) != string(want) {
			t.Errorf("%s beside the binary is not the binary's own copy", name)
		}
	}
	if changed, _ := RefreshBeside(exe); changed {
		t.Error("a second refresh rewrote files that were already current")
	}
	if had, err := RemoveBeside(bin); err != nil || !had {
		t.Fatalf("RemoveBeside = %v, %v", had, err)
	}
	for _, name := range BesideFiles() {
		if _, err := os.Stat(filepath.Join(bin, name)); !os.IsNotExist(err) {
			t.Errorf("%s was not removed", name)
		}
	}
	if _, err := os.Stat(exe); err != nil {
		t.Error("RemoveBeside touched the binary")
	}
}

// <state>/legal/ holds the tarball's legal entries, as files, and a second
// write replaces the directory whole: nothing stale is left beside them.
func TestWriteDirReplacesTheDirectoryWhole(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "legal")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "STALE"), []byte("an older release's file"), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := WriteDir(dir); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	_ = filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			rel, _ := filepath.Rel(dir, path)
			got = append(got, filepath.ToSlash(rel))
		}
		return err
	})
	if strings.Join(got, " ") != "LICENSE LICENSES/Apache-2.0.txt NOTICE SOURCE-AND-BUILD.md THIRD-PARTY-NOTICES.md TRADEMARKS.md" {
		t.Fatalf("<state>/legal/ holds %v", got)
	}
	for _, leftover := range []string{dir + ".new", dir + ".old"} {
		if _, err := os.Stat(leftover); !os.IsNotExist(err) {
			t.Errorf("%s left behind", leftover)
		}
	}
	notice, _ := os.ReadFile(filepath.Join(dir, "NOTICE"))
	if !strings.Contains(strings.Join(strings.Fields(string(notice)), " "), formulation1) {
		t.Error("the written NOTICE lacks the owner's statement")
	}
}
