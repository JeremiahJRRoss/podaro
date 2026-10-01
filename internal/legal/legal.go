// SPDX-License-Identifier: AGPL-3.0-only

// Package legal assembles what `podaro legal` prints, what GET
// /system/legal returns and what the console's /legal page shows (the
// reconciliation §7.2; the reconciliation plan's R5, tasks 3 and 4): the
// product and its version, the licence, the owner's two statements, the
// offer of this build's exact source, where releases are published and
// how to verify one, the pointer to the name policy, and a summary of the
// third-party material. Everything is read from the files the binary
// embeds (legal.go at the module root) — the two statements and the name
// pointer from NOTICE, the summary from THIRD-PARTY-NOTICES.md — so the
// command, the page and the files a release ships cannot say different
// things, and a rebranded build still says what NOTICE says.
package legal

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/brand"
)

// License is the licence of Podaro's first-party material (ADR-0004).
const License = "AGPL-3.0-only"

// Info is the legal summary of the running binary: GET /system/legal's
// body under "legal", `podaro legal --json`'s, and what the /legal page
// renders — the page renders nothing this does not hold (ADR-0003).
type Info struct {
	// Product and Title are the display name the binary was built with
	// (internal/brand); a rebranded build shows its own here and nowhere
	// else in this value.
	Product string `json:"product"`
	Title   string `json:"title"`
	Version string `json:"version"`
	// License is the SPDX identifier of the first-party material, and
	// LicenseText names the file that holds the licence's text.
	License     string `json:"license"`
	LicenseText string `json:"license_text"`
	// Copyright and Licensing are NOTICE's two statements (the owner's
	// Amendment 1), verbatim: the qualified copyright statement and,
	// separately, the licensing grant. Never a bare copyright claim.
	Copyright  string   `json:"copyright"`
	Licensing  string   `json:"licensing"`
	Source     Source   `json:"source"`
	Releases   Releases `json:"releases"`
	Trademarks string   `json:"trademarks"`
	// ThirdParty is THIRD-PARTY-NOTICES.md's component table: every
	// third-party component the binary compiles in or embeds, each under
	// its own licence.
	ThirdParty []Component `json:"third_party"`
	// Files are the legal files inside this binary, by the names they
	// have in the repository and the release tarball.
	Files []string `json:"files"`
}

// Source is the offer of this build's corresponding source.
type Source struct {
	// Build is "release" for a binary whose version names a release tag,
	// "unreleased" for one built from the development line (a VERSION
	// ending in -dev), which no tag holds.
	Build string `json:"build"`
	// Offer is the sentence that makes the offer.
	Offer string `json:"offer"`
	// URL and Tag are where a release build's exact source is: the tag
	// v<version> of the repository SOURCE names.
	URL string `json:"url,omitempty"`
	Tag string `json:"tag,omitempty"`
	// Repository is the canonical source location the build embeds (the
	// root SOURCE file).
	Repository string `json:"repository"`
	// Operator is config.yaml's legal.source_url when the operator set it:
	// their statement of where the source of the build they run is — the
	// downstream case, a build that no tag of Repository holds.
	Operator string `json:"operator,omitempty"`
}

// Releases says where releases are published and how one is verified —
// the only sense in which a build is the project's; no surface calls
// itself "official" (TRADEMARKS.md).
type Releases struct {
	URL    string `json:"url"`
	Verify string `json:"verify"`
}

// Component is one row of THIRD-PARTY-NOTICES.md's component table.
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	License string `json:"license"`
	How     string `json:"how"`
}

// Text is one embedded licence or notice file, whole.
type Text struct {
	Name string `json:"name"`
	Text string `json:"text"`
}

// Unreleased reports whether version is the development line's: a VERSION
// that ends in -dev (main reads 0.0.1-dev between releases) names no tag.
func Unreleased(version string) bool { return strings.HasSuffix(version, "-dev") }

// Build assembles the summary for this binary. operator is config.yaml's
// legal.source_url ("" when unset); it is printed as the operator's
// statement beside the build's own offer, never in place of it.
func Build(operator string) (Info, error) {
	files := podaro.LegalFiles()
	notice, err := fs.ReadFile(files, "NOTICE")
	if err != nil {
		return Info{}, err
	}
	paras := paragraphs(string(notice))
	pick := func(prefix string) (string, error) {
		for _, p := range paras {
			if strings.HasPrefix(p, prefix) {
				return p, nil
			}
		}
		return "", fmt.Errorf("the embedded NOTICE has no paragraph beginning %q", prefix)
	}
	copyright, err := pick("Copyright © 2026 Jeremiah Ross, to the extent copyright subsists")
	if err != nil {
		return Info{}, err
	}
	licensing, err := pick("To the extent copyright subsists, ")
	if err != nil {
		return Info{}, err
	}
	trademarks, err := pick("The Podaro name is covered separately by TRADEMARKS.md")
	if err != nil {
		return Info{}, err
	}
	third, err := fs.ReadFile(files, "THIRD-PARTY-NOTICES.md")
	if err != nil {
		return Info{}, err
	}
	components, err := componentTable(string(third))
	if err != nil {
		return Info{}, err
	}
	var names []string
	if err := fs.WalkDir(files, ".", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			names = append(names, path)
		}
		return err
	}); err != nil {
		return Info{}, err
	}
	sort.Strings(names)

	version := podaro.Version()
	repo := podaro.SourceURL()
	src := Source{Repository: repo, Operator: operator}
	if Unreleased(version) {
		src.Build = "unreleased"
		src.Offer = fmt.Sprintf("an unreleased build (v%s): no release tag holds its exact source — obtain its source from whoever gave you this binary", version)
	} else {
		src.Build = "release"
		src.Tag = "v" + version
		src.URL = repo + "/tree/" + src.Tag
		src.Offer = fmt.Sprintf("the source of %s v%s is at %s — the tag %s of %s", brand.Name, version, src.URL, src.Tag, repo)
	}
	return Info{
		Product:     brand.Name,
		Title:       brand.Title,
		Version:     version,
		License:     License,
		LicenseText: "LICENSE — the GNU Affero General Public License, version 3",
		Copyright:   copyright,
		Licensing:   licensing,
		Source:      src,
		Releases: Releases{
			URL: repo + "/releases",
			Verify: "official releases are published at " + repo + "/releases, each with a SHA256SUMS file beside its artifacts; " +
				"a download is one of them only if its digest is listed there — sha256sum --ignore-missing -c SHA256SUMS",
		},
		Trademarks: trademarks,
		ThirdParty: components,
		Files:      names,
	}, nil
}

// Texts returns the licence and notice texts `podaro legal --licenses`
// prints, whole, in reading order: the AGPL, NOTICE, every text under
// LICENSES/, then THIRD-PARTY-NOTICES.md — which carries every
// third-party licence and notice text the binary compiles in or embeds,
// the fonts' among them.
func Texts() ([]Text, error) {
	files := podaro.LegalFiles()
	order := []string{"LICENSE", "NOTICE"}
	extra, err := fs.Glob(files, "LICENSES/*")
	if err != nil {
		return nil, err
	}
	sort.Strings(extra)
	order = append(append(order, extra...), "THIRD-PARTY-NOTICES.md")
	out := make([]Text, 0, len(order))
	for _, name := range order {
		b, err := fs.ReadFile(files, name)
		if err != nil {
			return nil, err
		}
		out = append(out, Text{Name: name, Text: string(b)})
	}
	return out, nil
}

// DirFiles are the files <state>/legal/ holds: the release tarball's legal
// entries (RELEASE-MANIFEST.json aside, which is written per release and
// cannot be inside the binary whose digest it records).
func DirFiles() []string {
	return []string{"LICENSE", "NOTICE", "TRADEMARKS.md", "THIRD-PARTY-NOTICES.md", "LICENSES", "SOURCE-AND-BUILD.md"}
}

// WriteDir writes the embedded legal files to dir — `podaro system
// install`'s <state>/legal/, the bare-binary path's copy of what a
// tarball carries (the reconciliation §7.1). The directory is replaced
// whole: a file a newer binary no longer carries does not linger beside
// the ones it does, and a write that fails half-way leaves the previous
// copy in place.
func WriteDir(dir string) error {
	files := podaro.LegalFiles()
	next := dir + ".new"
	if err := os.RemoveAll(next); err != nil {
		return err
	}
	for _, top := range DirFiles() {
		err := fs.WalkDir(files, top, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			target := filepath.Join(next, filepath.FromSlash(path))
			if d.IsDir() {
				return os.MkdirAll(target, 0o755)
			}
			b, err := fs.ReadFile(files, path)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			return os.WriteFile(target, b, 0o644)
		})
		if err != nil {
			_ = os.RemoveAll(next)
			return err
		}
	}
	old := dir + ".old"
	_ = os.RemoveAll(old)
	if err := os.Rename(dir, old); err != nil && !errors.Is(err, fs.ErrNotExist) {
		_ = os.RemoveAll(next)
		return err
	}
	if err := os.Rename(next, dir); err != nil {
		_ = os.Rename(old, dir)
		return err
	}
	return os.RemoveAll(old)
}

// BesideFiles are the notices install.sh puts beside the installed binary
// (INSTALL §2 step 1, §5): the four a release's recipient reads first.
func BesideFiles() []string {
	return []string{"LICENSE", "NOTICE", "TRADEMARKS.md", "THIRD-PARTY-NOTICES.md"}
}

// placedBeside reports whether dir holds the notices a Podaro install put
// there: its NOTICE is Podaro's own, whose first line has named the
// project since the first release — by its current title, or by the
// title the project carried before the rename, which an installation
// made by an earlier build still holds beside its binary until an
// upgrade rewrites it. Nothing else in a directory the operator may share
// with other software is ever treated as ours.
func placedBeside(dir string) bool {
	b, err := os.ReadFile(filepath.Join(dir, "NOTICE"))
	if err != nil {
		return false
	}
	first, _, _ := strings.Cut(string(b), "\n")
	switch strings.TrimSpace(first) {
	case "Podaro Community", "Podaro DemoStudio":
		return true
	}
	return false
}

// RefreshBeside rewrites the notices beside the binary at exe from the
// copies it carries, when install.sh put them there — so that after
// `system upgrade` replaced the binary, the files beside it are the new
// binary's, not the ones the installer copied from an older release. A
// directory without them is left alone: no file is ever added beside a
// binary the installer did not place notices beside. It reports whether
// anything was rewritten.
func RefreshBeside(exe string) (bool, error) {
	dir := filepath.Dir(exe)
	if !placedBeside(dir) {
		return false, nil
	}
	files := podaro.LegalFiles()
	changed := false
	for _, name := range BesideFiles() {
		want, err := fs.ReadFile(files, name)
		if err != nil {
			return changed, err
		}
		path := filepath.Join(dir, name)
		if got, err := os.ReadFile(path); err == nil && string(got) == string(want) {
			continue
		}
		if err := os.WriteFile(path, want, 0o644); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}

// RemoveBeside removes the notices install.sh put beside the binary in
// dir — `system uninstall` removes them with the binary they cover — and
// reports whether there were any. Only a directory whose NOTICE is
// Podaro's own is touched.
func RemoveBeside(dir string) (bool, error) {
	if !placedBeside(dir) {
		return false, nil
	}
	for _, name := range BesideFiles() {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return true, err
		}
	}
	return true, nil
}

// paragraphs splits a plain-text file at blank lines, each paragraph's
// lines joined by single spaces — NOTICE wraps its sentences at 75
// columns, and a statement is compared and printed as one line.
func paragraphs(text string) []string {
	var out []string
	for _, block := range regexp.MustCompile(`\n[ \t]*\n`).Split(strings.ReplaceAll(text, "\r\n", "\n"), -1) {
		if p := strings.Join(strings.Fields(block), " "); p != "" {
			out = append(out, p)
		}
	}
	return out
}

var tableRow = regexp.MustCompile("^\\| (.+?) \\| (.+?) \\| (.+?) \\| (.+?) \\|$")

// componentTable reads the table under THIRD-PARTY-NOTICES.md's
// "## Components" heading, the generator's own format
// (hack/third_party_notices.sh).
func componentTable(text string) ([]Component, error) {
	at := strings.Index(text, "\n## Components\n")
	if at < 0 {
		return nil, errors.New("the embedded THIRD-PARTY-NOTICES.md has no component table")
	}
	var out []Component
	for _, line := range strings.Split(text[at:], "\n")[2:] {
		if line == "" {
			if len(out) > 0 {
				break
			}
			continue
		}
		m := tableRow.FindStringSubmatch(line)
		if m == nil || m[1] == "Component" || strings.HasPrefix(m[1], "---") {
			continue
		}
		// The table is Markdown; the summary is text, so its code spans
		// lose their backticks. "—" is the table's word for no version.
		unquote := func(s string) string { return strings.ReplaceAll(s, "`", "") }
		version := unquote(m[2])
		if version == "—" {
			version = ""
		}
		out = append(out, Component{Name: unquote(m[1]), Version: version, License: unquote(m[3]), How: unquote(m[4])})
	}
	if len(out) == 0 {
		return nil, errors.New("the embedded THIRD-PARTY-NOTICES.md's component table is empty")
	}
	return out, nil
}
