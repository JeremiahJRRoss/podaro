// SPDX-License-Identifier: AGPL-3.0-only

package podaro

import (
	"embed"
	"io/fs"
	"strings"
)

// The legal files travel inside the binary (the reconciliation §7.1–§7.2;
// the reconciliation plan's R5): whoever runs a copy — the operator at
// the shell, an attendee or a signed-out visitor at the console — reaches
// the licence, the notices and the offer of this build's source from the
// copy itself, never only from a tarball that a bare-binary install never
// downloads. `podaro legal` and the console's /legal page read them
// (internal/legal), and `podaro system install` writes them to
// <state>/legal/.
//
// An edit to any of these files changes the binary's bytes, so they are
// among the trees a documents-only closure commit may not touch
// (docs/code-execution/P1-close-out.md, step 7).
//
//go:embed LICENSE NOTICE TRADEMARKS.md THIRD-PARTY-NOTICES.md SOURCE-AND-BUILD.md LICENSES SOURCE
var legalFiles embed.FS

// LegalFiles returns the embedded legal files under the names they have
// at the repository's root and in the release tarball: LICENSE, NOTICE,
// TRADEMARKS.md, THIRD-PARTY-NOTICES.md, SOURCE-AND-BUILD.md, SOURCE and
// LICENSES/.
func LegalFiles() fs.FS { return legalFiles }

// SourceURL is the canonical source location this build names: the one
// line of the root SOURCE file. It is a location, not a commit — the
// binary carries no commit hash, so that a documents-only closure commit
// rebuilds the tested artifact byte for byte — and the version is what
// binds a release build to its tag there (SOURCE-AND-BUILD.md).
func SourceURL() string {
	b, err := legalFiles.ReadFile("SOURCE")
	if err != nil {
		panic("embedded SOURCE: " + err.Error()) // the embed directive above names it; a build without it does not compile
	}
	return strings.TrimSpace(string(b))
}
