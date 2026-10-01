// SPDX-License-Identifier: AGPL-3.0-only

package podaro

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sync"
)

// Embedded assets extracted by `podaro system install` (INSTALL §2 step 2:
// "extracted from binary (no downloads)"). At plan step S1 these were
// stubs; the console bundle arrived at S5 and the starter template at S2
// (TestEmbedded holds the catalog to it).

//go:embed console
var consoleAssets embed.FS

//go:embed scenarios
var starterCatalog embed.FS

// The frozen interface schemas and the module library travel inside the
// binary too (plan S3): `lab validate` and `lab plan` must work on a clean
// machine from the binary alone, with no repository checkout beside it.

//go:embed schemas
var schemaFiles embed.FS

//go:embed modules
var moduleLibrary embed.FS

// The retirement manifest, hack/retirement.json, is embedded too — by
// retirement.go, which exposes it as Retirement() for the retired-name
// diagnostics (PDR-E106, PDR-E107) and R3's catalog filter.

// ConsoleAssets returns the embedded console static bundle.
func ConsoleAssets() fs.FS {
	sub, err := fs.Sub(consoleAssets, "console")
	if err != nil {
		panic(err)
	}
	return sub
}

var (
	revisionOnce    sync.Once
	consoleRevision string
)

// ConsoleRevision is the console bundle's content revision: a short
// digest of every file under console/assets, computed once from the
// embedded bundle. The shell puts it in the asset URLs' `?v=` — the
// gateway serves assets `public, max-age=86400`, so the key must change
// whenever a bundle does, and the release number does not on an
// in-place upgrade of a dev build: a browser that had the old console.js
// cached under it would run new markup against a script without the
// component the markup names.
func ConsoleRevision() string {
	revisionOnce.Do(func() { consoleRevision = revisionOf(ConsoleAssets(), "assets") })
	return consoleRevision
}

// revisionOf digests every file under root in fsys — path, size and
// contents, in walk order, which is lexical and so stable — to twelve
// hex characters: enough to differ on any change, short enough for a
// URL.
func revisionOf(fsys fs.FS, root string) string {
	h := sha256.New()
	_ = fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		fmt.Fprintf(h, "%s\x00%d\x00", path, len(data))
		h.Write(data)
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// StarterCatalog returns the embedded starter templates.
func StarterCatalog() fs.FS {
	sub, err := fs.Sub(starterCatalog, "scenarios")
	if err != nil {
		panic(err)
	}
	return sub
}

// Schemas returns the embedded JSON Schemas (schemas/*.json) — the frozen
// shapes for templates, modules, playbooks, and checkpoints: v1alpha2, the
// current contract, and v1alpha1, frozen history the engine still reads.
func Schemas() fs.FS {
	sub, err := fs.Sub(schemaFiles, "schemas")
	if err != nil {
		panic(err)
	}
	return sub
}

// ModuleLibrary returns the embedded module library (modules/<name>/
// module.yaml) — the "installed module library" that `use:` resolves
// against (spec 0003 §3).
func ModuleLibrary() fs.FS {
	sub, err := fs.Sub(moduleLibrary, "modules")
	if err != nil {
		panic(err)
	}
	return sub
}
