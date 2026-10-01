// SPDX-License-Identifier: AGPL-3.0-only

package lab

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"

	podaro "github.com/jeremiahjrross/podaro"
)

// Library is the installed module library `use: modules/<name>@<version>`
// resolves against (spec 0003 §3): one directory per module holding
// module.yaml. The embedded library ships inside the binary; a directory
// library serves module authoring (`--modules DIR`).
type Library struct {
	fsys    fs.FS
	display string
}

// EmbeddedLibrary is the module library compiled into the binary.
func EmbeddedLibrary() *Library {
	return &Library{fsys: podaro.ModuleLibrary(), display: "modules"}
}

// DirLibrary serves modules from a directory on disk.
func DirLibrary(dir string) *Library {
	return &Library{fsys: os.DirFS(dir), display: dir}
}

// Load reads <name>/module.yaml. A missing module is reported by the
// caller as an unresolved reference; a present but unreadable one is
// PDR-E100 at the module's path.
func (l *Library) Load(name string) (*Document, error) {
	rel := path.Join(name, "module.yaml")
	return LoadDocument(l.fsys, rel, path.Join(l.display, rel))
}

// LibraryError is a module library that cannot be read at all — a
// `--modules DIR` that does not exist or cannot be traversed — as opposed
// to a module missing from a readable library.
type LibraryError struct {
	Dir string
	Err error
}

func (e *LibraryError) Error() string { return "module library " + e.Dir + ": " + e.Err.Error() }
func (e *LibraryError) Unwrap() error { return e.Err }

// Check reports an unreadable library root (a `--modules DIR` that does
// not exist or cannot be traversed) as a *LibraryError, before any module
// is looked up.
func (l *Library) Check() error {
	// Listing, not a stat: a root that exists but cannot be read (a file,
	// a directory without read permission) is just as unusable.
	if _, err := fs.ReadDir(l.fsys, "."); err != nil {
		return &LibraryError{Dir: l.display, Err: err}
	}
	return nil
}

// Has reports whether the library holds a module of that name. A present
// but unreadable module (permissions, a file where the directory should
// be) is reported as an error, never as "not installed"; an unreadable
// library root is a *LibraryError.
func (l *Library) Has(name string) (bool, error) {
	if err := l.Check(); err != nil {
		return false, err
	}
	_, err := fs.Stat(l.fsys, path.Join(name, "module.yaml"))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, err
	}
}

// Pin copies the named modules' definitions into dir (one directory per
// module holding module.yaml), so a delivery instance can keep resolving
// against exactly the definitions it was admitted with (invariant 4) —
// a later binary, with a later embedded library, changes nothing it runs.
func (l *Library) Pin(dir string, names []string) error {
	for _, name := range names {
		raw, err := fs.ReadFile(l.fsys, path.Join(name, "module.yaml"))
		if err != nil {
			return &LibraryError{Dir: l.display, Err: err}
		}
		if err := os.MkdirAll(filepath.Join(dir, name), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name, "module.yaml"), raw, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// Names lists the installed module names, sorted.
func (l *Library) Names() []string {
	entries, err := fs.ReadDir(l.fsys, ".")
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if ok, _ := l.Has(e.Name()); e.IsDir() && ok {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}
