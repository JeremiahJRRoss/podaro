// SPDX-License-Identifier: AGPL-3.0-only

// Package fsx lands files durably: a temporary file beside the target,
// synced before the rename that puts it in place, the directory synced
// after — so what a caller reports done survives a power loss (INSTALL
// step 4). The atomic writes of setup and the engine — the certificate
// set, config.yaml, the operator record — go through it.
package fsx

import (
	"os"
	"path/filepath"
)

// Sync flushes a file or directory to stable storage. Tests replace it
// to prove a write's syncs happen, and in what order.
var Sync = func(f *os.File) error { return f.Sync() }

// WriteFile lands data at path, at mode, by a temporary file beside it
// (`<path>.tmp`): written, synced, closed, renamed into place, and the
// directory synced after. A failure at any point leaves the target as
// it was.
func WriteFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Chmod(mode); err != nil { // the umask never narrows it further, a file that was there takes it
		return fail(err)
	}
	if err := Sync(f); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return SyncDir(filepath.Dir(path))
}

// SyncDir flushes a directory to stable storage: the renames and
// creations inside it.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return Sync(d)
}
