// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package tlsca

import "golang.org/x/sys/unix"

// exchange swaps two paths in one atomic operation (renameat2 with
// RENAME_EXCHANGE, Linux 3.15+); filesystems without it return an error
// and Publish falls back to two renames.
func exchange(a, b string) error {
	return unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE)
}
