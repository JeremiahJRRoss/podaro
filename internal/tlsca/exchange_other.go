// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package tlsca

import "errors"

// exchange is unavailable off Linux (Podaro serves from a Linux host);
// Publish falls back to two renames.
func exchange(a, b string) error { return errors.ErrUnsupported }
