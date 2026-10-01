// SPDX-License-Identifier: AGPL-3.0-only

// Package podaro carries repository-level metadata shared by the engine
// and its commands.
package podaro

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var rawVersion string

// Version returns the semantic version recorded in the repository's
// VERSION file — the single source of truth for the release number.
func Version() string {
	return strings.TrimSpace(rawVersion)
}
