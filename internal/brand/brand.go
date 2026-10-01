// SPDX-License-Identifier: AGPL-3.0-only

// Package brand is the product's display name, in one place, so that an
// independently named build is one build flag away (the reconciliation
// §6.5; TRADEMARKS.md, "Rebranding a build"):
//
//	go build -ldflags "-X $(go list -m)/internal/brand.Name=<name> -X $(go list -m)/internal/brand.Title=<title>" ./cmd/podaro
//
// The values are set when the binary is built and never from a request,
// a configuration file or the environment: a page title is not something
// a visitor or an operator can change on a running copy.
//
// What reads them: the console's page titles, its status-bar wordmark and
// the sign-in eyebrow, the CLI root's description, the evidence report's
// title and footer, the systemd unit's description, `podaro version
// --json` (which the installer reads for its own lines), and the product
// line of `podaro legal`. What never reads them is everything a fork must
// not have to change and a rename must not reach: the `podaro` binary and
// command, the `podaro_session` cookie, the `pdr-` labels, the API path
// `/api/v1alpha1`, the schema `$id`s, the state paths and the import path
// are compatibility identifiers; and the licence, NOTICE, the third-party
// notices and the source offer are the build's provenance, which stay as
// they are whatever the build is called (internal/legal).
package brand

// Name is the product's name as pages and commands show it. Podaro is
// the project's name and nothing more is claimed for it (TRADEMARKS.md).
var Name = "Podaro"

// Title is the product's full display title, as the governing documents
// use it.
var Title = "Podaro Community"
