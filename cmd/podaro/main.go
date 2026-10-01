// SPDX-License-Identifier: AGPL-3.0-only

// Command podaro is the Podaro engine CLI (UX Guide §7 grammar; command
// surface per User Manual §15, growing step by step along the plan).
package main

import (
	"os"

	"github.com/jeremiahjrross/podaro/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
