// SPDX-License-Identifier: AGPL-3.0-only

// Package cli wires the podaro command tree (UX Guide §7 grammar). Exit
// codes: 0 success · 1 the operation failed (anatomy on stderr) ·
// 2 preconditions/usage (doctor-shaped problems).
package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremiahjrross/podaro/internal/brand"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
)

var jsonOut bool

// exitErr carries an exit code for outcomes already rendered (a failing
// doctor board, an uninstall refusal) — no further printing wanted.
type exitErr struct{ code int }

func (e exitErr) Error() string { return fmt.Sprintf("exit %d", e.code) }

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use: "podaro",
		// The display name is the build's (internal/brand); the command is
		// `podaro` whatever the build is called.
		Short:         brand.Name + ": verified lab environments — demos, guided training, bug repros",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.PersistentFlags().BoolVar(&jsonOut, "json", false, "machine-readable output (read commands)")

	root.AddCommand(newVersion(), newLegal(), newExplain(), newAccess(), newObserve(), newDoctor(), newSystem(), newSetup(), newAuth(), newLab(), newUp(), newStatus(), newSeed(), newVerify(), newLogs(), newReset(), newDestroy(), newEngine())
	return root
}

// exitFor maps one error code to its UX §7 exit code. It is a function
// rather than a switch inside exitCode because a command that renders its
// own `--json` envelope has to exit with the same code the human path
// would: the code decides, never the call site.
func exitFor(code string) int {
	switch code {
	case pdr.CodeConfigUnreadable, pdr.CodeConfigUnknownKey, pdr.CodeConfigInvalid, pdr.CodeUninstallInstance, pdr.CodeUninstallUnreadable, pdr.CodeLabUnreadable,
		pdr.CodeLabInitTarget, pdr.CodeDestroyConfirm, pdr.CodeResetConfirm, pdr.CodeCreateRequest, pdr.CodeSetupFailed, pdr.CodePasswordPolicy:
		return 2 // precondition and usage problems — doctor-shaped (UX §7)
	default:
		return 1
	}
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	return exitCode(newRoot().Execute())
}

// exitCode maps a command's error to the UX §7 exit code, rendering the
// error anatomy on stderr where one applies.
func exitCode(err error) int {
	if err == nil {
		return 0
	}

	var ee exitErr
	if errors.As(err, &ee) {
		return ee.code
	}

	var pe *pdr.Error
	if errors.As(err, &pe) {
		render.Detect(os.Stderr).Anatomy(pe)
		return exitFor(pe.Code)
	}

	// Cobra-level problems (unknown command or flag) are usage errors.
	fmt.Fprintf(os.Stderr, "podaro: %v\n", err)
	return 2
}
