// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremiahjrross/podaro/internal/lab"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
)

// The authoring loop (User Manual §11, §15): `lab init` scaffolds (plan
// S10, lab_init.go), and `lab validate` and `lab plan` are the P0 exit
// gate (roadmap §10). Validate and plan read the caller's filesystem and
// are the internal twins of POST /lab/validate and /lab/plan (API §6).
func newLab() *cobra.Command {
	var modulesDir string
	cmd := &cobra.Command{
		Use:   "lab",
		Short: "authoring loop: scaffold, validate and plan a template directory",
	}
	cmd.PersistentFlags().StringVar(&modulesDir, "modules", "", "resolve use: references against this module directory instead of the installed library")
	library := func() *lab.Library {
		if modulesDir != "" {
			return lab.DirLibrary(modulesDir)
		}
		return lab.EmbeddedLibrary()
	}
	cmd.AddCommand(newLabInit(), newLabValidate(library), newLabPlan(library))
	return cmd
}

// validateJSON is the API §6 success body of POST /lab/validate.
type validateJSON struct {
	Valid    bool          `json:"valid"`
	Warnings []lab.Finding `json:"warnings"`
}

func newLabValidate(library func() *lab.Library) *cobra.Command {
	return &cobra.Command{
		Use:   "validate <template-dir>",
		Short: "schema + referential + policy validation, with file:line errors",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := lab.Validate(lab.Options{Path: args[0], Library: library()})
			if err != nil {
				return jsonOrErr(err, 2) // unreadable path: precondition, exit 2
			}
			if e := res.Error(); e != nil {
				// A lab that fails validation is a failed operation (exit 1)
				// whatever the leading code; only an unreadable path is a
				// precondition problem (exit 2, via Execute).
				if jsonOut {
					_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"error": e})
				} else {
					render.Detect(os.Stderr).Anatomy(e)
				}
				return exitErr{1}
			}
			warnings := res.Warnings
			if warnings == nil {
				warnings = []lab.Finding{}
			}
			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(validateJSON{Valid: true, Warnings: warnings})
			}
			p := render.Detect(os.Stdout)
			p.Check(render.Pass, args[0], len(args[0])+2, res.Summary())
			for _, w := range warnings {
				p.Check(render.Warn, w.Code, 10, w.Path+"  "+w.Message)
			}
			return nil
		},
	}
}

func newLabPlan(library func() *lab.Library) *cobra.Command {
	var profile string
	cmd := &cobra.Command{
		Use:   "plan <template-dir>",
		Short: "what create would do: services, images + digests, seeds, checkpoints by class, licenses",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			plan, res, err := lab.MakePlan(lab.PlanOptions{Options: lab.Options{Path: args[0], Library: library()}, Profile: profile})
			if err != nil {
				if res == nil {
					return jsonOrErr(err, 2) // unreadable path: precondition, exit 2
				}
				if jsonOut {
					_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"error": err})
				} else if pe, ok := err.(*pdr.Error); ok {
					render.Detect(os.Stderr).Anatomy(pe)
				} else {
					return err
				}
				return exitErr{1}
			}
			if jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{"plan": plan})
			}
			plan.Render(render.Detect(os.Stdout))
			return nil
		},
	}
	cmd.Flags().StringVar(&profile, "profile", "", "resource profile to plan with (default: standard when the template declares it)")
	return cmd
}

// jsonOrErr keeps the API §3 envelope on stdout under --json for errors
// raised before validation could run, with the same exit code the human
// path gets; without --json the error flows to Execute's anatomy.
func jsonOrErr(err error, code int) error {
	pe, ok := err.(*pdr.Error)
	if !ok || !jsonOut {
		return err
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"error": pe})
	return exitErr{code}
}
