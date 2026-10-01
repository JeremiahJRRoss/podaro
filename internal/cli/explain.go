// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
)

// newExplain builds `podaro explain PDR-Exxx` (API §5, plan S9). It reads
// the registry embedded in this binary — the one every emitted code has
// had an entry in since plan S1 — so it answers with no engine, no
// socket and no network: the moment an operator most needs an error
// explained is the moment the engine may be the thing that is wrong.
func newExplain() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain <PDR-CODE>",
		Short: "explain a PDR error code, offline",
		Long: "Expand a PDR error code: what it means, what causes it, the background " +
			"an operator needs, and what to do next. Read from the registry embedded in " +
			"this binary — no engine, no network.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			code := pdr.NormalizeCode(args[0])
			entry, ok := pdr.Lookup(code)
			if !ok {
				e := pdr.New(pdr.CodeExplainUnknown, "no such error code: %s", args[0])
				e.Cause = "this release's registry holds " + fmt.Sprint(len(pdr.Codes())) + " codes, and that is not one of them"
				e.Next = "podaro explain --list"
				if near := pdr.Near(code); len(near) > 0 {
					e.Next = "did you mean " + strings.Join(near, " or ") + "? · podaro explain --list"
				}
				return e
			}
			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{"error_help": entry})
			}
			p := render.Detect(os.Stdout)
			p.Explain(entry)
			return nil
		},
	}
	list := false
	cmd.Flags().BoolVar(&list, "list", false, "list every code this release can emit")
	cmd.Args = func(c *cobra.Command, args []string) error {
		if list {
			return cobra.NoArgs(c, args)
		}
		return cobra.ExactArgs(1)(c, args)
	}
	runOne := cmd.RunE
	cmd.RunE = func(c *cobra.Command, args []string) error {
		if !list {
			return runOne(c, args)
		}
		codes := pdr.Codes()
		if jsonOut {
			out := make([]pdr.Entry, 0, len(codes))
			for _, code := range codes {
				e, _ := pdr.Lookup(code)
				out = append(out, e)
			}
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"error_help": out})
		}
		p := render.Detect(os.Stdout)
		for _, code := range codes {
			e, _ := pdr.Lookup(code)
			p.Plain(fmt.Sprintf("%-10s %s", e.Code, e.Title))
		}
		return nil
	}
	return cmd
}
