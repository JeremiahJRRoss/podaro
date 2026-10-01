// SPDX-License-Identifier: AGPL-3.0-only

package cli

// `podaro access create|list|revoke` (Manual §15, API §2.4, plan S9):
// the operator's side of an attendee link.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremiahjrross/podaro/internal/render"
)

func newAccess() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "access",
		Short: "attendee access links for one instance",
		Long: "Issue, list and revoke attendee links. A link signs its holder into that " +
			"one lab and nothing else: no destroy, no reset, no logs, no other instance.",
	}
	cmd.AddCommand(newAccessCreate(), newAccessList(), newAccessRevoke())
	return cmd
}

func newAccessCreate() *cobra.Command {
	var name, expires string
	cmd := &cobra.Command{
		Use:   "create <instance>",
		Short: "issue an attendee link",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			out, err := newClient().IssueAccess(ctx, args[0], name, expires)
			if err != nil {
				return err
			}
			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(out)
			}
			p := render.Detect(os.Stdout)
			p.Plain(fmt.Sprintf("✓ access for %s on %s · expires %s", out.Access.Name, args[0], out.Access.Expires.Format(time.RFC3339)))
			p.Indent("link", 10, out.Join)
			p.Blank()
			// The secret is printed once because it is stored hashed: there
			// is no second chance to read it, and saying so is kinder than
			// letting an operator discover it later.
			p.Plain("  This link is shown once. Podaro keeps only its hash — issue a new one if it is lost.")
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "who the link is for (lowercase letters, digits, '-', '.', '_')")
	cmd.Flags().StringVar(&expires, "expires", "", "how long it lives (default 8h, at most 24h)")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func newAccessList() *cobra.Command {
	return &cobra.Command{
		Use:   "list <instance>",
		Short: "list an instance's attendee links",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			list, err := newClient().ListAccess(ctx, args[0])
			if err != nil {
				return err
			}
			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{"access": list})
			}
			p := render.Detect(os.Stdout)
			if len(list) == 0 {
				p.Plain("no access links on " + args[0])
				return nil
			}
			for _, a := range list {
				used := "never used"
				if a.LastUsed != nil {
					used = "last used " + a.LastUsed.Format(time.RFC3339)
				}
				p.Plain(fmt.Sprintf("%-16s %-10s expires %s · %s · id %s",
					a.Name, a.Prefix+"…", a.Expires.Format(time.RFC3339), used, a.ID))
			}
			return nil
		},
	}
}

func newAccessRevoke() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <instance> <id>",
		Short: "revoke an attendee link",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			if err := newClient().RevokeAccess(ctx, args[0], args[1]); err != nil {
				return err
			}
			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(map[string]string{"revoked": args[1]})
			}
			render.Detect(os.Stdout).Plain("✓ access " + args[1] + " revoked on " + args[0])
			return nil
		},
	}
}
