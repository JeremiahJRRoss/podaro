// SPDX-License-Identifier: AGPL-3.0-only

package cli

// `podaro logs <instance> [service]` (Manual §15, API §7): a product's
// own account of itself, redacted.
//
// The redaction happens in the engine, not here: what arrives on this
// socket has already passed the instance's filter, so a client that
// writes it to a file, a pipe or a terminal cannot be the place a secret
// escapes.

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/jeremiahjrross/podaro/internal/api"
	"github.com/jeremiahjrross/podaro/internal/render"
)

func newLogs() *cobra.Command {
	var since string
	var tail int
	var follow bool
	cmd := &cobra.Command{
		Use:   "logs <instance> [service]",
		Short: "a service's own output, redacted",
		Long: "Print one service's logs. Secret values generated for the instance are filtered out " +
			"by the engine before they leave it. With no service named, the instance's services are listed.",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClient()
			instance := args[0]
			if len(args) == 1 {
				// Naming no service is not an error: the useful answer is
				// the list of names the next command needs.
				view, err := c.Instance(cmd.Context(), instance)
				if err != nil {
					return err
				}
				if len(view.Services) == 0 {
					render.Detect(os.Stdout).Plain("no services on " + instance + " yet")
					return nil
				}
				// It is not an error, so it does not leave as one: the
				// names print, the next command is offered, and the exit
				// status is zero. Returning PDR-E214 here sent the answer
				// through error rendering and made a discovery form fail
				// — the command's own Long has promised this listing
				// since it shipped.
				out := render.Detect(os.Stdout)
				out.Plain("services of " + instance + ":")
				names := make([]string, 0, len(view.Services))
				for _, s := range view.Services {
					names = append(names, s.Name)
					out.Indent(s.Name, 24, string(s.Stage))
				}
				out.NextAction("podaro logs " + instance + " " + names[0])
				return nil
			}
			// A follow ends on Ctrl-C, and the stream closes with it, so
			// the engine's own read stops rather than outliving the
			// client that asked for it.
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			stream, err := c.Logs(ctx, instance, args[1], since, tail, follow)
			if err != nil {
				return err
			}
			defer stream.Close()
			if _, err := io.Copy(os.Stdout, stream); err != nil && ctx.Err() == nil {
				return fmt.Errorf("reading the logs of %s/%s: %w", instance, args[1], err)
			}
			// The note goes to stderr, after the log: stdout stays
			// exactly the product's own words, so a pipe or a redirect
			// gets the log and nothing of ours — and the operator still
			// learns that what they are reading is a prefix.
			if stream.Truncated {
				fmt.Fprintf(os.Stderr, "note: this is the first %d MiB; the log is longer. "+
					"Narrow it with --since or --tail, or read it on the host.\n", api.MaxLogRead>>20)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&since, "since", "", "only lines newer than this (10m, 1h)")
	cmd.Flags().IntVar(&tail, "tail", 0, "only the last N lines")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "keep the stream open as lines arrive")
	return cmd
}
