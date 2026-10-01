// SPDX-License-Identifier: AGPL-3.0-only

package cli

// `podaro observe status|test` (Manual §4 and §15, roadmap §9): what the
// observability export is doing, and proof that the pipe works.
//
// Neither command can turn export on or change where it points. That is
// `config.yaml`, which the operator owns — the CLI reports and probes.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/observe"
	"github.com/jeremiahjrross/podaro/internal/render"
)

// observeColumn is the detail column of the observe block.
const observeColumn = 10

func newObserve() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "observe",
		Short: "observability export posture and probes",
		Long: "Podaro's own logs, metrics and traces, exported to destinations you configure " +
			"in config.yaml. Off by default. Nothing is ever sent to the project, or to anyone you did not configure.",
	}
	cmd.AddCommand(newObserveStatus(), newObserveTest())
	return cmd
}

func newObserveStatus() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "what the export is configured to do, and what has happened",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			p, err := newClient().ObservePosture(ctx)
			if err != nil {
				return err
			}
			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(p)
			}
			pr := render.Detect(os.Stdout)
			any := false
			for _, sig := range signals(p) {
				if sig.posture.Exporter == "off" {
					pr.Check(render.Pending, sig.name, observeColumn, "off")
					continue
				}
				any = true
				detail := sig.posture.Exporter + " → " + sig.posture.Endpoint
				pr.Check(render.Pass, sig.name, observeColumn, detail)
				if sig.posture.Insecure {
					pr.Indent("!", observeColumn, "insecure: this destination's certificate is not verified")
				}
			}
			pr.Blank()
			if !any {
				// The default, and worth saying in full: silence here is
				// a configuration choice, not a broken exporter.
				pr.Plain("export is off — Podaro is sending nothing anywhere.")
				pr.Plain("configure destinations under observability: in " + config.Path() + " (User Manual §4).")
				return nil
			}
			pr.Plain(fmt.Sprintf("%d exported · %d dropped · %d withheld · %d failed sends",
				p.Exported, p.Dropped, p.Withheld, p.Failures))
			if p.LastErr != "" {
				pr.Indent("last:", observeColumn, p.LastErr)
			}
			pr.NextAction("podaro observe test")
			return nil
		},
	}
}

func newObserveTest() *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "send one probe through each configured signal",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
			defer cancel()
			probes, err := newClient().ObserveTest(ctx)
			if err != nil {
				return err
			}
			if jsonOut {
				if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"probes": probes}); err != nil {
					return err
				}
				// The status is the command's answer and does not depend
				// on how it printed: automation reading `--json` was told
				// a broken export path is healthy.
				for _, pb := range probes {
					if !pb.OK {
						return exitErr{1}
					}
				}
				return nil
			}
			pr := render.Detect(os.Stdout)
			if len(probes) == 0 {
				pr.Plain("export is off — there is nothing to probe (User Manual §4).")
				return nil
			}
			failed := 0
			for _, pb := range probes {
				if pb.OK {
					pr.Check(render.Pass, pb.Signal, observeColumn,
						fmt.Sprintf("%s → %s · accepted in %d ms", pb.Exporter, pb.Endpoint, pb.TookMS))
					continue
				}
				failed++
				pr.Check(render.Fail, pb.Signal, observeColumn,
					fmt.Sprintf("%s → %s · %s", pb.Exporter, pb.Endpoint, pb.Error))
			}
			pr.Blank()
			if failed > 0 {
				// The probe is the truth: a destination that refused is
				// reported as refusing, and the command fails.
				pr.Plain(fmt.Sprintf("%d of %d signals did not land — the export is not working.", failed, len(probes)))
				return exitErr{1}
			}
			pr.Plain(fmt.Sprintf("%d of %d signals landed. Check the destination: the probe carries "+
				"body \"podaro observe test\".", len(probes), len(probes)))
			return nil
		},
	}
}

type namedSignal struct {
	name    string
	posture observe.SignalPosture
}

func signals(p observe.Posture) []namedSignal {
	return []namedSignal{{"logs", p.Logs}, {"metrics", p.Metrics}, {"traces", p.Traces}}
}
