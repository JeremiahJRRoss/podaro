// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/doctor"
	"github.com/jeremiahjrross/podaro/internal/render"
)

func newDoctor() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "environment diagnostics with exact remediations (reads only)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(config.Path())
			if err != nil {
				return err // config problems are doctor-shaped: exit 2
			}
			report := doctor.Run(doctor.Host{}, cfg)
			if jsonOut {
				if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
					return err
				}
			} else {
				report.Render(render.Detect(os.Stdout))
			}
			if report.Summary.Fail > 0 {
				return exitErr{2}
			}
			return nil
		},
	}
}
