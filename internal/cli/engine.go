// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/system"
)

// newEngine is the hidden service entrypoint the systemd unit execs. Not
// part of the documented CLI surface.
func newEngine() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "engine",
		Hidden: true,
		Short:  "engine process entrypoints (used by the service unit)",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "serve",
		Short: "run the engine: state, runtime, reconcile-on-start, the local socket door",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			return system.Serve(os.Stdout)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:    "simulate-reboot",
		Hidden: true,
		Short:  "fake runtime only: stop every container the way a host reboot would (hack/interrupt_test.sh)",
		Args:   cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			if os.Getenv(system.EnvRuntime) != "fake" {
				return fmt.Errorf("simulate-reboot exists for the fake runtime only (%s=fake); reboot a real host to test Podman", system.EnvRuntime)
			}
			return runtime.Reboot(system.FakeWorldPath(config.StateDir()))
		},
	})
	return cmd
}
