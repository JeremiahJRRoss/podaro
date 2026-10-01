// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremiahjrross/podaro/internal/render"
	"github.com/jeremiahjrross/podaro/internal/system"
)

// newSetup is INSTALL §2 step 4: domain, local CA, wildcard leaf, gateway.
func newSetup() *cobra.Command {
	var o system.SetupOptions
	cmd := &cobra.Command{
		Use:   "setup --domain <domain>",
		Short: "configure the domain and TLS, then open the gateway",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Whether --port was passed is the flag's own state: zero is a
			// port an operator can type, and an out-of-range one, so it must
			// reach the validation rather than read as no flag at all.
			o.PortGiven = cmd.Flags().Changed("port")
			return system.Setup(render.Detect(os.Stdout), o)
		},
	}
	cmd.Flags().StringVar(&o.Domain, "domain", "", "the parent domain instances live under (lab.example.com)")
	cmd.Flags().IntVar(&o.Port, "port", 0, "gateway port (default: the configured port, or 7777)")
	cmd.Flags().StringVar(&o.IP, "ip", "", "address to print in the DNS block (default: detected)")
	return cmd
}
