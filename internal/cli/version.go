// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/brand"
)

// newVersion is `podaro version`. The plain line names the command and
// the version — `podaro v<version>`, which hack/release_package.sh checks
// the packaged binary prints — and `--json` adds the build's display name
// (internal/brand), which install.sh reads for its own lines.
func newVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "print the podaro version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(map[string]string{"version": podaro.Version(), "product": brand.Name, "title": brand.Title})
			}
			fmt.Printf("podaro v%s\n", podaro.Version())
			return nil
		},
	}
}
