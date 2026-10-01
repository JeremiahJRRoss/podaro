// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremiahjrross/podaro/internal/render"
	"github.com/jeremiahjrross/podaro/internal/system"
)

func newSystem() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "system",
		Short: "install, uninstall, and manage the podaro service",
	}
	cmd.AddCommand(newSystemInstall(), newSystemUpgrade(), newSystemUninstall(), newSystemStatus(), newSystemStart(), newSystemStop(), newSystemRestart())
	return cmd
}

// `podaro system status|start|stop|restart` (INSTALL §2 step 6, Manual
// §15): the unit through systemctl --user, with the account's session
// filled in, so they work from any shell the account gets.
func newSystemStatus() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "the service and the engine behind it: state, restarts, whether it answers",
		Long: "Read podaro.service from systemd and probe the engine on its socket. Exit 0 when the " +
			"unit is active and the engine answers; 1 when either is not; 2 when the unit is not " +
			"installed. --json prints the same facts as one object.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := system.ServiceStatusNow()
			if err != nil {
				return err
			}
			if jsonOut {
				if err := json.NewEncoder(os.Stdout).Encode(st); err != nil {
					return err
				}
			} else {
				system.RenderServiceStatus(render.Detect(os.Stdout), st)
			}
			switch {
			case !st.Loaded:
				return exitErr{2}
			case !st.Healthy():
				return exitErr{1}
			}
			return nil
		},
	}
}

func newSystemStart() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "start the service and wait for the engine to answer",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return system.ServiceStart(render.Detect(os.Stdout))
		},
	}
}

func newSystemStop() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "stop the service; labs keep running, the console does not answer until start",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return system.ServiceStop(render.Detect(os.Stdout))
		},
	}
}

func newSystemRestart() *cobra.Command {
	return &cobra.Command{
		Use:   "restart",
		Short: "restart the service and wait for the engine to reattach to its labs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return system.ServiceRestart(render.Detect(os.Stdout))
		},
	}
}

func newSystemInstall() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "self-extract assets and enable the user service (never root)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return system.Install(render.Detect(os.Stdout))
		},
	}
}

// `podaro system upgrade` (INSTALL §6): the one command in Podaro that
// reaches the network on its own behalf, and only when it is run.
func newSystemUpgrade() *cobra.Command {
	var from, to string
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "fetch a release, verify it, back up the state, and swap the binary",
		Long: "Download a release and its SHA256SUMS, verify the digest locally, back up the state " +
			"database, replace the binary and restart the service. Nothing is replaced until the " +
			"checksum matches. On a host with no route out, point --from at your own mirror.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return system.Upgrade(render.Detect(os.Stdout), system.UpgradeOptions{Base: from, Version: to})
		},
	}
	cmd.Flags().StringVar(&from, "from", "", "release location (default: "+system.DefaultReleaseBase+", the project's releases; a mirror for air-gapped hosts)")
	cmd.Flags().StringVar(&to, "to", "", "version to install (default: whatever the release location calls latest)")
	return cmd
}

func newSystemUninstall() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "remove the service, state, configuration, and binary",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p := render.Detect(os.Stdout)
			confirm := func() bool {
				if yes {
					return true
				}
				fmt.Print("confirm [y/N]: ")
				line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
				switch strings.ToLower(strings.TrimSpace(line)) {
				case "y", "yes":
					return true
				}
				return false
			}
			code, err := system.Uninstall(p, confirm)
			if err != nil {
				return err // aborted: anatomy on stderr, nothing removed
			}
			if code != 0 {
				return exitErr{code}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the confirmation prompt (scripts)")
	return cmd
}
