// SPDX-License-Identifier: AGPL-3.0-only

package system

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// runUserBase is where logind keeps each account's runtime directory;
// tests point it at a temporary tree.
var runUserBase = "/run/user"

// sessionEnv completes env with the account's XDG_RUNTIME_DIR and
// DBUS_SESSION_BUS_ADDRESS when a shell has neither — `sudo -iu podaro`
// gives a login shell with no logind session (INSTALL §2; acceptance log
// 0002, deviation 1) — and the runtime directory and its bus socket exist,
// so `systemctl --user` reaches the account's service manager from any
// shell. Values already set are kept.
func sessionEnv(env []string) []string {
	value := func(key string) string {
		v := ""
		for _, kv := range env {
			if strings.HasPrefix(kv, key+"=") {
				v = strings.TrimPrefix(kv, key+"=")
			}
		}
		return v
	}
	runtimeDir := value("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		d := filepath.Join(runUserBase, strconv.Itoa(os.Getuid()))
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			runtimeDir = d
			env = append(env, "XDG_RUNTIME_DIR="+d)
		}
	}
	if value("DBUS_SESSION_BUS_ADDRESS") == "" && runtimeDir != "" {
		bus := filepath.Join(runtimeDir, "bus")
		if fi, err := os.Stat(bus); err == nil && fi.Mode()&os.ModeSocket != 0 {
			env = append(env, "DBUS_SESSION_BUS_ADDRESS=unix:path="+bus)
		}
	}
	return env
}

// systemctl is `systemctl --user <args>` with the account's session
// reachable, whatever shell the CLI runs in.
func systemctl(args ...string) *exec.Cmd {
	cmd := exec.Command("systemctl", append([]string{"--user"}, args...)...)
	cmd.Env = sessionEnv(os.Environ())
	return cmd
}
