// SPDX-License-Identifier: AGPL-3.0-only

package system

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A sudo -iu shell has neither variable; the account's runtime directory
// and bus socket exist because lingering is on. Both are filled in, and
// nothing already set is touched.
func TestSessionEnvFillsTheAccountSession(t *testing.T) {
	base, err := os.MkdirTemp("/tmp", "pdr-sess")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	old := runUserBase
	runUserBase = base
	t.Cleanup(func() { runUserBase = old })
	dir := filepath.Join(base, strconv.Itoa(os.Getuid()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	// No runtime directory bus yet: the directory is named, the bus is not.
	env := sessionEnv([]string{"PATH=/usr/bin"})
	if !has(env, "XDG_RUNTIME_DIR="+dir) || hasKey(env, "DBUS_SESSION_BUS_ADDRESS") {
		t.Fatalf("without a bus socket: %v", env)
	}

	l, err := net.Listen("unix", filepath.Join(dir, "bus"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	env = sessionEnv([]string{"PATH=/usr/bin"})
	if !has(env, "XDG_RUNTIME_DIR="+dir) || !has(env, "DBUS_SESSION_BUS_ADDRESS=unix:path="+filepath.Join(dir, "bus")) {
		t.Fatalf("with a bus socket: %v", env)
	}

	// Set values are kept — the systemd user service's own environment,
	// or an operator who pointed at another session on purpose.
	given := []string{"XDG_RUNTIME_DIR=/elsewhere", "DBUS_SESSION_BUS_ADDRESS=unix:path=/elsewhere/bus"}
	if got := sessionEnv(given); strings.Join(got, "\n") != strings.Join(given, "\n") {
		t.Fatalf("set values changed: %v", got)
	}
}

func has(env []string, kv string) bool {
	for _, e := range env {
		if e == kv {
			return true
		}
	}
	return false
}

func hasKey(env []string, key string) bool {
	for _, e := range env {
		if strings.HasPrefix(e, key+"=") {
			return true
		}
	}
	return false
}
