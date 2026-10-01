// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/api"
	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/observe"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// serveObserve runs the socket door with an export configured to a
// destination that is not there, so every probe fails.
func serveObserve(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	store := state.NewMemory()
	exp, err := observe.New(observe.Options{
		Config: &config.Observability{
			// Port 1 on loopback: nothing listens, and the refusal is
			// immediate, so the probe fails for the plainest reason.
			Logs: &config.Signal{Exporter: "http", Endpoint: "http://127.0.0.1:1"},
		},
		Filter: func() (func(string) string, error) { return func(s string) string { return s }, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.NewService(store, filepath.Join(t.TempDir(), "auth.json"))
	srv := api.New(api.Options{Engine: engine.New(engine.Options{Store: store}), Auth: svc, Observe: exp})
	if err := os.MkdirAll(filepath.Dir(socketPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", socketPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() { _ = http.Serve(l, srv.SocketHandler()) }()
}

// `observe test` exits non-zero when a destination refuses its probe —
// that is the command's whole point, and the human-readable path does
// it. `--json` returned right after encoding, before the check, so
// automation reading the exit status was told a broken export path is
// healthy. The JSON is the same either way; only the status was wrong.
func TestJSONObserveTestFailsWhenAProbeDoes(t *testing.T) {
	serveObserve(t)
	code, out, _ := run(t, "--json", "observe", "test")
	if !strings.Contains(out, `"probes"`) || !strings.Contains(out, `"ok":false`) {
		t.Fatalf("the json body changed shape: %q", out)
	}
	if code != 1 {
		t.Errorf("exit %d for a probe that did not land — automation reads that as a healthy export", code)
	}

	// The human path already did this, and still must.
	if code, _, _ := run(t, "observe", "test"); code != 1 {
		t.Errorf("exit %d on the rendered path", code)
	}
}
