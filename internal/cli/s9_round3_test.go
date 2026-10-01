// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/api"
	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// serveLab runs the socket door over a store a test can fill.
func serveLab(t *testing.T) state.Store {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	store := state.NewMemory()
	svc := auth.NewService(store, filepath.Join(t.TempDir(), "auth.json"))
	srv := api.New(api.Options{Engine: engine.New(engine.Options{Store: store}), Auth: svc})
	if err := os.MkdirAll(filepath.Dir(socketPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", socketPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() { _ = http.Serve(l, srv.SocketHandler()) }()
	return store
}

// `podaro logs <instance>` with no service names the instance's services
// — the command's own Long says so, and the comment above the branch
// says naming none is not an error. It returned PDR-E214: a non-zero
// exit, the list rendered as an error's cause, and a documented
// discovery form that fails.
func TestLogsWithoutAServiceListsThem(t *testing.T) {
	store := serveLab(t)
	now := time.Now().UTC().Truncate(time.Second)
	if err := store.PutInstance(state.Instance{Name: "demo", Template: "t", Mode: "delivery",
		Source: "/s", Created: now, Updated: now, Stage: state.StageReady}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"grafana", "prometheus"} {
		if err := store.PutService(state.Service{Instance: "demo", Name: name, Module: name,
			Image: "docker.io/library/" + name, Container: "pdr-demo-" + name, Stage: state.StageReady}); err != nil {
			t.Fatal(err)
		}
	}

	code, out, errOut := run(t, "logs", "demo")
	if code != 0 {
		t.Errorf("naming no service exits %d, want 0: %q", code, errOut)
	}
	if errOut != "" {
		t.Errorf("the listing went to stderr: %q", errOut)
	}
	for _, want := range []string{"grafana", "prometheus", "podaro logs demo grafana"} {
		if !strings.Contains(out, want) {
			t.Errorf("the listing does not carry %q:\n%s", want, out)
		}
	}
	// It is a listing, not a refusal wearing one.
	if strings.Contains(out, "PDR-E214") || strings.Contains(errOut, "PDR-E214") {
		t.Errorf("the listing is still an error:\n%s%s", out, errOut)
	}
}
