// SPDX-License-Identifier: AGPL-3.0-only

package system

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/config"
)

// socketPath points the process at a private runtime directory and
// returns the path the engine's door would take.
func socketPath(t *testing.T) string {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	dir := config.RuntimeDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "api.sock")
}

// The wait after a restart only stats the socket path. `Serve` binds the
// socket before the fallible part of startup — reconcile-on-start — so
// the path exists during a window in which the process is on its way to
// dying, and a socket left behind by a `kill -9` exists for good. The
// upgrade printed "service restarted" on the strength of a file, and
// then ignored the error from the read that would have caught it.
func TestTheRestartWaitsForAnEngineThatAnswers(t *testing.T) {
	// 1. A path that exists but nothing is listening on: what a crash
	// leaves behind.
	sock := socketPath(t)
	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := awaitEngine(400 * time.Millisecond); err == nil {
		t.Error("a socket file nothing answers on was taken for a running engine")
	}
	if err := os.Remove(sock); err != nil {
		t.Fatal(err)
	}

	// 2. Bound, accepting, and answering nothing: the window between
	// `net.Listen` and a `Start` that fails.
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	if _, err := awaitEngine(400 * time.Millisecond); err == nil {
		t.Error("an engine that accepts and says nothing was taken for a restarted one")
	}
	l.Close()
	<-done
	_ = os.Remove(sock)

	// 3. The control: an engine that answers the read the upgrade makes.
	l2, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"instances":[]}`))
		})}
	go func() { _ = srv.Serve(l2) }()
	defer srv.Close()
	if _, err := awaitEngine(3 * time.Second); err != nil {
		t.Errorf("an engine that answers was not recognised: %v", err)
	}
}
