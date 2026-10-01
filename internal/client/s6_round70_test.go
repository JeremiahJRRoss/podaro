// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/api"
	"github.com/jeremiahjrross/podaro/internal/engine"
)

// Review round 70: an evidence cutoff carrying fractional seconds was
// formatted with RFC3339, which drops them — moving the boundary back by
// up to a second, so the caller is handed entries from before the
// instant it asked about.
func TestAnEvidenceCutoffKeepsItsSubsecondPrecision(t *testing.T) {
	dir, err := os.MkdirTemp("", "pc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "api.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc(api.Prefix+"/instances/lab/evidence", func(w http.ResponseWriter, r *http.Request) {
		got <- r.URL.Query().Get("since")
		_ = json.NewEncoder(w).Encode(map[string]any{"evidence": []any{}})
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })

	since := time.Date(2026, 9, 6, 12, 0, 0, int(500*time.Millisecond), time.UTC)
	if _, err := New(sock).Evidence(context.Background(), "lab", engine.EvidenceFilter{Since: since}); err != nil {
		t.Fatal(err)
	}
	sent := <-got
	parsed, err := time.Parse(time.RFC3339Nano, sent)
	if err != nil {
		t.Fatalf("the cutoff %q is not a timestamp the engine parses: %v", sent, err)
	}
	if !parsed.Equal(since) {
		t.Fatalf("the boundary moved: sent %q (%s), the caller asked for %s", sent, parsed, since)
	}
}
