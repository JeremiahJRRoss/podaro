// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/runtime"
)

// A non-following log read is capped at 4 MiB. Past the cap the answer
// was still `200`, ended with an ordinary EOF — possibly mid-line — and
// said nothing: an operator could read a prefix, miss the failure they
// were investigating, and have no way to know. The answer says which it
// is now, and the CLI prints the note to stderr so the log on stdout
// stays exactly the product's own words.
func TestALogCutShortSaysSo(t *testing.T) {
	srv, apiSrv, authSvc := newNetworkServer(t)
	eng := engineOf[apiSrv]
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	job, err := eng.Create(context.Background(), engine.CreateRequest{Path: fixture, Name: "long"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Wait(context.Background(), job.ID); err != nil {
		t.Fatal(err)
	}
	secret, _, err := authSvc.CreateToken("ro", auth.ScopeRead, "jross", auth.MechanismSocket)
	if err != nil {
		t.Fatal(err)
	}
	ro := map[string]string{"Authorization": "Bearer " + secret}

	// The premise: a short log is whole, and says nothing about being
	// cut — the header must mean something.
	resp := do(t, srv, http.MethodGet, "/instances/long/services/web/logs", ro, "")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get(HeaderTruncated) != "" {
		t.Fatalf("a whole log is not marked truncated: %d %q", resp.StatusCode, resp.Header.Get(HeaderTruncated))
	}
	if len(body) == 0 {
		t.Fatal("premise: the fake wrote no log at all")
	}

	// A log past the cap: the answer carries the first 4 MiB and says so.
	t.Setenv(runtime.EnvFakeLogBytes, strconv.Itoa(MaxLogRead+64<<10))
	resp = do(t, srv, http.MethodGet, "/instances/long/services/web/logs", ro, "")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("a long log still answers: %d", resp.StatusCode)
	}
	if got := resp.Header.Get(HeaderTruncated); got != "true" {
		t.Errorf("the answer does not say it was cut short: %q", got)
	}
	if len(body) != MaxLogRead {
		t.Errorf("the answer carries %d bytes, want the cap's %d", len(body), MaxLogRead)
	}
}
