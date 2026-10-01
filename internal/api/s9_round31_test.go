// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// holdingLogs is the fake runtime with one difference: its log stream
// stays open until something closes it. The fake's own record is finite
// by design — it says so — so a follow it serves ends on its own, and a
// follow that ends on its own cannot show whether the credential that
// opened it is still checked.
type holdingLogs struct {
	*runtime.Fake
	r *io.PipeReader
	w *io.PipeWriter
}

func (h *holdingLogs) Logs(ctx context.Context, ref string, opts runtime.LogOptions) (io.ReadCloser, error) {
	if !opts.Follow {
		return h.Fake.Logs(ctx, ref, opts)
	}
	return h.r, nil
}

// A follow is a request that does not return, and the credential it was
// admitted with is read once, at the door. Signing out, revoking the
// token or reaching the idle expiry must close the stream: a `podman
// logs --follow` that keeps delivering a product's output to a revoked
// credential is a sign-out that did not sign anything out. The event
// feed re-checks on every tick (`credentialLive`); a follow did not.
func TestALogFollowStopsWhenItsCredentialDoes(t *testing.T) {
	dir := t.TempDir()
	fake, err := runtime.NewFake(filepath.Join(dir, "world.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fake.Close)
	pr, pw := io.Pipe()
	hold := &holdingLogs{Fake: fake, r: pr, w: pw}

	store := state.NewMemory()
	eng := engine.New(engine.Options{Store: store, Runtime: hold, StateDir: dir, PollInterval: 50 * time.Millisecond})
	t.Cleanup(func() { shutdown(eng) })
	authSvc := auth.NewService(store, filepath.Join(dir, "auth.json"))
	if err := authSvc.SetOperator("jross", "correct horse battery", false, auth.MechanismSocket); err != nil {
		t.Fatal(err)
	}
	api := New(Options{Engine: eng, Auth: authSvc, Address: func() (string, int) { return "lab.test", 8443 }})
	srv := httptest.NewServer(api.NetworkHandler())
	t.Cleanup(srv.Close)
	// After the server's, so it runs before it: httptest.Server.Close
	// waits for the handlers still running, and a follow blocked on this
	// pipe is one. Closing the pipe is what lets that handler return —
	// including on a tree where the fix is absent, so this test fails
	// there rather than hanging.
	t.Cleanup(func() { _ = pw.Close() })

	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	src, err := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "instances", "lab", "modules"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.PutInstance(state.Instance{
		Name: "lab", Template: "t", Mode: "delivery", Source: src, Created: now, Updated: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutService(state.Service{Instance: "lab", Name: "web", Image: "img", Container: "pdr-lab-web"}); err != nil {
		t.Fatal(err)
	}

	secret, _, err := authSvc.CreateToken("ci", auth.ScopeRead, "jross", auth.MechanismSocket)
	if err != nil {
		t.Fatal(err)
	}
	// The first line goes in before the request: an http.ResponseWriter
	// holds the header until the body starts, so a follow with nothing
	// to say yet has not answered yet either.
	go func() { _, _ = io.WriteString(pw, "before · the product is talking\n") }()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+Prefix+"/instances/lab/services/web/logs?follow=true", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the follow: %d", resp.StatusCode)
	}

	lines := make(chan string, 4)
	go func() {
		br := bufio.NewReader(resp.Body)
		for {
			line, err := br.ReadString('\n')
			if line != "" {
				lines <- strings.TrimRight(line, "\n")
			}
			if err != nil {
				close(lines)
				return
			}
		}
	}()
	select {
	case got, ok := <-lines:
		if !ok || got != "before · the product is talking" {
			t.Fatalf("the follow did not deliver its first line: %q (open %v)", got, ok)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the follow delivered nothing")
	}

	// The credential goes. Every new request from it is refused from
	// here on; this one is already inside.
	if err := authSvc.RevokeToken("ci", "jross", auth.MechanismSocket); err != nil {
		t.Fatal(err)
	}
	revoked := time.Now()
	go func() {
		for i := 0; i < 60; i++ {
			if _, err := io.WriteString(pw, "after · still talking\n"); err != nil {
				return
			}
			time.Sleep(300 * time.Millisecond)
		}
	}()
	// The check has a cadence, so up to one tick of output may still be
	// on its way — that residual is the documented one (THREAT_MODEL,
	// "a credential outliving an open stream"). What must not happen is
	// the stream staying open.
	deadline := time.After(20 * time.Second)
	var last time.Duration
	for {
		select {
		case got, ok := <-lines:
			if !ok {
				if closed := time.Since(revoked); closed > 10*time.Second {
					t.Fatalf("the follow took %s to notice its credential was gone", closed)
				}
				if last > 5*time.Second {
					t.Fatalf("a revoked credential was served the product's output %s after the revocation", last)
				}
				return // the stream closed: what a revocation is for
			}
			if strings.HasPrefix(got, "after") {
				last = time.Since(revoked)
			}
		case <-deadline:
			t.Fatal("the follow outlived its credential and was still open, delivering the product's output")
		}
	}
}
