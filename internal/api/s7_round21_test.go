// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bufio"
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/engine"
)

// A credential is checked once, when a request is admitted (Server.handle
// reads the principal the door put on the context). The event feed's
// request does not return: it loops until the client goes away. So a
// session that expired, or a token that was revoked, went on receiving
// checkpoint and audit frames for as long as the socket stayed open —
// while every new request from the same credential was refused. A
// sign-out that leaves a stream running is not a sign-out.
//
// The feed re-checks the credential it opened with on its own tick, and
// ends the stream when it no longer resolves. It uses the peek that does
// *not* slide a session's idle expiry: an open stream is not activity, or
// a console left open would keep its own session alive for ever.
func TestTheFeedEndsWhenTheCredentialThatOpenedItDoes(t *testing.T) {
	srv, api, authSvc, _ := newNetworkServerIn(t)
	eng := engineOf[api]
	ctx := context.Background()
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	job, err := eng.Create(ctx, engine.CreateRequest{Path: fixture, Name: "watched"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Wait(ctx, job.ID); err != nil {
		t.Fatal(err)
	}

	resp := do(t, srv, http.MethodPost, "/auth/session", map[string]string{"Content-Type": "application/json"},
		`{"username":"jross","password":"correct horse battery"}`)
	readAll(resp)
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == auth.CookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("login set no session cookie")
	}
	sess, err := authSvc.Peek(cookie.Value)
	if err != nil || sess == nil {
		t.Fatalf("the fixture's session does not resolve: %v", err)
	}

	feedCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(feedCtx, http.MethodGet, srv.URL+Prefix+"/instances/watched/events", nil)
	req.Header.Set("Cookie", auth.CookieName+"="+cookie.Value)
	feed, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer feed.Body.Close()
	if feed.StatusCode != http.StatusOK {
		t.Fatalf("feed status %d", feed.StatusCode)
	}
	body := bufio.NewReader(feed.Body)
	v, err := eng.View("watched", engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := eng.Jobs("watched", engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	opening := readFrames(t, body, len(v.Services)+1+len(rows), 5*time.Second, cancel)
	if len(opening) == 0 {
		t.Fatal("the feed sent nothing while the session was good")
	}

	// The learner signs out. Every new request with this cookie is
	// refused from here on, and the stream must not outlive it.
	if err := authSvc.Logout(sess); err != nil {
		t.Fatal(err)
	}
	// The fixture produced the state before the behaviour is asserted:
	// the credential no longer resolves, and an ordinary request with it
	// is refused.
	if _, err := authSvc.Peek(cookie.Value); err == nil {
		t.Fatal("the fixture did not invalidate the session")
	}
	after := do(t, srv, http.MethodGet, "/auth/session", map[string]string{"Cookie": auth.CookieName + "=" + cookie.Value}, "")
	readAll(after)
	if after.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a request with the signed-out cookie was not refused: %d", after.StatusCode)
	}

	frames := readFrames(t, body, 3, 8*time.Second, cancel)
	ended := false
	for _, f := range frames {
		if f.Event == "end" {
			ended = true
		}
	}
	if !ended {
		t.Fatalf("the stream outlived the credential that opened it; frames after sign-out: %s", describe(frames))
	}
	// And it says why, in the stream's own grammar rather than by going
	// quiet — a feed that stops without a word looks like an idle lab.
	for _, f := range frames {
		if f.Event != "end" {
			continue
		}
		if reason, _ := f.Data["reason"].(string); !strings.Contains(reason, "credential") {
			t.Errorf("the end frame does not say the credential ended it: %v", f.Data)
		}
	}
}
