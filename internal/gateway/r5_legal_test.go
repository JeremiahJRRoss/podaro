// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/api"
	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// The reconciliation plan's R5 (the reconciliation §7.2; threat model
// B1): the licence and source page, and its route, answer anyone who can
// reach the gateway — a visitor who never signed in, an attendee on their
// lab's hostname, and a session bound to one lab on any other hostname,
// because the public routes read no session to bind. The page carries the
// console's own headers and no session chrome, and every other path still
// denies until authenticated.
func TestTheLegalPageIsPublic(t *testing.T) {
	r := newRig(t)
	r.up("t1")
	boundElsewhere := func() map[string]string {
		sess := &state.Session{ID: "s-other", Subject: "alice", Mechanism: "instance-access", Instance: "other", CSRF: "c", Created: time.Now(), LastSeen: time.Now(), Expires: time.Now().Add(time.Hour)}
		if err := r.st.PutSession(*sess); err != nil {
			t.Fatal(err)
		}
		c, _ := r.auth.CookieValue(sess)
		return map[string]string{"Cookie": auth.CookieName + "=" + c}
	}()
	for _, c := range []struct {
		name, host string
		hdr        map[string]string
	}{
		{"a signed-out visitor at the apex", domain, nil},
		{"a signed-out visitor at a lab's hostname", "t1." + domain, nil},
		{"a session bound to another lab, at the apex", domain, boundElsewhere},
	} {
		resp := r.get(c.host, "/legal", c.hdr)
		page := body(resp)
		if resp.StatusCode != http.StatusOK || !strings.Contains(page, `<h1 id="legal-title">Licence and source</h1>`) {
			t.Fatalf("%s: /legal answered %d\n%s", c.name, resp.StatusCode, page)
		}
		if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") || resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: the page lacks the console's headers: %v", c.name, resp.Header)
		}
		if strings.Contains(page, "signed in as") || strings.Contains(page, `action="/logout"`) {
			t.Errorf("%s: the public page carries session chrome", c.name)
		}
		if !strings.Contains(page, "<title>Licence and source · Podaro</title>") || !strings.Contains(page, `<a class="brand" href="/">`) {
			t.Errorf("%s: the page's title or wordmark", c.name)
		}
		resp = r.get(c.host, api.Prefix+"/system/legal", c.hdr)
		if b := body(resp); resp.StatusCode != http.StatusOK || !strings.Contains(b, `"license":"AGPL-3.0-only"`) {
			t.Fatalf("%s: GET /system/legal answered %d %s", c.name, resp.StatusCode, b)
		}
	}
	// The binding still holds for everything that reads a session.
	resp := r.get(domain, api.Prefix+"/instances", boundElsewhere)
	if b := body(resp); resp.StatusCode != http.StatusForbidden || !strings.Contains(b, pdr.CodeSessionRefused) {
		t.Fatalf("a bound session elsewhere on a non-public route: %d %s", resp.StatusCode, b)
	}
	for _, path := range []string{api.Prefix + "/system", api.Prefix + "/instances", api.Prefix + "/healthz"} {
		resp := r.get(domain, path, nil)
		body(resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s signed out: %d, want 401", path, resp.StatusCode)
		}
	}
	resp = r.do(http.MethodPost, domain, "/legal", nil, "")
	body(resp)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /legal: %d", resp.StatusCode)
	}
}

// Every page links to /legal — the sign-in page included, so a visitor
// who has never signed in reaches the source offer — and the link is
// relative: the sign-in and home pages carry no URL off the gateway
// (hack/gateway_test.sh holds the served pages to the same rule).
func TestEveryPageLinksToTheLegalPage(t *testing.T) {
	r := newRig(t)
	external := regexp.MustCompile(`https?://[^"' ]+`)
	for _, c := range []struct {
		path string
		hdr  map[string]string
	}{
		{"/login", nil},
		{"/", map[string]string{"Cookie": auth.CookieName + "=" + r.cookie}},
	} {
		resp := r.get(domain, c.path, c.hdr)
		page := body(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", c.path, resp.StatusCode)
		}
		if !strings.Contains(page, `<a href="/legal">Licence and source</a>`) {
			t.Errorf("%s does not link to /legal:\n%s", c.path, page)
		}
		for _, u := range external.FindAllString(page, -1) {
			if !strings.Contains(u, domain) {
				t.Errorf("%s carries a URL off the gateway: %s", c.path, u)
			}
		}
	}
}

// The page is rate-limited per source like its route: a burst, then 429,
// rendered as the console's error page with its Retry-After.
func TestTheLegalPageIsRateLimited(t *testing.T) {
	r := newRig(t)
	var refused *http.Response
	var page string
	for i := 0; i < 80 && refused == nil; i++ {
		resp := r.get(domain, "/legal", nil)
		b := body(resp)
		if resp.StatusCode == http.StatusTooManyRequests {
			refused, page = resp, b
		} else if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: %d", i+1, resp.StatusCode)
		}
	}
	if refused == nil {
		t.Fatal("eighty requests from one source were never refused")
	}
	if refused.Header.Get("Retry-After") == "" || !strings.Contains(page, pdr.CodePublicThrottled) || !strings.Contains(page, "<!doctype html>") {
		t.Fatalf("the refusal: Retry-After %q\n%s", refused.Header.Get("Retry-After"), page)
	}
}
