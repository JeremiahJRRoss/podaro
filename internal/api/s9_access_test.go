// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

func newAccessHarness(t *testing.T) (srvURL string, api *Server, authSvc *auth.Service, cookie string, client *http.Client) {
	t.Helper()
	srv, api, authSvc, _ := newNetworkServerIn(t)
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	if err := storeOf[api].PutInstance(state.Instance{
		Name: "lab", Template: "t", Mode: "delivery", Source: "/s", Created: now, Updated: now,
	}); err != nil {
		t.Fatal(err)
	}
	resp := do(t, srv, http.MethodPost, "/auth/session", map[string]string{"Content-Type": "application/json"},
		`{"username":"jross","password":"correct horse battery"}`)
	readAll(resp)
	for _, c := range resp.Cookies() {
		if c.Name == auth.CookieName {
			cookie = auth.CookieName + "=" + c.Value
		}
	}
	if cookie == "" {
		t.Fatal("the operator did not sign in")
	}
	// A cookie-authenticated write carries the session's CSRF value
	// (API §2.2); the operator's own console does the same.
	resp = do(t, srv, http.MethodGet, "/auth/session", map[string]string{"Cookie": cookie}, "")
	var who map[string]any
	if err := json.Unmarshal([]byte(readAll(resp)), &who); err != nil {
		t.Fatalf("whoami: %v", err)
	}
	inner, _ := who["session"].(map[string]any)
	token, _ := inner["csrf"].(string)
	if token == "" {
		t.Fatalf("the session carries no csrf: %v", who)
	}
	testCSRF[cookie] = token
	return srv.URL, api, authSvc, cookie, srv.Client()
}

// testCSRF keeps each signed-in cookie's CSRF value, so request() can
// send it on writes as a browser would.
var testCSRF = map[string]string{}

func jsonBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var out map[string]any
	raw := readAll(resp)
	if raw == "" {
		return out
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		// A route that does not exist answers plain text; the caller
		// judges the status, which is the point of those cases.
		return map[string]any{"body": raw}
	}
	return out
}

func request(t *testing.T, client *http.Client, url, method, path, cookie, body string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, url+Prefix+path, strings.NewReader(body))
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
		req.Header.Set("Content-Type", "application/json")
		if token := testCSRF[cookie]; token != "" && method != http.MethodGet {
			req.Header.Set(auth.CSRFHeader, token)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp, jsonBody(t, resp)
}

// Plan S9, API §2.4: an operator issues an attendee credential for one
// instance, the attendee exchanges it for a session scoped to that
// instance, and every issue, join and revocation lands in the audit
// stream — without the secret ever appearing anywhere but the one
// response that mints it.
func TestInstanceAccessIssueJoinAndRevoke(t *testing.T) {
	url, api, _, cookie, client := newAccessHarness(t)

	resp, out := request(t, client, url, http.MethodPost, "/instances/lab/access", cookie, `{"name":"alice","expires":"2h"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("issue: %d %v", resp.StatusCode, out)
	}
	secret, _ := out["token"].(string)
	if !auth.WellFormedAccessSecret(secret) {
		t.Fatalf("the issued secret is a pdi_ credential: %q", secret)
	}
	acc, _ := out["access"].(map[string]any)
	if acc["name"] != "alice" || acc["prefix"] == "" {
		t.Fatalf("the record carries the name and the prefix: %v", acc)
	}
	if _, has := acc["hash"]; has {
		t.Fatalf("a record never carries the hash: %v", acc)
	}
	link, _ := out["join"].(string)
	if !strings.HasPrefix(link, "https://lab.lab.test:8443") || !strings.Contains(link, secret) {
		t.Fatalf("the join link is on the instance's own hostname: %q", link)
	}

	// The listing shows it, without the secret.
	resp, out = request(t, client, url, http.MethodGet, "/instances/lab/access", cookie, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: %d %v", resp.StatusCode, out)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), secret) {
		t.Fatal("a listing carried the secret")
	}
	list, _ := out["access"].([]any)
	if len(list) != 1 {
		t.Fatalf("one credential, got %d", len(list))
	}
	first, _ := list[0].(map[string]any)
	if first["name"] != "alice" || first["last_used"] != nil {
		t.Fatalf("the listing before any join: %v", first)
	}
	id, _ := first["id"].(string)

	// Join: a session bound to the instance, carrying the attendee's name.
	resp, out = request(t, client, url, http.MethodGet, "/join/"+secret, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("join: %d %v", resp.StatusCode, out)
	}
	sess, _ := out["session"].(map[string]any)
	if sess["instance"] != "lab" || sess["subject"] != "alice" {
		t.Fatalf("the session is alice's, on lab: %v", sess)
	}
	joined := ""
	for _, c := range resp.Cookies() {
		if c.Name == auth.CookieName {
			joined = auth.CookieName + "=" + c.Value
		}
	}
	if joined == "" {
		t.Fatal("the join set no session cookie")
	}

	// That session reaches its instance and nothing above the grant.
	resp, _ = request(t, client, url, http.MethodGet, "/instances/lab", joined, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("an attendee reads their own instance: %d", resp.StatusCode)
	}
	resp, out = request(t, client, url, http.MethodDelete, "/instances/lab", joined, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("an attendee may not destroy: %d %v", resp.StatusCode, out)
	}
	// Logs are outside the grant: read scope, which an instance session
	// does not have (API §7). The endpoint lands with the rest of S9's
	// hardening; until then the route is absent, and absent is not
	// reachable either — the assertion holds across both.
	resp, out = request(t, client, url, http.MethodGet, "/instances/lab/services/web/logs", joined, "")
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("an attendee may not read logs: %d %v", resp.StatusCode, out)
	}
	resp, out = request(t, client, url, http.MethodPost, "/instances/lab/access", joined, `{"name":"mallory"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("an attendee may not issue credentials: %d %v", resp.StatusCode, out)
	}

	// The use is recorded against the credential.
	_, out = request(t, client, url, http.MethodGet, "/instances/lab/access", cookie, "")
	list, _ = out["access"].([]any)
	first, _ = list[0].(map[string]any)
	if first["last_used"] == nil {
		t.Fatalf("the join is recorded against the credential: %v", first)
	}

	// Revoke: the next join is refused.
	resp, out = request(t, client, url, http.MethodDelete, "/instances/lab/access/"+id, cookie, "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: %d %v", resp.StatusCode, out)
	}
	resp, out = request(t, client, url, http.MethodGet, "/join/"+secret, "", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a revoked link: %d %v", resp.StatusCode, out)
	}
	e, _ := out["error"].(map[string]any)
	if e["code"] != pdr.CodeSessionRefused {
		t.Fatalf("the refusal: %v", e)
	}

	// Every act is in the instance's audit stream, and none of them
	// carries the secret.
	records, err := storeOf[api].ListAudit("lab")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, rec := range records {
		seen[rec.Action] = true
		if strings.Contains(rec.Detail, secret) {
			t.Fatalf("an audit record carried the secret: %+v", rec)
		}
	}
	for _, action := range []string{"access-issue", "join", "access-revoke"} {
		if !seen[action] {
			t.Fatalf("the audit stream is missing %s: %+v", action, records)
		}
	}
}

func TestAJoinIsRefusedInOneShapeWhateverIsWrong(t *testing.T) {
	url, _, authSvc, cookie, client := newAccessHarness(t)
	for _, bad := range []string{"pdr_notanaccesstoken", "pdi_short", "nonsense", strings.Repeat("a", 60)} {
		resp, out := request(t, client, url, http.MethodGet, "/join/"+bad, "", "")
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%q: %d %v", bad, resp.StatusCode, out)
		}
		e, _ := out["error"].(map[string]any)
		msg, _ := e["message"].(string)
		if e["code"] != pdr.CodeSessionRefused || !strings.Contains(msg, "not valid") {
			t.Fatalf("%q: the refusal must not say which of the reasons it is: %v", bad, e)
		}
	}
	// An expired credential is refused in the same shape.
	resp, out := request(t, client, url, http.MethodPost, "/instances/lab/access", cookie, `{"name":"bob","expires":"1m"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("issue: %d %v", resp.StatusCode, out)
	}
	secret, _ := out["token"].(string)
	*clockOf[authSvc] = clockOf[authSvc].Add(2 * time.Minute)
	resp, out = request(t, client, url, http.MethodGet, "/join/"+secret, "", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("an expired link: %d %v", resp.StatusCode, out)
	}
}

func TestAnAccessCredentialIsRefusedWhenItAsksForTooMuch(t *testing.T) {
	url, _, _, cookie, client := newAccessHarness(t)
	for _, body := range []string{
		`{"name":"","expires":"1h"}`,
		`{"name":"Alice Smith","expires":"1h"}`,
		`{"name":"alice","expires":"48h"}`,
		`{"name":"alice","expires":"10s"}`,
		`{"name":"alice","expires":"soon"}`,
		`{"name":"alice","expiry":"1h"}`,
		`null`,
		`"alice"`,
	} {
		resp, out := request(t, client, url, http.MethodPost, "/instances/lab/access", cookie, body)
		if resp.StatusCode < 400 {
			t.Fatalf("%s was accepted: %d %v", body, resp.StatusCode, out)
		}
	}
	resp, out := request(t, client, url, http.MethodPost, "/instances/nope/access", cookie, `{"name":"alice"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an instance that does not exist: %d %v", resp.StatusCode, out)
	}
}
