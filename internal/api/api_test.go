// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/console"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/lab"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// The 428 gate answers with API §6.2's shape: each detail is
// {license, url}, never the finding shape {path, hint}.
func TestLicenseGateDetailsUseTheDocumentedFields(t *testing.T) {
	t.Setenv(runtime.EnvFakeReadyDelay, "100ms")
	dir := t.TempDir()
	fake, err := runtime.NewFake(filepath.Join(dir, "world.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fake.Close)
	eng := engine.New(engine.Options{Store: state.NewMemory(), Runtime: fake, StateDir: dir, Library: lab.DirLibrary(filepath.Join("..", "lab", "testdata", "modules"))})
	t.Cleanup(func() { shutdown(eng) })
	srv := httptest.NewServer(New(Options{Engine: eng}).SocketHandler())
	t.Cleanup(srv.Close)
	aliases, _ := filepath.Abs(filepath.Join("..", "lab", "testdata", "valid-aliases"))
	code, out := call(t, srv, http.MethodPost, "/instances", map[string]any{"path": aliases, "name": "lic"})
	if code != http.StatusPreconditionRequired {
		t.Fatalf("expected 428, got %d %v", code, out)
	}
	details, _ := out["error"].(map[string]any)["details"].([]any)
	if len(details) != 1 {
		t.Fatalf("one missing acceptance expected: %v", out)
	}
	d, _ := details[0].(map[string]any)
	if d["license"] != "custom-terms" || d["url"] == "" || d["url"] == nil {
		t.Fatalf("a license detail is {license, url}: %v", d)
	}
	for _, k := range []string{"path", "hint", "code"} {
		if _, present := d[k]; present {
			t.Fatalf("a license detail carries no %q: %v", k, d)
		}
	}
}

// A failed job's error is the §3 envelope object over the socket, null
// while there is none — never a JSON string to decode twice (API §4).
// And a create naming both sources is 400.
func TestJobErrorIsAStructuredEnvelope(t *testing.T) {
	srv, _ := newServer(t)
	dir := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx", "lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(string(raw), "budget: 1m }", "budget: 1ms }", 1)
	if body == string(raw) {
		t.Fatal("fixture readiness line changed; update the test")
	}
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := call(t, srv, http.MethodPost, "/instances", map[string]any{"path": dir, "name": "jerr"})
	if code != http.StatusAccepted {
		t.Fatalf("create: %d %v", code, out)
	}
	job := out["job"].(map[string]any)
	if v, present := job["error"]; !present || v != nil {
		t.Fatalf("a queued job carries error: null, got %v", out)
	}
	id := job["id"].(string)
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, out = call(t, srv, http.MethodGet, "/jobs/"+id, nil)
		if code != http.StatusOK {
			t.Fatalf("job: %d %v", code, out)
		}
		job = out["job"].(map[string]any)
		if job["state"] == "failed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the job never failed: %v", out)
		}
		time.Sleep(50 * time.Millisecond)
	}
	env, ok := job["error"].(map[string]any)
	if !ok || env["code"] != "PDR-E205" || env["message"] == "" {
		t.Fatalf("a failed job's error must be the envelope object: %v", job["error"])
	}
	if code, out := call(t, srv, http.MethodPost, "/instances", map[string]any{"path": dir, "template": "hello-nginx", "name": "both"}); code != http.StatusBadRequest || out["error"].(map[string]any)["code"] != "PDR-E212" {
		t.Fatalf("both sources must be 400 with E212: %d %v", code, out)
	}
}

// A body the engine cannot decode is a malformed create request —
// PDR-E212, 400 — never the invalid-name code.
func TestMalformedCreateBodyIsE212(t *testing.T) {
	srv, _ := newServer(t)
	resp, err := http.Post(srv.URL+"/api/v1alpha1/instances", "application/json", strings.NewReader("{not json"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest || out["error"].(map[string]any)["code"] != "PDR-E212" {
		t.Fatalf("malformed body: %d %v", resp.StatusCode, out)
	}
}

// One JSON object is the documented create body: trailing data after it,
// and a body naming no source, are malformed requests (PDR-E212, 400).
func TestCreateBodyMustBeOneObjectWithASource(t *testing.T) {
	srv, _ := newServer(t)
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	for _, body := range []string{
		`{"path":"` + fixture + `","name":"trail"} {"x":1}`,
		`{"path":"` + fixture + `","name":"trail"}garbage`,
		`{}`,
		`null`,
	} {
		resp, err := http.Post(srv.URL+Prefix+"/instances", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || out["error"].(map[string]any)["code"] != "PDR-E212" {
			t.Fatalf("body %q: %d %v", body, resp.StatusCode, out)
		}
	}
	if code, out := call(t, srv, http.MethodGet, "/instances/trail", nil); code != http.StatusNotFound {
		t.Fatalf("nothing may have been created from a malformed body: %d %v", code, out)
	}
}

func newServer(t *testing.T) (*httptest.Server, *engine.Engine) {
	t.Helper()
	return newServerWith(t, state.NewMemory())
}

func newServerWith(t *testing.T, store state.Store) (*httptest.Server, *engine.Engine) {
	t.Helper()
	t.Setenv(runtime.EnvFakeReadyDelay, "100ms")
	dir := t.TempDir()
	fake, err := runtime.NewFake(filepath.Join(dir, "world.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fake.Close)
	eng := engine.New(engine.Options{Store: store, Runtime: fake, StateDir: dir, PollInterval: 50 * time.Millisecond})
	t.Cleanup(func() { shutdown(eng) })
	srv := httptest.NewServer(New(Options{Engine: eng}).SocketHandler())
	t.Cleanup(srv.Close)
	return srv, eng
}

// shutdown stops an engine's jobs before the test's directories are
// removed (registered as a cleanup right after the engine is made, so it
// runs after the server closes and before the fake and the directories go).
func shutdown(eng *engine.Engine) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = eng.Shutdown(ctx)
}

func call(t *testing.T, srv *httptest.Server, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var buf *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		buf = bytes.NewReader(raw)
	} else {
		buf = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, srv.URL+Prefix+path, buf)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// The S4 door: create is 202 + job, the instance object carries the
// ladder, destroy demands the echoed name, errors are the §3 envelope
// with the documented statuses.
func TestSocketDoorLifecycle(t *testing.T) {
	srv, eng := newServer(t)
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))

	if code, out := call(t, srv, http.MethodGet, "/healthz", nil); code != 200 || out["ok"] != true {
		t.Fatalf("healthz: %d %v", code, out)
	}
	if code, _ := call(t, srv, http.MethodGet, "/system", nil); code != 200 {
		t.Fatalf("system: %d", code)
	}
	code, out := call(t, srv, http.MethodPost, "/instances", map[string]any{"path": fixture, "name": "api1"})
	if code != http.StatusAccepted {
		t.Fatalf("create: %d %v", code, out)
	}
	job := out["job"].(map[string]any)
	jobID := job["id"].(string)
	if code, out := call(t, srv, http.MethodPost, "/instances", map[string]any{"path": fixture, "name": "api1"}); code != http.StatusConflict || out["error"].(map[string]any)["code"] != "PDR-E200" {
		t.Errorf("duplicate: %d %v", code, out)
	}
	if code, out := call(t, srv, http.MethodPost, "/instances", map[string]any{"template": "nope"}); code != http.StatusNotFound || out["error"].(map[string]any)["code"] != "PDR-E207" {
		t.Errorf("unknown template: %d %v", code, out)
	}
	if code, out := call(t, srv, http.MethodPost, "/instances", map[string]any{"path": fixture, "name": "Bad_Name"}); code != http.StatusBadRequest || out["error"].(map[string]any)["code"] != "PDR-E206" {
		t.Errorf("bad name: %d %v", code, out)
	}
	if _, err := eng.Wait(context.Background(), jobID); err != nil {
		t.Fatal(err)
	}
	code, out = call(t, srv, http.MethodGet, "/instances/api1", nil)
	inst := out["instance"].(map[string]any)
	ladder := inst["ladder"].(map[string]any)
	if code != 200 || ladder["stage"] != "ready" || ladder["condensed"] != "●●●●●●●" {
		t.Fatalf("instance: %d %v", code, inst)
	}
	if code, out := call(t, srv, http.MethodGet, "/jobs/"+jobID, nil); code != 200 || out["job"].(map[string]any)["state"] != "succeeded" || len(out["events"].([]any)) == 0 {
		t.Errorf("job: %d %v", code, out)
	}
	if code, out := call(t, srv, http.MethodGet, "/instances", nil); code != 200 || len(out["instances"].([]any)) != 1 {
		t.Errorf("list: %d %v", code, out)
	}
	if code, out := call(t, srv, http.MethodDelete, "/instances/api1?confirm=wrong", nil); code != http.StatusBadRequest || out["error"].(map[string]any)["code"] != "PDR-E203" {
		t.Errorf("wrong confirm: %d %v", code, out)
	}
	if code, out := call(t, srv, http.MethodDelete, "/instances/nope?confirm=nope", nil); code != http.StatusNotFound {
		t.Errorf("missing: %d %v", code, out)
	}
	code, out = call(t, srv, http.MethodDelete, "/instances/api1?confirm=api1", nil)
	if code != http.StatusAccepted {
		t.Fatalf("destroy: %d %v", code, out)
	}
	if _, err := eng.Wait(context.Background(), out["job"].(map[string]any)["id"].(string)); err != nil {
		t.Fatal(err)
	}
	if code, _ := call(t, srv, http.MethodGet, "/instances/api1", nil); code != http.StatusNotFound {
		t.Errorf("after destroy: %d", code)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+Prefix+"/instances", bytes.NewReader([]byte("{")))
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed body: %d", resp.StatusCode)
	}
}

func TestStatusMapping(t *testing.T) {
	cases := map[string]int{"PDR-E101": 400, "PDR-E106": 400, "PDR-E107": 404, "PDR-E202": 404, "PDR-E201": 409, "PDR-E215": 409, "PDR-E031": 428, "PDR-E204": 500, "PDR-E999": 500}
	for code, want := range cases {
		if got := Status(code); got != want {
			t.Errorf("%s → %d, want %d", code, got, want)
		}
	}
}

// GET /jobs/{id} promises the job plus its journal: a journal the store
// could not read is an error (500, PDR-E204), never an empty events[].
func TestJobEndpointReportsJournalFaults(t *testing.T) {
	store := &journalFault{Store: state.NewMemory()}
	srv, _ := newServerWith(t, store)
	now := time.Now().UTC()
	if err := store.PutJob(state.Job{ID: "job_jf", Kind: "create", Instance: "x", State: state.JobSucceeded, Stage: "done", Started: now, Finished: &now}); err != nil {
		t.Fatal(err)
	}
	store.fail = true
	code, body := call(t, srv, "GET", "/jobs/job_jf", nil)
	if code != http.StatusInternalServerError {
		t.Fatalf("journal fault: %d %v", code, body)
	}
	if e, _ := body["error"].(map[string]any); e["code"] != pdr.CodeRuntimeFailed || !strings.Contains(fmt.Sprint(e["message"]), "journal") {
		t.Fatalf("journal fault envelope: %v", body)
	}
	store.fail = false
	code, body = call(t, srv, "GET", "/jobs/job_jf", nil)
	if _, isArray := body["events"].([]any); code != http.StatusOK || !isArray {
		t.Fatalf("journal readable again, as an array: %d %v", code, body)
	}
}

// journalFault is a store whose journal reads fail on demand.
type journalFault struct {
	state.Store
	fail bool
}

func (j *journalFault) ListEvents(job string) ([]state.Event, error) {
	if j.fail {
		return nil, errors.New("database is locked (transient)")
	}
	return j.Store.ListEvents(job)
}

// clockOf holds the fake clock newNetworkServer installs on the auth
// service, so tests can step past login backoffs.
var clockOf = map[*auth.Service]*time.Time{}

// engineOf holds the engine behind a network server, so tests can wait on
// jobs and read the audit stream without a socket door.
var engineOf = map[*Server]*engine.Engine{}

// storeOf holds the store behind a network server, for tests that plant
// a session by hand.
var storeOf = map[*Server]state.Store{}

// dirOf holds the state directory behind a network server, for tests
// that need an instance's own tree on disk beside its row.
var dirOf = map[*Server]string{}

func newNetworkServer(t *testing.T) (*httptest.Server, *Server, *auth.Service) {
	t.Helper()
	srv, api, authSvc, _ := newNetworkServerIn(t)
	return srv, api, authSvc
}

// newNetworkServerIn is newNetworkServer returning the state directory
// too (auth.json lives there).
func newNetworkServerIn(t *testing.T) (*httptest.Server, *Server, *auth.Service, string) {
	t.Helper()
	t.Setenv(runtime.EnvFakeReadyDelay, "100ms")
	dir := t.TempDir()
	fake, err := runtime.NewFake(filepath.Join(dir, "world.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fake.Close)
	store := state.NewMemory()
	eng := engine.New(engine.Options{Store: store, Runtime: fake, StateDir: dir, PollInterval: 50 * time.Millisecond})
	t.Cleanup(func() { shutdown(eng) })
	authSvc := auth.NewService(store, filepath.Join(dir, "auth.json"))
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	clockOf[authSvc] = &now
	authSvc.SetClock(func() time.Time { return *clockOf[authSvc] })
	if err := authSvc.SetOperator("jross", "correct horse battery", false, auth.MechanismSocket); err != nil {
		t.Fatal(err)
	}
	api := New(Options{Engine: eng, Auth: authSvc, Address: func() (string, int) { return "lab.test", 8443 }})
	engineOf[api] = eng
	storeOf[api] = store
	dirOf[api] = dir
	srv := httptest.NewServer(api.NetworkHandler())
	t.Cleanup(srv.Close)
	return srv, api, authSvc, dir
}

// The idle expiry slides in the browser too: the response that slides
// the record re-issues the cookie with a fresh Max-Age, and a request
// inside the same minute re-issues nothing.
func TestSessionCookieSlidesWithTheSession(t *testing.T) {
	srv, _, authSvc := newNetworkServer(t)
	resp := do(t, srv, http.MethodPost, "/auth/session", map[string]string{"Content-Type": "application/json"}, `{"username":"jross","password":"correct horse battery"}`)
	readAll(resp)
	sessionCookie := func(resp *http.Response) *http.Cookie {
		for _, c := range resp.Cookies() {
			if c.Name == auth.CookieName {
				return c
			}
		}
		return nil
	}
	issued := sessionCookie(resp)
	if issued == nil {
		t.Fatal("login set no cookie")
	}
	hdr := map[string]string{"Cookie": auth.CookieName + "=" + issued.Value}
	resp = do(t, srv, http.MethodGet, "/auth/session", hdr, "")
	readAll(resp)
	if c := sessionCookie(resp); c != nil {
		t.Fatalf("inside the login's minute nothing slides, yet the cookie was re-issued: %+v", c)
	}
	*clockOf[authSvc] = clockOf[authSvc].Add(2 * time.Minute)
	resp = do(t, srv, http.MethodGet, "/auth/session", hdr, "")
	readAll(resp)
	again := sessionCookie(resp)
	if again == nil || again.Value != issued.Value || again.MaxAge != int(auth.SessionIdle/time.Second) || again.Domain != "lab.test" || !again.Secure || !again.HttpOnly || again.SameSite != http.SameSiteLaxMode {
		t.Fatalf("the slide must re-issue the same cookie with a fresh Max-Age: %+v", again)
	}
	resp = do(t, srv, http.MethodGet, "/healthz", hdr, "")
	readAll(resp)
	if c := sessionCookie(resp); c != nil {
		t.Fatalf("the next request in the same minute must not re-issue: %+v", c)
	}
}

// A plain HTML login whose Login fails with something other than an
// envelope — an unreadable operator file here — renders the 500 page,
// never a dropped connection from a nil envelope.
func TestHTMLLoginSurvivesANonEnvelopeError(t *testing.T) {
	srv, _, _, dir := newNetworkServerIn(t)
	path := filepath.Join(dir, "auth.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	resp := do(t, srv, http.MethodPost, "/auth/session", map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Accept": "text/html"}, "username=jross&password=whatever+whatever")
	b := readAll(resp)
	if resp.StatusCode != 500 || !strings.Contains(b, "<!doctype html>") || !strings.Contains(b, "PDR-E204") {
		t.Fatalf("form login over a broken operator file: %d %s", resp.StatusCode, b)
	}
}

func do(t *testing.T, srv *httptest.Server, method, path string, hdr map[string]string, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+Prefix+path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readAll(resp *http.Response) string {
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// The network door: deny until authenticated, the documented cookie,
// CSRF on cookie writes, whoami, logout.
func TestNetworkDoorSessions(t *testing.T) {
	srv, _, authSvc := newNetworkServer(t)
	for _, path := range []string{"/instances", "/healthz", "/system", "/auth/session", "/auth/tokens"} {
		resp := do(t, srv, http.MethodGet, path, nil, "")
		if b := readAll(resp); resp.StatusCode != 401 || !strings.Contains(b, "PDR-E300") {
			t.Errorf("GET %s without credentials: %d %s", path, resp.StatusCode, b)
		}
	}
	resp := do(t, srv, http.MethodPost, "/auth/session", map[string]string{"Content-Type": "application/json"}, `{"username":"jross","password":"wrong password here"}`)
	if b := readAll(resp); resp.StatusCode != 401 || !strings.Contains(b, "PDR-E301") {
		t.Fatalf("bad login: %d %s", resp.StatusCode, b)
	}
	*clockOf[authSvc] = clockOf[authSvc].Add(2 * time.Second) // past the 1 s backoff
	resp = do(t, srv, http.MethodPost, "/auth/session", map[string]string{"Content-Type": "application/json"}, `{"username":"jross","password":"correct horse battery"}`)
	b := readAll(resp)
	if resp.StatusCode != 200 || !strings.Contains(b, `"subject":"jross"`) || !strings.Contains(b, `"scope":"admin"`) {
		t.Fatalf("login: %d %s", resp.StatusCode, b)
	}
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == auth.CookieName {
			cookie = c
		}
	}
	if cookie == nil || cookie.Domain != "lab.test" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.MaxAge != int(auth.SessionIdle/time.Second) {
		t.Fatalf("cookie attributes (API §2.2): %+v", cookie)
	}
	hdr := map[string]string{"Cookie": auth.CookieName + "=" + cookie.Value}
	resp = do(t, srv, http.MethodGet, "/auth/session", hdr, "")
	var who struct {
		Session auth.Whoami `json:"session"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&who)
	resp.Body.Close()
	if who.Session.CSRF == "" || who.Session.Mechanism != "session" || who.Session.Expires == nil {
		t.Fatalf("whoami: %+v", who)
	}
	resp = do(t, srv, http.MethodDelete, "/auth/session", hdr, "")
	if b := readAll(resp); resp.StatusCode != 403 || !strings.Contains(b, "PDR-E305") {
		t.Fatalf("logout without CSRF: %d %s", resp.StatusCode, b)
	}
	resp = do(t, srv, http.MethodPost, "/instances", map[string]string{"Cookie": hdr["Cookie"], "Content-Type": "application/json"}, `{"template":"x"}`)
	if resp.StatusCode != 403 {
		t.Fatalf("create without CSRF: %d", resp.StatusCode)
	}
	readAll(resp)
	hdr[auth.CSRFHeader] = who.Session.CSRF
	resp = do(t, srv, http.MethodGet, "/healthz", hdr, "")
	if resp.StatusCode != 200 {
		t.Fatalf("healthz with a session: %d", resp.StatusCode)
	}
	readAll(resp)
	resp = do(t, srv, http.MethodDelete, "/auth/session", hdr, "")
	if resp.StatusCode != 204 {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	readAll(resp)
	resp = do(t, srv, http.MethodGet, "/instances", hdr, "")
	if resp.StatusCode != 401 {
		t.Fatalf("session after logout: %d", resp.StatusCode)
	}
	readAll(resp)
}

// Scopes and the socket-only routes: a read token reads and is refused
// admin work with the required scope named; operator, reload, and audit
// are absent (404) on the network.
func TestNetworkDoorScopesAndSocketOnly(t *testing.T) {
	srv, _, authSvc := newNetworkServer(t)
	secret, _, err := authSvc.CreateToken("ci", auth.ScopeRead, "jross", auth.MechanismSocket)
	if err != nil {
		t.Fatal(err)
	}
	hdr := map[string]string{"Authorization": "Bearer " + secret, "Content-Type": "application/json"}
	resp := do(t, srv, http.MethodGet, "/instances", hdr, "")
	if resp.StatusCode != 200 {
		t.Fatalf("read token: %d", resp.StatusCode)
	}
	readAll(resp)
	resp = do(t, srv, http.MethodPost, "/instances", hdr, `{"template":"x"}`)
	if b := readAll(resp); resp.StatusCode != 403 || !strings.Contains(b, "PDR-E304") || !strings.Contains(b, `"path":"required_scope","hint":"admin"`) {
		t.Fatalf("read token creating: %d %s", resp.StatusCode, b)
	}
	resp = do(t, srv, http.MethodGet, "/auth/tokens", hdr, "")
	if resp.StatusCode != 403 {
		t.Fatalf("read token listing tokens: %d", resp.StatusCode)
	}
	readAll(resp)
	resp = do(t, srv, http.MethodGet, "/instances", map[string]string{"Authorization": "Bearer pdr_bogus"}, "")
	if resp.StatusCode != 401 {
		t.Fatalf("bogus token: %d", resp.StatusCode)
	}
	readAll(resp)
	admin, _, _ := authSvc.CreateToken("remote", auth.ScopeAdmin, "jross", auth.MechanismSocket)
	ahdr := map[string]string{"Authorization": "Bearer " + admin, "Content-Type": "application/json"}
	for _, c := range []struct{ method, path string }{{http.MethodPost, "/auth/operator"}, {http.MethodPost, "/system/reload"}, {http.MethodGet, "/system/audit"}} {
		resp := do(t, srv, c.method, c.path, ahdr, `{"username":"x","password":"correct horse battery"}`)
		if resp.StatusCode != 404 {
			t.Errorf("%s %s on the network: %d (must be absent)", c.method, c.path, resp.StatusCode)
		}
		readAll(resp)
	}
	// Token management works for admin on the network, and never echoes secrets back.
	resp = do(t, srv, http.MethodPost, "/auth/tokens", ahdr, `{"name":"dash","scope":"read"}`)
	if b := readAll(resp); resp.StatusCode != 201 || !strings.Contains(b, `"secret":"pdr_`) {
		t.Fatalf("create token: %d %s", resp.StatusCode, b)
	}
	resp = do(t, srv, http.MethodGet, "/auth/tokens", ahdr, "")
	if b := readAll(resp); resp.StatusCode != 200 || strings.Contains(b, "pdr_") || !strings.Contains(b, `"name":"dash"`) {
		t.Fatalf("list tokens: %d %s", resp.StatusCode, b)
	}
	resp = do(t, srv, http.MethodDelete, "/auth/tokens/dash", ahdr, "")
	if resp.StatusCode != 204 {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	readAll(resp)
}

// Accept: text/html returns the console fragment of exactly the data the
// JSON twin carries (ADR-0003), from the same handlers.
func TestFragmentsAreTheJSONTwins(t *testing.T) {
	srv, api, authSvc := newNetworkServer(t)
	secret, _, _ := authSvc.CreateToken("ci", auth.ScopeRead, "jross", auth.MechanismSocket)
	hdr := map[string]string{"Authorization": "Bearer " + secret, "Accept": "text/html"}
	resp := do(t, srv, http.MethodGet, "/instances", hdr, "")
	b := readAll(resp)
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("fragment: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	want, _ := api.o.Console.Fragment(console.FragmentInstances, []engine.InstanceView{})
	if b != string(want) {
		t.Fatalf("fragment diverges from the renderer:\n%s\n---\n%s", b, want)
	}
	resp = do(t, srv, http.MethodGet, "/instances/none", hdr, "")
	if b := readAll(resp); resp.StatusCode != 404 || !strings.Contains(b, `<section class="error-panel"`) || !strings.Contains(b, "PDR-E202") {
		t.Fatalf("error fragment: %d %s", resp.StatusCode, b)
	}
	// JSON wins when the client prefers it.
	resp = do(t, srv, http.MethodGet, "/instances", map[string]string{"Authorization": "Bearer " + secret, "Accept": "application/json, text/html"}, "")
	if b := readAll(resp); !strings.HasPrefix(b, `{"instances":`) {
		t.Fatalf("json preference: %s", b)
	}
	// htmx marks its requests.
	resp = do(t, srv, http.MethodGet, "/auth/session", map[string]string{"Authorization": "Bearer " + secret, "HX-Request": "true"}, "")
	if b := readAll(resp); !strings.Contains(b, `<span class="session">`) {
		t.Fatalf("hx-request fragment: %s", b)
	}
}

// Throttled logins answer 429 with Retry-After (API §2.1, §3).
func TestLoginThrottleStatus(t *testing.T) {
	srv, _, _ := newNetworkServer(t)
	hdr := map[string]string{"Content-Type": "application/json"}
	resp := do(t, srv, http.MethodPost, "/auth/session", hdr, `{"username":"jross","password":"nope nope nope nope"}`)
	readAll(resp)
	resp = do(t, srv, http.MethodPost, "/auth/session", hdr, `{"username":"jross","password":"correct horse battery"}`)
	if b := readAll(resp); resp.StatusCode != 429 || resp.Header.Get("Retry-After") != "1" || !strings.Contains(b, "PDR-E302") {
		t.Fatalf("throttled: %d %q %s", resp.StatusCode, resp.Header.Get("Retry-After"), b)
	}
	// Form posts from the login page render the page around the error —
	// keyed like every page: this render frames its own shell, and
	// carried an empty asset cache key that a browser would have kept
	// for a day.
	resp = do(t, srv, http.MethodPost, "/auth/session", map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Accept": "text/html"}, "username=jross&password=whatever")
	if b := readAll(resp); resp.StatusCode != 429 || !strings.Contains(b, "<!doctype html>") || !strings.Contains(b, "PDR-E302") || !strings.Contains(b, `/assets/console.js?v=`+podaro.ConsoleRevision()+`"`) {
		t.Fatalf("form throttled: %d %s", resp.StatusCode, b)
	}
}

// auditFault is a store whose audit appends fail on demand.
type auditFault struct {
	state.Store
	fail bool
}

func (f *auditFault) AppendAudit(a state.Audit) error {
	if f.fail {
		return errors.New("disk full")
	}
	return f.Store.AppendAudit(a)
}

func (f *auditFault) DeleteSessionAudited(id string, a state.Audit) error {
	if f.fail {
		return errors.New("disk full")
	}
	return f.Store.DeleteSessionAudited(id, a)
}

// A destroy is audited before it runs (API §2.5, §7): the system stream
// names who asked, by which mechanism, and the job — written before the
// job launches — and a destroy whose record cannot be written does not
// happen: the instance stays, nothing runs, the caller sees the store's
// fault.
func TestDestroyIsAuditedBeforeTheJobRuns(t *testing.T) {
	store := &auditFault{Store: state.NewMemory()}
	srv, eng := newServerWith(t, store)
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	code, out := call(t, srv, http.MethodPost, "/instances", map[string]any{"path": fixture, "name": "d1"})
	if code != http.StatusAccepted {
		t.Fatalf("create: %d %v", code, out)
	}
	if _, err := eng.Wait(context.Background(), out["job"].(map[string]any)["id"].(string)); err != nil {
		t.Fatal(err)
	}
	before, err := eng.Audit("")
	if err != nil {
		t.Fatal(err)
	}
	store.fail = true
	code, out = call(t, srv, http.MethodDelete, "/instances/d1?confirm=d1", nil)
	if code != http.StatusInternalServerError || out["error"].(map[string]any)["code"] != "PDR-E204" {
		t.Fatalf("a destroy whose record cannot be written must be the store's fault: %d %v", code, out)
	}
	time.Sleep(300 * time.Millisecond) // long enough for a launched job to have torn the fake world down
	if code, out := call(t, srv, http.MethodGet, "/instances/d1", nil); code != http.StatusOK || out["instance"].(map[string]any)["ladder"].(map[string]any)["stage"] != "ready" {
		t.Fatalf("the unaudited destroy must not have happened: %d %v", code, out)
	}
	if after, _ := eng.Audit(""); len(after) != len(before) {
		t.Fatalf("a refused act leaves no record: %d then %d", len(before), len(after))
	}
	store.fail = false
	code, out = call(t, srv, http.MethodDelete, "/instances/d1?confirm=d1", nil)
	if code != http.StatusAccepted {
		t.Fatalf("destroy once the record can be written: %d %v", code, out)
	}
	jobID := out["job"].(map[string]any)["id"].(string)
	after, _ := eng.Audit("")
	if len(after) != len(before)+1 {
		t.Fatalf("one destroy record, written before the job runs: %d then %d", len(before), len(after))
	}
	rec := after[len(after)-1]
	if rec.Action != "destroy" || rec.Instance != "" || rec.Actor != "operator" || rec.Mechanism != auth.MechanismSocket || !strings.Contains(rec.Detail, "instance d1") || !strings.Contains(rec.Detail, "job "+jobID) {
		t.Fatalf("the socket door's destroy record: %+v", rec)
	}
	if _, err := eng.Wait(context.Background(), jobID); err != nil {
		t.Fatal(err)
	}
	if code, _ := call(t, srv, http.MethodGet, "/instances/d1", nil); code != http.StatusNotFound {
		t.Errorf("after the audited destroy: %d", code)
	}

	// The network door names the principal: the operator's session here.
	nsrv, api, _ := newNetworkServer(t)
	neng := engineOf[api]
	resp := do(t, nsrv, http.MethodPost, "/auth/session", map[string]string{"Content-Type": "application/json"}, `{"username":"jross","password":"correct horse battery"}`)
	var login struct {
		Session struct {
			CSRF string `json:"csrf"`
		} `json:"session"`
	}
	var cookie string
	for _, c := range resp.Cookies() {
		if c.Name == auth.CookieName {
			cookie = c.Value
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(&login); err != nil || cookie == "" {
		t.Fatalf("login: %v cookie=%q", err, cookie)
	}
	resp.Body.Close()
	hdr := map[string]string{"Cookie": auth.CookieName + "=" + cookie, auth.CSRFHeader: login.Session.CSRF, "Content-Type": "application/json"}
	resp = do(t, nsrv, http.MethodPost, "/instances", hdr, fmt.Sprintf(`{"path":%q,"name":"d2"}`, fixture))
	var created struct {
		Job struct {
			ID string `json:"id"`
		} `json:"job"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil || resp.StatusCode != http.StatusAccepted {
		t.Fatalf("create over the network door: %d %v", resp.StatusCode, err)
	}
	resp.Body.Close()
	if _, err := neng.Wait(context.Background(), created.Job.ID); err != nil {
		t.Fatal(err)
	}
	resp = do(t, nsrv, http.MethodDelete, "/instances/d2?confirm=d2", hdr, "")
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil || resp.StatusCode != http.StatusAccepted {
		t.Fatalf("destroy over the network door: %d %v", resp.StatusCode, err)
	}
	resp.Body.Close()
	// The job this test launched finishes before the test does: a destroy
	// still tearing the fake world down as the temporary directory is
	// removed is a cleanup race, not a verdict.
	if _, err := neng.Wait(context.Background(), created.Job.ID); err != nil {
		t.Fatal(err)
	}
	list, _ := neng.Audit("")
	rec = list[len(list)-1]
	if rec.Action != "destroy" || rec.Actor != "jross" || rec.Mechanism != auth.MechanismSession || !strings.Contains(rec.Detail, "instance d2") || !strings.Contains(rec.Detail, "job "+created.Job.ID) {
		t.Fatalf("the network door's destroy record must name the operator: %+v", rec)
	}
}

// An instance-bound session sees its instance and nothing else (API §2.4):
// the grant is enforced by resource in the
// handlers, not by hostname alone — the listing holds only its instance,
// another instance and another instance's job are not found, and every
// endpoint outside the grant is refused with E304. A read token, above
// the instance scope, still reads everything.
func TestInstanceBoundSessionSeesOnlyItsInstance(t *testing.T) {
	srv, api, authSvc := newNetworkServer(t)
	eng, store := engineOf[api], storeOf[api]
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	jobs := map[string]string{}
	for _, name := range []string{"a1", "a2"} {
		job, err := eng.Create(context.Background(), engine.CreateRequest{Path: fixture, Name: name})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := eng.Wait(context.Background(), job.ID); err != nil {
			t.Fatal(err)
		}
		jobs[name] = job.ID
	}
	// Gen is what a join would have copied from the credential: an
	// instance-bound session without one is a session no join could
	// produce.
	a1, err := store.GetInstance("a1")
	if err != nil {
		t.Fatal(err)
	}
	sess := &state.Session{ID: "s-a1", Subject: "alice", Mechanism: "instance-access", Instance: "a1", Gen: a1.AuditFrom, CSRF: "c-a1", Created: time.Now(), LastSeen: time.Now(), Expires: time.Now().Add(time.Hour)}
	if err := store.PutSession(*sess); err != nil {
		t.Fatal(err)
	}
	cookie, _ := authSvc.CookieValue(sess)
	hdr := map[string]string{"Cookie": auth.CookieName + "=" + cookie, auth.CSRFHeader: sess.CSRF}
	get := func(path string) (int, map[string]any) {
		resp := do(t, srv, http.MethodGet, path, hdr, "")
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	errCode := func(out map[string]any) string {
		if e, ok := out["error"].(map[string]any); ok {
			return fmt.Sprint(e["code"])
		}
		return ""
	}
	code, out := get("/instances")
	if list, _ := out["instances"].([]any); code != 200 || len(list) != 1 || list[0].(map[string]any)["name"] != "a1" {
		t.Fatalf("the listing must hold the bound instance alone: %d %v", code, out)
	}
	if code, out := get("/instances/a1"); code != 200 || out["instance"].(map[string]any)["name"] != "a1" {
		t.Fatalf("own instance: %d %v", code, out)
	}
	if code, out := get("/instances/a2"); code != 404 || errCode(out) != "PDR-E202" {
		t.Fatalf("another instance must be not found: %d %v", code, out)
	}
	if code, out := get("/jobs/" + jobs["a1"]); code != 200 {
		t.Fatalf("own job: %d %v", code, out)
	}
	if code, out := get("/jobs/" + jobs["a2"]); code != 404 || errCode(out) != "PDR-E202" {
		t.Fatalf("another instance's job must be not found: %d %v", code, out)
	}
	if code, out := get("/auth/session"); code != 200 || out["session"].(map[string]any)["scope"] != auth.ScopeInstance || out["session"].(map[string]any)["instance"] != "a1" {
		t.Fatalf("whoami: %d %v", code, out)
	}
	for _, path := range []string{"/system", "/auth/tokens"} {
		if code, out := get(path); code != 403 || errCode(out) != "PDR-E304" {
			t.Fatalf("%s is outside the grant: %d %v", path, code, out)
		}
	}
	secret, _, err := authSvc.CreateToken("ci", auth.ScopeRead, "jross", auth.MechanismSocket)
	if err != nil {
		t.Fatal(err)
	}
	resp := do(t, srv, http.MethodGet, "/instances", map[string]string{"Authorization": "Bearer " + secret}, "")
	var all map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&all)
	resp.Body.Close()
	if list, _ := all["instances"].([]any); resp.StatusCode != 200 || len(list) != 2 {
		t.Fatalf("a read token lists every instance: %d %v", resp.StatusCode, all)
	}
}

// A login's next target stays on the gateway's own port:
// an absolute URL that omits the port would send the browser to 443,
// which on a gateway serving another port is a different service on the
// same hostname — so the effective port is compared, and 443 is only
// accepted when the gateway serves it.
func TestNextStaysOnTheGatewayPort(t *testing.T) {
	on := func(port int) *Server {
		return New(Options{Address: func() (string, int) { return "lab.test", port }})
	}
	for _, c := range []struct {
		port int
		next string
		want string
	}{
		{8443, "https://t1.lab.test/", ""},
		{8443, "https://t1.lab.test:443/", ""},
		{8443, "https://t1.lab.test:8443/x?y=1", "https://t1.lab.test:8443/x?y=1"},
		{8443, "https://lab.test:8443/", "https://lab.test:8443/"},
		{443, "https://t1.lab.test/", "https://t1.lab.test/"},
		{443, "https://t1.lab.test:443/", "https://t1.lab.test:443/"},
		{443, "https://t1.lab.test:8443/", ""},
		{8443, "/instances/t1", "/instances/t1"},
		{8443, "//evil.example/", ""},
		{8443, "https://evil.example/", ""},
		{8443, "http://t1.lab.test:8443/", ""},
		// Browsers read a backslash as a slash and drop tabs and
		// newlines, so these are network-path references to another
		// host: refused, as is any target holding
		// either character.
		{8443, "/\\evil.example", ""},
		{8443, "/\\\\evil.example/", ""},
		{8443, "/\t/evil.example", ""},
		{8443, "/\n/evil.example", ""},
		{8443, "/x\\y", ""},
		{8443, "https://t1.lab.test:8443/a\\b", ""},
	} {
		if got := on(c.port).SafeNext(c.next); got != c.want {
			t.Errorf("gateway :%d, next %q: got %q, want %q", c.port, c.next, got, c.want)
		}
	}
}

// holdTokenPut is a store whose token write signals and then waits: a
// creation in flight, its handler running, its answer already lost.
type holdTokenPut struct {
	state.Store
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (h *holdTokenPut) PutTokenAudited(tok state.Token, a state.Audit) error {
	h.once.Do(func() { close(h.entered) })
	<-h.release
	return h.Store.PutTokenAudited(tok, a)
}

// A token list is ordered after any creation in flight:
// a client reconciling an answer lost on the socket reads the
// outcome of the creation it lost, never the moment before it.
func TestATokenListIsOrderedAfterACreationInFlight(t *testing.T) {
	hold := &holdTokenPut{Store: state.NewMemory(), entered: make(chan struct{}), release: make(chan struct{})}
	var released sync.Once
	release := func() { released.Do(func() { close(hold.release) }) }
	authSvc := auth.NewService(hold, filepath.Join(t.TempDir(), "auth.json"))
	srv := httptest.NewServer(New(Options{Engine: engine.New(engine.Options{Store: hold}), Auth: authSvc}).SocketHandler())
	t.Cleanup(srv.Close)
	t.Cleanup(release) // runs before the server's close: a failed run must not hold it
	request := func(method, path, body string) (*http.Response, error) {
		req, _ := http.NewRequest(method, srv.URL+Prefix+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		return srv.Client().Do(req)
	}
	type answer struct {
		resp *http.Response
		err  error
	}
	created := make(chan answer, 1)
	go func() {
		resp, err := request(http.MethodPost, "/auth/tokens", `{"name":"ci","scope":"read"}`)
		created <- answer{resp, err}
	}()
	<-hold.entered
	listed := make(chan answer, 1)
	go func() {
		resp, err := request(http.MethodGet, "/auth/tokens", "")
		listed <- answer{resp, err}
	}()
	select {
	case a := <-listed:
		if a.err != nil {
			t.Fatal(a.err)
		}
		t.Fatalf("a list must not overtake a creation in flight: %d %s", a.resp.StatusCode, readAll(a.resp))
	case <-time.After(300 * time.Millisecond):
	}
	release()
	a := <-created
	if a.err != nil || a.resp.StatusCode != 201 {
		t.Fatalf("the creation: %v %v", a.resp, a.err)
	}
	readAll(a.resp)
	a = <-listed
	if a.err != nil {
		t.Fatal(a.err)
	}
	if b := readAll(a.resp); a.resp.StatusCode != 200 || !strings.Contains(b, `"name":"ci"`) {
		t.Fatalf("the list after the creation must show it: %d %s", a.resp.StatusCode, b)
	}
}
