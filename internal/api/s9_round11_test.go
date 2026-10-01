// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// swapOnRead replaces the instance the moment something has resolved it.
// That is the window this round's finding names: the handler resolves
// the target, and anything that resolves it a *second* time is looking
// at whatever the name means by then.
type swapOnRead struct {
	state.Store
	mu sync.Mutex
	// armed fires after an instance is resolved; onSession fires after a
	// *session* is. The second one is how a test reaches the window that
	// opens once a request is authenticated and before its handler acts.
	armed     func()
	onSession func()
}

// TouchSession is the *last* store call authentication makes: the slide
// that marks the session used. Firing here puts the swap after the
// principal is settled and before the handler runs, which is the window
// the finding names — firing during the read instead lands inside
// authentication, where the slide already refuses a session that has
// gone.
func (s *swapOnRead) TouchSession(id string, lastSeen, expires time.Time) error {
	err := s.Store.TouchSession(id, lastSeen, expires)
	s.mu.Lock()
	fire := s.onSession
	s.onSession = nil // once
	s.mu.Unlock()
	if fire != nil {
		fire()
	}
	return err
}

func (s *swapOnRead) armSession(f func()) {
	s.mu.Lock()
	s.onSession = f
	s.mu.Unlock()
}

func (s *swapOnRead) GetInstance(name string) (*state.Instance, error) {
	inst, err := s.Store.GetInstance(name)
	s.mu.Lock()
	fire := s.armed
	s.armed = nil // once
	s.mu.Unlock()
	if fire != nil {
		fire()
	}
	return inst, err
}

func (s *swapOnRead) arm(f func()) {
	s.mu.Lock()
	s.armed = f
	s.mu.Unlock()
}

// Round 10 bound the write to the generation the *store call* read, and
// I put that read inside `IssueAccess`. The handler had already resolved
// the instance and thrown the result away, so the window simply moved:
// destroyed and re-created between the handler's resolution and
// `IssueAccess`'s own lookup, the second read sees the replacement, the
// store check passes against it, and the link opens the new lab after
// all.
//
// The generation is resolved once, by the handler, and carried to the
// write. Issuance no longer looks the instance up a second time —
// there is no second read to disagree with the first.
func TestIssuanceResolvesTheGenerationOnce(t *testing.T) {
	srv, api, _, cookie := newSwapHarness(t)
	store := storeOf[api].(*swapOnRead)
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

	// The lab the operator is looking at, and the one that takes its
	// name while the request is in flight.
	store.arm(func() {
		if err := store.Store.DeleteInstance("lab"); err != nil {
			t.Errorf("destroying the first generation: %v", err)
		}
		if err := store.Store.PutInstance(state.Instance{
			Name: "lab", Template: "t", Mode: "delivery", Source: "/s",
			Created: now.Add(time.Minute), Updated: now.Add(time.Minute), AuditFrom: 4242,
		}); err != nil {
			t.Errorf("re-creating the name: %v", err)
		}
	})

	resp, out := request(t, srv.Client(), srv.URL, http.MethodPost, "/instances/lab/access", cookie,
		`{"name":"alice","expires":"8h"}`)

	// Neither branch prints the body on the failing path: a 201 carries
	// the join token, and no assertion of mine puts a credential in a
	// test log (invariant 6). The error envelope's code is safe and is
	// what says whether the refusal was the right one.
	if resp.StatusCode == http.StatusCreated {
		t.Fatal("the link was issued for a lab that no longer exists, against the one that took its name")
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("issuing against a replaced generation answered %d, want 404 (%s)", resp.StatusCode, errCodeOf(out))
	}
	// And nothing was left behind for the replacement to honour.
	if list, err := store.Store.ListAccess("lab"); err != nil || len(list) != 0 {
		t.Fatalf("the replacement carries %d credential(s) it never issued (%v)", len(list), err)
	}
}

// newSwapHarness is newNetworkServerIn with a store that can replace an
// instance mid-request, plus the operator's signed-in cookie.
func newSwapHarness(t *testing.T) (*httptest.Server, *Server, *auth.Service, string) {
	t.Helper()
	t.Setenv(runtime.EnvFakeReadyDelay, "100ms")
	dir := t.TempDir()
	fake, err := runtime.NewFake(filepath.Join(dir, "world.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fake.Close)
	store := &swapOnRead{Store: state.NewMemory()}
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
	srv := httptest.NewServer(api.NetworkHandler())
	t.Cleanup(srv.Close)

	if err := store.PutInstance(state.Instance{
		Name: "lab", Template: "t", Mode: "delivery", Source: "/s", Created: now, Updated: now,
	}); err != nil {
		t.Fatal(err)
	}
	resp := do(t, srv, http.MethodPost, "/auth/session", map[string]string{"Content-Type": "application/json"},
		`{"username":"jross","password":"correct horse battery"}`)
	readAll(resp)
	var cookie string
	for _, c := range resp.Cookies() {
		if c.Name == auth.CookieName {
			cookie = auth.CookieName + "=" + c.Value
		}
	}
	if cookie == "" {
		t.Fatal("the operator did not sign in")
	}
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
	return srv, api, authSvc, cookie
}

// The refusal for an unknown error code sent the client to
// `GET /system/errors`, which this server does not register — only
// `GET /system/errors/{code}`. Following the remediation produced a
// second 404, which is worse than no advice at all.
//
// The rule the test states is the general one: a remediation that names
// a *concrete* endpoint must name one that answers. A template — a path
// with a `{placeholder}` in it — is a shape, not a URL, and is skipped.
func TestARemediationNamesAnEndpointThatAnswers(t *testing.T) {
	srv, _, _, cookie := newSwapHarness(t)
	resp, out := request(t, srv.Client(), srv.URL, http.MethodGet, "/system/errors/PDR-E999", cookie, "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an unknown code answered %d, want 404", resp.StatusCode)
	}
	e, _ := out["error"].(map[string]any)
	next, _ := e["next"].(string)
	if next == "" {
		t.Fatal("the refusal offers no next step")
	}

	named := regexp.MustCompile(`(GET|POST|PUT|DELETE|PATCH) (/[A-Za-z0-9/{}._-]*)`).FindAllStringSubmatch(next, -1)
	if len(named) == 0 {
		return // advice that names no endpoint cannot name a wrong one
	}
	for _, m := range named {
		method, path := m[1], m[2]
		if strings.ContainsAny(path, "{}") {
			continue // a shape, not a URL
		}
		probe, _ := request(t, srv.Client(), srv.URL, method, path, cookie, "")
		if probe.StatusCode == http.StatusNotFound {
			t.Errorf("the remediation sends the client to %s %s, which answers 404", method, path)
		}
	}
}
