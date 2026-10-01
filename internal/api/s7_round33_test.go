// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/lab"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// API §2.4's fixed grant lists, in an attendee's own hands: "run verify,
// checkpoint runs, attest, and step seeds; write playbook progress".
// §11's legend says a session qualifies for a scope. Three of those were
// registered at `operate`, which an instance-bound session ranks below —
// so an attendee was refused exactly the writes the grant promises, and
// both shipped playbooks stop at their first actionable step.
//
// The grant is a set, not a rank: lowering the routes to the instance
// scope would have handed a *read-scoped token* the right to seed,
// attest and rewrite a learner's position. The rank is left alone and
// the session is admitted by name.
func TestTheFixedGrantAdmitsAnAttendeeToItsOwnWrites(t *testing.T) {
	srv, eng, store := grantHarness(t)
	ctx := context.Background()
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	for _, name := range []string{"theirs", "someone-elses"} {
		job, err := eng.Create(ctx, engine.CreateRequest{Path: fixture, Name: name})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := eng.Wait(ctx, job.ID); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	sess := state.Session{ID: "s-attendee", Subject: "alice", Mechanism: "instance-access",
		Instance: "theirs", CSRF: "c", Created: now, LastSeen: now, Expires: now.Add(time.Hour)}
	if err := store.PutSession(sess); err != nil {
		t.Fatal(err)
	}
	attendee := &Principal{Mechanism: auth.MechanismSession, Subject: "alice",
		Scope: auth.ScopeInstance, Session: &sess}
	reader := &Principal{Mechanism: auth.MechanismToken, Subject: "ci", Scope: auth.ScopeRead}

	as := func(p *Principal, method, path, body string) *http.Response {
		t.Helper()
		var rdr *strings.Reader
		if body == "" {
			rdr = strings.NewReader("")
		} else {
			rdr = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, srv.URL+Prefix+path, rdr)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.Config.Handler.ServeHTTP(w, req.WithContext(WithPrincipal(req.Context(), p)))
		return w.Result()
	}

	// The grant, on their own lab. The seed half of it is qualified —
	// §2.4 grants *step* seeds, and this fixture declares no seed at all,
	// so the case belongs to the fixture that has one (round 34's test).
	for _, c := range []struct{ what, method, path, body string }{
		{"an attestation", http.MethodPost, "/instances/theirs/checkpoints/no-such-cp/attest", `{"note":"done"}`},
		{"their position", http.MethodPut, "/instances/theirs/playbooks/no-such-pb/progress", `{"current_step":"one"}`},
	} {
		resp := as(attendee, c.method, c.path, c.body)
		// The fixtures name nothing that exists, so the answer is the
		// engine's own not-found — which is the point: the *grant* let the
		// request through to the engine, and only the engine's own reading
		// of the request refused it. A scope refusal is PDR-E304.
		if code := errorCode(t, resp); code == "PDR-E304" {
			t.Errorf("%s is refused to the attendee the grant promises it to (%s)", c.what, code)
		}
	}

	// And on nobody else's: the resource half is untouched, and answers
	// not-found rather than admitting the shape of another lab.
	for _, c := range []struct{ what, method, path, body string }{
		{"a seed", http.MethodPost, "/instances/someone-elses/seeds/any", ""},
		{"an attestation", http.MethodPost, "/instances/someone-elses/checkpoints/any/attest", `{"note":"x"}`},
		{"progress", http.MethodPut, "/instances/someone-elses/playbooks/any/progress", `{"current_step":"one"}`},
	} {
		resp := as(attendee, c.method, c.path, c.body)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s on another instance answered %d, want 404", c.what, resp.StatusCode)
		}
	}

	// What the grant excludes is still excluded.
	if resp := as(attendee, http.MethodPost, "/instances/theirs/reset", ""); errorCode(t, resp) != "PDR-E304" {
		t.Errorf("reset is inside the attendee grant; §2.4 lists it as structurally absent")
	}

	// And the rank is unchanged: a read token cannot write.
	for _, c := range []struct{ what, method, path, body string }{
		{"seed", http.MethodPost, "/instances/theirs/seeds/any", ""},
		{"attest", http.MethodPost, "/instances/theirs/checkpoints/any/attest", `{"note":"x"}`},
		{"progress", http.MethodPut, "/instances/theirs/playbooks/any/progress", `{"current_step":"one"}`},
	} {
		if code := errorCode(t, as(reader, c.method, c.path, c.body)); code != "PDR-E304" {
			t.Errorf("a read-scoped token may %s (%s); only a session in the grant may", c.what, code)
		}
	}
}

// errorCode reads the §3 envelope's code, or "" for a success.
func errorCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode < 400 {
		return ""
	}
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return "undecodable"
	}
	return env.Error.Code
}

// grantHarness serves the *raw* mux, so a test injects its own
// principal. The socket door would replace it with the operator's — and
// the first version of this test used that harness and proved nothing:
// every request ran as admin, including the ones asserting a refusal.
func grantHarness(t *testing.T) (*httptest.Server, *engine.Engine, state.Store) {
	t.Helper()
	t.Setenv(runtime.EnvFakeReadyDelay, "50ms")
	dir := t.TempDir()
	fake, err := runtime.NewFake(filepath.Join(dir, "world.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fake.Close)
	store := state.NewMemory()
	eng := engine.New(engine.Options{Store: store, Runtime: fake, StateDir: dir,
		Library:      lab.DirLibrary(filepath.Join("..", "lab", "testdata", "modules")),
		PollInterval: 20 * time.Millisecond})
	t.Cleanup(func() { shutdown(eng) })
	srv := httptest.NewServer(New(Options{Engine: eng}))
	t.Cleanup(srv.Close)
	return srv, eng, store
}
