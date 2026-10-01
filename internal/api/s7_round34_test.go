// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// §2.4 grants an attendee "step seeds", and the seed endpoint is one
// endpoint for two different acts. A seed a playbook step invokes is the
// learner's own — pressing the step's button runs it. A seed no step
// names is a *standing* seed: create's injection, the instance's
// starting data. Round 33 admitted a bound session to the endpoint,
// which admitted it to both, so an attendee could re-run a bootstrap
// injection under the lab their own progress is judged against.
//
// Neither shipped scenario declares a standing seed today, so nothing
// was exposed in the catalogue — but the endpoint was, and a template is
// a thing anyone may write.
func TestAnAttendeeMayRunOnlyTheSeedsAStepInvokes(t *testing.T) {
	srv, eng, store := grantHarness(t)
	// The fixture declares two seeds and a playbook step that invokes one:
	// `orders` is the step's, `exec-seed` is standing.
	fixture, _ := filepath.Abs(filepath.Join("..", "lab", "testdata", "valid-aliases"))
	job, err := eng.Create(context.Background(), engine.CreateRequest{Path: fixture, Name: "theirs", AcceptLicenses: []string{"custom-terms"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Wait(context.Background(), job.ID); err != nil {
		t.Fatal(err)
	}
	steps, err := eng.StepSeeds("theirs", engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 1 || steps[0] != "orders" {
		t.Fatalf("this case needs one step seed and a standing one; the fixture's step seeds are %v", steps)
	}

	now := time.Now()
	sess := state.Session{ID: "s-attendee", Subject: "alice", Mechanism: "instance-access",
		Instance: "theirs", CSRF: "c", Created: now, LastSeen: now, Expires: now.Add(time.Hour)}
	if err := store.PutSession(sess); err != nil {
		t.Fatal(err)
	}
	attendee := &Principal{Mechanism: auth.MechanismSession, Subject: "alice",
		Scope: auth.ScopeInstance, Session: &sess}
	operator := &Principal{Mechanism: auth.MechanismSocket, Subject: "operator", Scope: auth.ScopeAdmin}

	seed := func(p *Principal, name string) *http.Response {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, srv.URL+Prefix+"/instances/theirs/seeds/"+name, strings.NewReader(""))
		w := httptest.NewRecorder()
		srv.Config.Handler.ServeHTTP(w, req.WithContext(WithPrincipal(req.Context(), p)))
		return w.Result()
	}

	// The standing seed is not theirs to run.
	resp := seed(attendee, "exec-seed")
	if code := errorCode(t, resp); code != "PDR-E304" {
		t.Errorf("an attendee ran a standing seed (%s); §2.4 grants step seeds", code)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("a refusal outside the grant answered %d, want 403", resp.StatusCode)
	}

	// The step's own seed is. The fixture's generator is not one this
	// runtime can run, so the answer is the engine's own — the point is
	// that the grant let it through.
	if code := errorCode(t, seed(attendee, "orders")); code == "PDR-E304" {
		t.Errorf("a step seed is refused to the attendee whose step invokes it")
	}

	// And the operator's reach is unchanged.
	if code := errorCode(t, seed(operator, "exec-seed")); code == "PDR-E304" {
		t.Errorf("the operator lost a seed they had before")
	}

	// The seeds this test admitted are jobs, and a job outlives the
	// request that started it: waiting for them keeps the engine from
	// writing evidence into a directory the harness is removing.
	rows, err := eng.Jobs("theirs", engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, j := range rows {
		if j.Active() {
			_, _ = eng.Wait(ctx, j.ID)
		}
	}
}
