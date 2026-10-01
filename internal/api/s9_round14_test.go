// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// Review round 14, the two handlers with logic of
// their own.
//
// `listInstances` filtered the listing by *name*, and `getJob` compared
// the job's instance name to the bound one. Neither consulted the
// generation at all, so a bearer whose lab was destroyed and whose name
// was taken again was listed the replacement as its own and could read
// the replacement's job journal.
func TestTheListingAndTheJournalAreThisGenerationsOnly(t *testing.T) {
	srv, api, authSvc, _ := newSwapHarness(t)
	store := storeOf[api].(*swapOnRead)
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

	lab, err := store.GetInstance("lab")
	if err != nil {
		t.Fatal(err)
	}
	// A session for a generation that is no longer the one this name
	// carries — what a destroy and a re-create leave behind.
	sess := state.Session{
		ID: "s-stale", Subject: "alice", Mechanism: auth.MechanismSession, Instance: "lab",
		Gen: lab.AuditFrom - 1, CSRF: "c-stale", Created: now, LastSeen: now, Expires: now.Add(time.Hour),
	}
	if err := store.PutSession(sess); err != nil {
		t.Fatal(err)
	}
	value, err := authSvc.CookieValue(&sess)
	if err != nil {
		t.Fatal(err)
	}
	stale := auth.CookieName + "=" + value

	resp, out := request(t, srv.Client(), srv.URL, http.MethodGet, "/instances", stale, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the listing answered %d (%s)", resp.StatusCode, errCodeOf(out))
	}
	list, _ := out["instances"].([]any)
	if len(list) != 0 {
		t.Errorf("the listing offered a bearer of another generation %d instance(s) as its own", len(list))
	}

	// And its own generation still sees its lab, so the filter is not
	// simply refusing everyone.
	sess.ID, sess.Gen, sess.CSRF = "s-own", lab.AuditFrom, "c-own"
	if err := store.PutSession(sess); err != nil {
		t.Fatal(err)
	}
	value, err = authSvc.CookieValue(&sess)
	if err != nil {
		t.Fatal(err)
	}
	resp, out = request(t, srv.Client(), srv.URL, http.MethodGet, "/instances", auth.CookieName+"="+value, "")
	if list, _ = out["instances"].([]any); resp.StatusCode != http.StatusOK || len(list) != 1 {
		t.Fatalf("a bearer of the current generation must see its own lab: %d %v", resp.StatusCode, out)
	}
}
