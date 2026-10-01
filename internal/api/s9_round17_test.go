// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// failOnce makes the next GetInstance fail the way a store does: once,
// for a reason that is not an absence.
type failOnce struct {
	state.Store
	armed bool
}

func (f *failOnce) GetInstance(name string) (*state.Instance, error) {
	if f.armed {
		f.armed = false
		return nil, errors.New("disk went away")
	}
	return f.Store.GetInstance(name)
}

// Review round 17, second finding — mine from round
// 16.
//
// Making the bound listing the single-instance read was right; swallowing
// every error it returns was not. A store fault came back as `200` with
// an empty list, which an attendee reads as a lab that is simply empty.
// Only the not-found answer means an empty listing; anything else is a
// fault and is reported as one.
func TestAFaultIsNotAnEmptyListing(t *testing.T) {
	srv, api, authSvc, _ := newSwapHarness(t)
	base := storeOf[api].(*swapOnRead)
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

	lab, err := base.GetInstance("lab")
	if err != nil {
		t.Fatal(err)
	}
	sess := state.Session{
		ID: "s-fault", Subject: "alice", Mechanism: auth.MechanismSession, Instance: "lab",
		Gen: lab.AuditFrom, CSRF: "c-fault", Created: now, LastSeen: now, Expires: now.Add(time.Hour),
	}
	if err := base.PutSession(sess); err != nil {
		t.Fatal(err)
	}
	value, err := authSvc.CookieValue(&sess)
	if err != nil {
		t.Fatal(err)
	}
	cookie := auth.CookieName + "=" + value

	// Healthy first: the bearer sees its own lab.
	resp, out := request(t, srv.Client(), srv.URL, http.MethodGet, "/instances", cookie, "")
	if list, _ := out["instances"].([]any); resp.StatusCode != http.StatusOK || len(list) != 1 {
		t.Fatalf("a healthy listing answered %d with %v", resp.StatusCode, out)
	}

	// Then the store fails for the listing's own read.
	failing := &failOnce{Store: base.Store}
	base.Store = failing
	failing.armed = true
	// The session read comes first and would spend the failure; arm it
	// so the listing's own GetInstance is the one that fails.
	resp, out = request(t, srv.Client(), srv.URL, http.MethodGet, "/instances", cookie, "")
	if resp.StatusCode == http.StatusOK {
		if list, _ := out["instances"].([]any); len(list) == 0 {
			t.Fatal("a store fault was answered 200 with an empty listing: an attendee cannot tell that from a lab with nothing in it")
		}
	}
}
