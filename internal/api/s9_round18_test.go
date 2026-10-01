// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// failFor makes one instance's job history unreadable — the way a store
// fault reaches `Views`, which builds a view per instance and gives up on
// the first that cannot be read.
type failFor struct {
	state.Store
	instance string
}

func (f *failFor) ListJobs(instance string) ([]state.Job, error) {
	if instance == f.instance {
		return nil, errors.New("disk went away")
	}
	return f.Store.ListJobs(instance)
}

// The bound listing was the single-instance read — round 16's fix — but
// it ran *after* the operator's global listing, whose result it then
// threw away. So an attendee's listing still depended on every other lab
// on the host: a fault reading one of them answered the attendee 500,
// and the message named the lab that failed, which is a name their grant
// does not cover.
func TestABoundListingNeverRunsTheGlobalOne(t *testing.T) {
	srv, api, authSvc, operator := newSwapHarness(t)
	base := storeOf[api].(*swapOnRead)
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

	// A second lab, which the attendee has no grant for, whose job
	// history the store cannot read. Installed before any request: the
	// engine starts no goroutine of its own, so this is the only writer.
	base.Store = &failFor{Store: base.Store, instance: "backstage"}
	if err := base.PutInstance(state.Instance{
		Name: "backstage", Template: "t", Mode: "delivery", Source: "/s", Created: now, Updated: now,
	}); err != nil {
		t.Fatal(err)
	}

	lab, err := base.GetInstance("lab")
	if err != nil {
		t.Fatal(err)
	}
	sess := state.Session{
		ID: "s-bound", Subject: "alice", Mechanism: auth.MechanismSession, Instance: "lab",
		Gen: lab.AuditFrom, CSRF: "c-bound", Created: now, LastSeen: now, Expires: now.Add(time.Hour),
	}
	if err := base.PutSession(sess); err != nil {
		t.Fatal(err)
	}
	value, err := authSvc.CookieValue(&sess)
	if err != nil {
		t.Fatal(err)
	}

	resp, out := request(t, srv.Client(), srv.URL, http.MethodGet, "/instances", auth.CookieName+"="+value, "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("a lab an attendee holds answered %d because another lab could not be read (%s)", resp.StatusCode, errCodeOf(out))
	}
	if list, _ := out["instances"].([]any); resp.StatusCode == http.StatusOK && len(list) != 1 {
		t.Errorf("the attendee's listing holds %d labs — want its own", len(list))
	}
	if raw, _ := out["error"].(map[string]any); raw != nil {
		if msg, _ := raw["message"].(string); strings.Contains(msg, "backstage") {
			t.Errorf("the refusal names a lab outside the grant")
		}
	}

	// The operator's listing still reports the fault: the fix is that a
	// bound bearer does not run that read, not that nobody does.
	resp, out = request(t, srv.Client(), srv.URL, http.MethodGet, "/instances", operator, "")
	if resp.StatusCode == http.StatusOK {
		t.Errorf("the operator's listing hid a store fault behind %d", resp.StatusCode)
	}
	_ = out
}
