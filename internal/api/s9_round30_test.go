// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/auth"
)

// The peer address a join is made from is the operator's security
// record, not the lab's. An instance's audit stream is the attendee's:
// `Engine.Evidence` merges it into GET …/evidence, the SSE feed
// serializes every row's `detail`, and both are inside the attendee
// grant (API §2.4). So an address stored on the instance-scoped join row
// is an address every other attendee of that lab can read or watch —
// while `GET /system/audit`, which is socket-only, is where an operator
// asks where a link was used from.
func TestAnAttendeeNeverSeesAnotherAttendeesAddress(t *testing.T) {
	url, api, authSvc, cookie, client := newAccessHarness(t)
	// The harness plants the row, not the tree: a delivery instance's
	// evidence is read beside its pinned template and module library.
	if err := os.MkdirAll(filepath.Join(dirOf[api], "instances", "lab", "modules"), 0o700); err != nil {
		t.Fatal(err)
	}
	src, err := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	if err != nil {
		t.Fatal(err)
	}
	inst, err := storeOf[api].GetInstance("lab")
	if err != nil {
		t.Fatal(err)
	}
	inst.Source = src
	if err := storeOf[api].PutInstance(*inst); err != nil {
		t.Fatal(err)
	}

	// Two attendees on one lab: bob joins from an address of his own,
	// alice reads the lab's evidence.
	resp, out := request(t, client, url, http.MethodPost, "/instances/lab/access", cookie, `{"name":"bob","expires":"2h"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("issue bob: %d %v", resp.StatusCode, out)
	}
	bobSecret, _ := out["token"].(string)
	const bobAddr = "198.51.100.7"
	if _, _, err := authSvc.Join(bobSecret, bobAddr); err != nil {
		t.Fatalf("bob joins: %v", err)
	}

	resp, out = request(t, client, url, http.MethodPost, "/instances/lab/access", cookie, `{"name":"alice","expires":"2h"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("issue alice: %d %v", resp.StatusCode, out)
	}
	aliceSecret, _ := out["token"].(string)
	resp, out = request(t, client, url, http.MethodGet, "/join/"+aliceSecret, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("alice joins: %d %v", resp.StatusCode, out)
	}
	alice := ""
	for _, c := range resp.Cookies() {
		if c.Name == auth.CookieName {
			alice = auth.CookieName + "=" + c.Value
		}
	}
	if alice == "" {
		t.Fatal("alice's join set no session cookie")
	}

	// What alice is served.
	resp, out = request(t, client, url, http.MethodGet, "/instances/lab/evidence?type=audit", alice, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("alice reads the evidence: %d %v", resp.StatusCode, out)
	}
	body, _ := json.Marshal(out)
	if strings.Contains(string(body), bobAddr) {
		t.Fatalf("an attendee is served another attendee's peer address in the lab's evidence:\n%s", body)
	}

	// The rows themselves, because the SSE feed serializes the same
	// `detail` this endpoint renders: what the stream cannot leak is
	// what the instance's stream does not hold.
	rows, err := storeOf[api].ListAudit("lab")
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range rows {
		if strings.Contains(rec.Detail, bobAddr) {
			t.Fatalf("the instance's audit stream holds a peer address: %+v", rec)
		}
	}

	// And the operator's own record is not lost with it: the system
	// stream, which only the local socket reads, still says where.
	sys, err := storeOf[api].ListAudit("")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rec := range sys {
		if rec.Action == "join" && rec.Actor == "bob" && strings.Contains(rec.Detail, bobAddr) {
			found = true
		}
	}
	if !found {
		t.Fatalf("the operator's socket-only audit no longer says where a join came from: %+v", sys)
	}
}
