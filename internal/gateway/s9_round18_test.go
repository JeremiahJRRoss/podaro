// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// Every read an attendee reaches through the API is compared against the
// generation their grant names — rounds 10 to 17 closed those one at a
// time. The server-rendered lab page was not one of them: it asked the
// engine as `engine.Socket`, the local door, which is bound to no
// generation at all. So the ladder, the playbook list and the step
// progress it painted came from whatever lab holds the name *now*, for a
// grant that named the one before it.
func TestTheLabPageIsThisGenerationsOnly(t *testing.T) {
	r := newRig(t)
	r.up("t1")
	inst, err := r.st.GetInstance("t1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	// bind issues a cookie for a grant of one generation of t1. The
	// value itself is never printed: a failing assertion says which
	// grant it was, never what it carries.
	bind := func(id string, gen int64) string {
		t.Helper()
		sess := state.Session{ID: id, Subject: "alice", Mechanism: "instance-access", Instance: "t1",
			Gen: gen, CSRF: "c-" + id, Created: now, LastSeen: now, Expires: now.Add(time.Hour)}
		if err := r.st.PutSession(sess); err != nil {
			t.Fatal(err)
		}
		c, err := r.auth.CookieValue(&sess)
		if err != nil {
			t.Fatal(err)
		}
		return auth.CookieName + "=" + c
	}
	const ladder = `<span class="instance-name">t1</span>`

	// A grant for the lab that is gone, on the name a later lab carries.
	resp := r.get("t1."+domain, "/", map[string]string{"Cookie": bind("s-stale", inst.AuditFrom-1)})
	page := body(resp)
	if resp.StatusCode == 200 {
		t.Errorf("a grant for a generation that is gone was served the lab page of the lab holding its name now (%d)", resp.StatusCode)
	}
	if strings.Contains(page, ladder) {
		t.Errorf("the page painted a lab the grant never named")
	}

	// Its own generation is served, so the check is not refusing everyone.
	resp = r.get("t1."+domain, "/", map[string]string{"Cookie": bind("s-own", inst.AuditFrom)})
	if page = body(resp); resp.StatusCode != 200 || !strings.Contains(page, ladder) {
		t.Fatalf("the attendee's own lab answered %d", resp.StatusCode)
	}
	// And the operator, entitled to no one generation, still sees it.
	resp = r.get("t1."+domain, "/", map[string]string{"Cookie": auth.CookieName + "=" + r.cookie})
	if page = body(resp); resp.StatusCode != 200 || !strings.Contains(page, ladder) {
		t.Fatalf("the operator's lab page answered %d", resp.StatusCode)
	}
}
