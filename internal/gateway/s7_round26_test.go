// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// The template can only omit what it is told about, and the shell was
// told the instance and never the caller. This is the wiring: a session
// bound to this very instance — the attendee case API §2.4 describes,
// admitted by the gateway on its own hostname — is served the lab and
// none of the three controls it would be refused.
//
// The one refused control the reviewer named is Reset (`reset-plan`
// needs read; the `instance` scope ranks below it). `GET /system` needs
// read too, and the operator console lists every instance, which is the
// first thing §2.4's grant excludes.
func TestAnInstanceBoundSessionIsServedNoControlItIsRefused(t *testing.T) {
	r := newRig(t)
	r.up("t1")

	now := time.Now()
	inst, err := r.st.GetInstance("t1")
	if err != nil {
		t.Fatal(err)
	}
	// The generation the grant was issued for. A session the engine
	// mints carries `acc.Gen` and always has; this fixture predates the
	// field, and the lab page now compares it like every other read on
	// an attendee's path. The assertions below are
	// unchanged — this is the session the system would issue.
	sess := state.Session{ID: "s-attendee", Subject: "alice", Mechanism: "instance-access",
		Instance: "t1", Gen: inst.AuditFrom, CSRF: "c-attendee", Created: now, LastSeen: now, Expires: now.Add(time.Hour)}
	if err := r.st.PutSession(sess); err != nil {
		t.Fatal(err)
	}
	c, err := r.auth.CookieValue(&sess)
	if err != nil {
		t.Fatal(err)
	}

	resp := r.get("t1."+domain, "/", map[string]string{"Cookie": auth.CookieName + "=" + c})
	page := body(resp)
	if resp.StatusCode != 200 {
		t.Fatalf("the attendee's own lab answered %d", resp.StatusCode)
	}
	for _, refused := range []string{"reset-plan", `id="system"`} {
		if strings.Contains(page, refused) {
			t.Errorf("the lab page offers %q to a session bound to it", refused)
		}
	}
	if strings.Contains(page, `href="https://`+domain) {
		t.Errorf("the lab page sends a bound session to the operator console, which refuses it")
	}
	// It is their lab, and it is all there.
	for _, kept := range []string{"instance-name", "panel-evidence", "Sign out"} {
		if !strings.Contains(page, kept) {
			t.Errorf("the attendee's lab page lost %q", kept)
		}
	}

	// The operator, on the same page, still has all three.
	resp = r.get("t1."+domain, "/", map[string]string{"Cookie": auth.CookieName + "=" + r.cookie})
	page = body(resp)
	for _, want := range []string{"reset-plan", `id="system"`, `href="https://` + domain} {
		if !strings.Contains(page, want) {
			t.Errorf("the operator's lab page lost %q", want)
		}
	}
}
