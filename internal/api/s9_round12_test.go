// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// slowBody delivers a request body one piece at a time and runs a
// function in the gap. It is the attacker's whole apparatus: a body
// arrives as slowly as its sender likes, and the principal that
// authorised the request was resolved before the first byte of it.
type slowBody struct {
	head, tail string
	between    func()
	sent       bool
}

func (b *slowBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, b.head), nil
	}
	if b.between != nil {
		b.between()
		b.between = nil
	}
	if b.tail == "" {
		return 0, io.EOF
	}
	n := copy(p, b.tail)
	b.tail = ""
	return n, nil
}

func (b *slowBody) Close() error { return nil }

// Rounds 10 and 11 bound *issuing* a credential to a generation. A
// session was still bound to a name: `scoped` compared names, the
// principal was resolved once at the start of the request and never
// re-read, and the session row a destroy deletes was therefore beside
// the point once a request was under way.
//
// So an attendee starts a body-bearing request, lets the body take as
// long as it likes, and in that window the lab is destroyed and its name
// re-created. The already-authenticated principal is untouched, and the
// engine writes to whatever the name means by then.
//
// The credential carries the generation it was issued for, the session
// inherits it at the join, and it is checked against the lab as it
// stands — at `scoped`, and again after any body is read.
func TestABodyInFlightCannotOutliveTheLab(t *testing.T) {
	for _, c := range []struct{ name, method, path, head, tail string }{
		{"progress", http.MethodPut, "/instances/lab/playbooks/pii-redaction/progress",
			`{"current_step":"s1",`, `"steps":{}}`},
		{"attest", http.MethodPost, "/instances/lab/checkpoints/es-up/attest",
			`{"note":"looked`, ` at it"}`},
		{"verify", http.MethodPost, "/instances/lab/verify", `{`, `}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv, api, authSvc, _ := newSwapHarness(t)
			store := storeOf[api].(*swapOnRead)
			now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

			// The attendee's own session, as a join would have made it.
			lab, err := store.GetInstance("lab")
			if err != nil {
				t.Fatal(err)
			}
			sess := state.Session{
				ID: "s-lab", Subject: "alice", Mechanism: auth.MechanismSession, Instance: "lab",
				Gen: lab.AuditFrom, CSRF: "c-lab", Created: now, LastSeen: now, Expires: now.Add(time.Hour),
			}
			if err := store.PutSession(sess); err != nil {
				t.Fatal(err)
			}
			value, err := authSvc.CookieValue(&sess)
			if err != nil {
				t.Fatal(err)
			}
			attendee := auth.CookieName + "=" + value

			// The lab is destroyed and its name taken again while the
			// body is still arriving.
			replace := func() {
				if err := store.Store.DeleteInstance("lab"); err != nil {
					t.Errorf("destroying the lab: %v", err)
				}
				if err := store.Store.PutInstance(state.Instance{
					Name: "lab", Template: "t", Mode: "delivery", Source: "/s",
					Created: now.Add(time.Minute), Updated: now.Add(time.Minute), AuditFrom: lab.AuditFrom + 4242,
				}); err != nil {
					t.Errorf("re-creating the name: %v", err)
				}
			}

			// The destroy must land *after* the server has
			// authenticated this request and before its handler acts.
			// The store says when that has happened: authentication
			// reads the session, which both the fixed code and the
			// code before it do. The body then finishes.
			authenticated := make(chan struct{})
			store.armSession(func() {
				replace()
				close(authenticated)
			})
			req, _ := http.NewRequest(c.method, srv.URL+Prefix+c.path,
				&slowBody{head: c.head, tail: c.tail, between: func() {
					select {
					case <-authenticated:
					case <-time.After(5 * time.Second):
						t.Error("the server never read the session: the window was never opened")
					}
				}})
			req.Header.Set("Cookie", attendee)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(auth.CSRFHeader, sess.CSRF)
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			out := jsonBody(t, resp)

			// What is being asserted is where the request *stopped*.
			// 404 means it was refused at the door, on the session's own
			// generation, before the engine was asked anything. Any
			// other answer — a success, or an engine error about the lab
			// that took the name — means the door let it through and the
			// engine was working on the replacement. That is the defect,
			// whether or not the write happened to land: this fixture's
			// replacement has no module directory on disk, so before the
			// fix these come back 500 and 409 rather than 200, and the
			// authorization decision had already been made wrongly by
			// then.
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("an attendee of the destroyed lab reached the engine against the one that took its name: %d (%s)",
					resp.StatusCode, errCodeOf(out))
			}
		})
	}
}
