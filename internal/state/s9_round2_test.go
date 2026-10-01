// SPDX-License-Identifier: AGPL-3.0-only

package state

import (
	"errors"
	"testing"
	"time"
)

// A destroy took the instance's access credentials and left the sessions
// those credentials had opened. Nothing re-checks the instance when a
// session is resolved — a session is bound by *name* — so an attendee's
// cookie stayed valid for the rest of its idle window and became valid
// against the **next** lab of that name, reveals included.
//
// Round 1 closed the same window for the credential and did not ask what
// its sibling should do. This is the sibling.
func TestDestroyTakesTheSessionsItsLinksOpened(t *testing.T) {
	for _, c := range []struct {
		name string
		open func(*testing.T) Store
	}{
		{"memory", func(*testing.T) Store { return NewMemory() }},
		{"sqlite", func(t *testing.T) Store {
			s, err := OpenSQLite(t.TempDir() + "/state.db")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			return s
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := c.open(t)
			now := time.Now().UTC().Truncate(time.Second)
			if err := s.PutInstance(Instance{Name: "class", Template: "t", Mode: "delivery",
				Source: "/s", Created: now, Updated: now}); err != nil {
				t.Fatal(err)
			}
			bound := Session{ID: "att-1", Subject: "alice", Mechanism: "instance-access", Instance: "class",
				CSRF: "c1", Created: now, LastSeen: now, Expires: now.Add(12 * time.Hour)}
			operator := Session{ID: "op-1", Subject: "jross", Mechanism: "session",
				CSRF: "c2", Created: now, LastSeen: now, Expires: now.Add(12 * time.Hour)}
			for _, sess := range []Session{bound, operator} {
				if err := s.PutSession(sess); err != nil {
					t.Fatal(err)
				}
			}
			// The premise: both are there before the destroy.
			for _, id := range []string{"att-1", "op-1"} {
				if got, err := s.GetSession(id); err != nil || got == nil {
					t.Fatalf("premise: %s is not stored: %v", id, err)
				}
			}

			if err := s.DeleteInstance("class"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.GetSession("att-1"); !errors.Is(err, ErrNotFound) {
				t.Errorf("a session bound to the destroyed lab outlived it: %v", err)
			}
			// The operator's session is bound to no instance and stays.
			if got, err := s.GetSession("op-1"); err != nil || got == nil {
				t.Errorf("the destroy took a session that was not the lab's: %v", err)
			}
		})
	}
}
