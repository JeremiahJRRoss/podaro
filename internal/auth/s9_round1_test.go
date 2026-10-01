// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// The hook fires *after* the read here, not before it: the race this
// test is about is a revocation landing between the join's lookup and
// the session it opens, and a hook that ran first would only prove that
// a link revoked beforehand is refused — which was never in doubt.
func (r *raceStore) GetAccessByHash(hash string) (*state.Access, error) {
	acc, err := r.Store.GetAccessByHash(hash)
	r.intercept()
	return acc, err
}

// A revocation the operator has been told succeeded must stop the link.
// The join read the credential, minted the session, and *then* recorded
// the use — and a `TouchAccess` that answered not-found was only logged.
// So a revocation landing in that window returned success to the
// operator while the same link opened a working session.
//
// The comment above it called recording the use afterwards "the harmless
// half of the two". It was not: the harm is the whole guarantee.
func TestARevokedLinkOpensNoSession(t *testing.T) {
	inner := state.NewMemory()
	store := &raceStore{Store: inner}
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	svc := NewService(store, filepath.Join(t.TempDir(), "auth.json"))
	svc.SetClock(func() time.Time { return now })
	if err := inner.PutInstance(state.Instance{Name: "class", Template: "t", Mode: "delivery",
		Source: "/s", Created: now, Updated: now}); err != nil {
		t.Fatal(err)
	}
	secret, acc, err := svc.IssueAccess("class", 0, "alice", time.Hour, "jross", MechanismSocket)
	if err != nil {
		t.Fatal(err)
	}

	// The premise: the link works before the revocation.
	sess, _, err := svc.Join(secret, "203.0.113.9")
	if err != nil || sess == nil || sess.Instance != "class" {
		t.Fatalf("a live link opens a session: %+v %v", sess, err)
	}

	// The revocation lands between the lookup and the session.
	store.before = func() {
		if err := inner.DeleteAccessAudited("class", acc.ID,
			state.Audit{At: now, Instance: "class", Action: "access-revoke", Actor: "jross"}); err != nil {
			t.Fatal(err)
		}
	}
	got, _, err := svc.Join(secret, "203.0.113.9")
	if err == nil || got != nil {
		t.Fatalf("a link revoked mid-join opened a session: %+v %v", got, err)
	}
	// And it is refused in the one shape every other refusal takes: a
	// join page is reachable by anyone with the URL, so the answer must
	// not say which of the reasons applied.
	if msg := err.Error(); !strings.Contains(msg, "this access link is not valid") {
		t.Errorf("the refusal names the reason: %q", msg)
	}
	// And the live session is the only one there: the refused join stored
	// nothing, rather than a session that is refused later.
	if got, err := inner.GetSession(sess.ID); err != nil || got == nil {
		t.Errorf("the earlier session should be untouched: %+v %v", got, err)
	}
}

// And no credential is issued for a lab that is gone: a destroy
// committing between the handler's check and the write would leave a
// link joinable by name, valid again the moment that name is reused.
func TestNoLinkIsIssuedForAnInstanceThatIsGone(t *testing.T) {
	store := state.NewMemory()
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	svc := NewService(store, filepath.Join(t.TempDir(), "auth.json"))
	svc.SetClock(func() time.Time { return now })
	// And the operator reads the answer every other unknown instance
	// gives, not a runtime failure: the lab really is gone.
	_, _, err := svc.IssueAccess("gone", 0, "alice", time.Hour, "jross", MechanismSocket)
	if err == nil {
		t.Fatal("issuing for an instance that is not there succeeded")
	}
	var pe *pdr.Error
	if !errors.As(err, &pe) || pe.Code != pdr.CodeInstanceNotFound {
		t.Fatalf("the refusal is %v, want %s", err, pdr.CodeInstanceNotFound)
	}
	if got, _ := store.ListAccess("gone"); len(got) != 0 {
		t.Errorf("the refused issue left %d credentials", len(got))
	}
}

// Round 2: the join's touch-cache write was not under the mutex. The
// line was lifted out of newSession, whose caller holds s.mu for the
// whole login, into a path that holds nothing — while Resolve, the token
// paths, revocation and Sweep all take it. Two joins on one link raced
// on a plain map, which -race sees and a production process may not
// survive.
func TestConcurrentJoinsDoNotRaceTheTouchCache(t *testing.T) {
	store := state.NewMemory()
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	svc := NewService(store, filepath.Join(t.TempDir(), "auth.json"))
	svc.SetClock(func() time.Time { return now })
	if err := store.PutInstance(state.Instance{Name: "class", Template: "t", Mode: "delivery",
		Source: "/s", Created: now, Updated: now}); err != nil {
		t.Fatal(err)
	}
	secret, _, err := svc.IssueAccess("class", 0, "alice", time.Hour, "jross", MechanismSocket)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := svc.Join(secret, "203.0.113.9"); err != nil {
				t.Errorf("join: %v", err)
			}
		}()
	}
	wg.Wait()
}
