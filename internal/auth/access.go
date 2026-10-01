// SPDX-License-Identifier: AGPL-3.0-only

package auth

// Instance access credentials (API §2.4, plan S9): the `pdi_` link an
// operator hands an attendee, and the exchange that turns it into a
// session scoped to one instance.
//
// It is not a bearer credential. A `pdi_` secret buys exactly one thing —
// a session for its instance — and the grant that session carries is
// fixed by the engine, not by what the holder asks for. The secret is
// stored hashed, as an operator token is; it expires on its own, because
// a link handed out at the start of a workshop should stop working after
// it; and every issue, join and revocation lands in the instance's audit
// stream.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// AccessPrefix marks an instance access secret. It differs from
// TokenPrefix by one letter on purpose: the two are read by different
// doors, and a credential pasted into the wrong one is refused by shape
// rather than by lookup.
const AccessPrefix = "pdi_"

// AccessTTL bounds how long an access credential may live, and what one
// asking for nothing gets. A workshop is a day at the outside; a link
// that outlives the lab it opens is a credential nobody remembers
// issuing.
const (
	DefaultAccessTTL = 8 * time.Hour
	MaxAccessTTL     = 24 * time.Hour
)

// NewAccessSecret makes an access secret: the prefix and 32 random
// bytes, base64url.
func NewAccessSecret() (string, error) {
	raw, err := randomBytes(32)
	if err != nil {
		return "", err
	}
	return AccessPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// WellFormedAccessSecret reports whether a secret has that shape. A
// join is refused on shape before anything is looked up, so a pasted
// operator token never reaches the credential table at all.
func WellFormedAccessSecret(secret string) bool {
	rest, ok := strings.CutPrefix(secret, AccessPrefix)
	if !ok {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	return err == nil && len(raw) == 32
}

// AccessSecretPrefix is the part of an access secret a listing shows:
// the eight characters after the prefix, so an operator can tell one
// attendee's link from another without holding either.
func AccessSecretPrefix(secret string) string {
	rest := strings.TrimPrefix(secret, AccessPrefix)
	if len(rest) < 8 {
		return rest
	}
	return rest[:8]
}

func accessHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// IssueAccess mints an attendee credential for one instance. The secret
// is returned once — it is never stored, only its hash — and the record
// of the issue lands with it or neither does.
// IssueAccess mints an attendee credential for one instance.
//
// gen is the generation the *caller* resolved — an InstanceView's
// Generation(). The write below is bound to it, so a destroy and a
// re-create of the same name after that resolution refuses rather than
// handing the replacement a link issued for the lab that is gone. It is
// a parameter rather than something read here on purpose: round 10 read
// it here, which left the window between the caller's resolution and
// this one, and a second read is a second answer.
func (s *Service) IssueAccess(instance string, gen int64, name string, ttl time.Duration, actor, mechanism string) (secret string, acc *state.Access, err error) {
	if err := CheckUsername(name); err != nil {
		e := pdr.New(pdr.CodePasswordPolicy, "access name %q: lowercase letters, digits, '-', '.', '_' only, 1–32 characters", name)
		e.Next = "podaro access create <instance> --name alice --expires 8h"
		return "", nil, e
	}
	switch {
	case ttl == 0:
		ttl = DefaultAccessTTL
	case ttl < time.Minute:
		e := pdr.New(pdr.CodePasswordPolicy, "an access credential must live at least a minute, not %s", ttl)
		e.Next = "--expires 8h"
		return "", nil, e
	case ttl > MaxAccessTTL:
		e := pdr.New(pdr.CodePasswordPolicy, "an access credential may live at most %s, not %s", MaxAccessTTL, ttl)
		e.Cause = "a link that outlives the workshop it opens is a credential nobody remembers issuing"
		e.Next = "--expires 8h · issue a new one when the next session starts"
		return "", nil, e
	}
	secret, err = NewAccessSecret()
	if err != nil {
		return "", nil, err
	}
	id, err := randomBytes(tokenIDBytes)
	if err != nil {
		return "", nil, err
	}
	now := s.now().UTC()
	rec := &state.Access{
		ID:       hex.EncodeToString(id),
		Instance: instance,
		Name:     name,
		Prefix:   AccessSecretPrefix(secret),
		Hash:     accessHash(secret),
		Created:  now,
		Expires:  now.Add(ttl),
	}
	audit := state.Audit{At: now, Instance: instance, Action: "access-issue", Actor: actor, Mechanism: mechanism,
		Detail: fmt.Sprintf("%s · expires %s", name, rec.Expires.Format(time.RFC3339))}
	if err := s.store.PutAccessAudited(*rec, gen, audit); err != nil {
		// The store refuses a credential for a lab that is not there,
		// which is how a destroy racing this issue is closed out. What
		// the operator is owed then is the answer every other unknown
		// instance gets, not a runtime failure: the lab really is gone.
		if errors.Is(err, state.ErrNotFound) {
			e := pdr.New(pdr.CodeInstanceNotFound, "no such instance %q", instance)
			e.Cause = "the instance was destroyed while the credential was being issued"
			e.Next = "podaro status · issue the link on a lab that exists"
			return "", nil, e
		}
		return "", nil, fmt.Errorf("issue access for %s: %w", instance, err)
	}
	return secret, rec, nil
}

// Join exchanges an access secret for a session scoped to its instance.
// The refusals are deliberately one shape — a secret that is malformed,
// unknown, expired or revoked all answer `PDR-E311` with the same
// message — so a link that does not work says so without saying which of
// those it is: a join page is reachable by anyone with the URL.
func (s *Service) Join(secret, source string) (*state.Session, *state.Access, error) {
	refuse := func() (*state.Session, *state.Access, error) {
		e := pdr.New(pdr.CodeSessionRefused, "this access link is not valid")
		e.Cause = "the link is malformed, expired, or has been revoked"
		e.Next = "ask the operator for a new link"
		return nil, nil, e
	}
	if !WellFormedAccessSecret(secret) {
		return refuse()
	}
	acc, err := s.store.GetAccessByHash(accessHash(secret))
	if err != nil || acc == nil {
		return refuse()
	}
	now := s.now().UTC()
	if !acc.Expires.After(now) {
		return refuse()
	}
	// The session's subject is the attendee's name, so every audited act
	// it performs — a reveal above all — says who did it.
	//
	// The use, the session and the audit record are one write, and the
	// credential still being there is what admits them. Recording the use
	// *after* the session was called the harmless half of a race, and it
	// was not: a revocation could return success to the operator and this
	// link still open a session, because a `TouchAccess` that answered
	// not-found was only logged. Now nothing is stored at all, and the
	// join is refused in the same shape as every other refusal, which is
	// what a revoked link is owed.
	sess, err := s.joinSession(acc, now, source)
	if err != nil {
		if errors.Is(err, state.ErrNotFound) {
			return refuse()
		}
		return nil, nil, err
	}
	return sess, acc, nil
}

// joinSession mints the session the access row opens and hands both it
// and the record to the store as one write.
func (s *Service) joinSession(acc *state.Access, now time.Time, source string) (*state.Session, error) {
	id, err := randomBytes(24)
	if err != nil {
		return nil, err
	}
	csrf, err := randomBytes(24)
	if err != nil {
		return nil, err
	}
	sess := &state.Session{
		ID: hex.EncodeToString(id), Subject: acc.Name, Mechanism: MechanismSession, Instance: acc.Instance,
		// The credential's generation, not one read here: the link was
		// issued for one lab, and the session it opens is for that lab
		// and no later namesake. Copying it rather than looking it up
		// keeps the binding to a single resolution, the way round 11
		// had to learn.
		Gen:  acc.Gen,
		CSRF: base64.RawURLEncoding.EncodeToString(csrf), Created: now, LastSeen: now, Expires: now.Add(SessionIdle),
	}
	// Two records, two readers. The instance's stream is the attendee's:
	// `Engine.Evidence` merges it into GET …/evidence and the event feed
	// serializes every row's detail, both inside the attendee grant — so
	// a peer address recorded there is one attendee's network address
	// handed to every other attendee of the same lab. Where a link was
	// used from is the operator's security record, and it goes where the
	// operator's own login records go: the system stream, which only the
	// local socket reads (GET /system/audit, API §7). The lab's row says
	// who joined and when, which is what its evidence is for.
	//
	// Not a filter at the read: the report an operator exports and may
	// hand to attendees is built from these same rows, so a stream that
	// holds no address cannot leak one however it is read.
	rec := state.Audit{
		At: now, Instance: acc.Instance, Action: "join", Actor: acc.Name, Mechanism: MechanismSession,
	}
	sys := state.Audit{
		At: now, Action: "join", Actor: acc.Name, Mechanism: MechanismSession,
		Detail: acc.Instance + " · " + acc.ID + " · " + source,
	}
	if err := s.store.JoinAccessAudited(acc.ID, now, *sess, rec, sys); err != nil {
		return nil, err
	}
	// A fresh record needs no slide for a minute: the cookie issued with
	// it already carries the full idle window.
	//
	// Under the mutex, because this line was lifted out of newSession —
	// whose caller, Login, holds it for the whole login — into a path
	// that does not. Every other reader and writer of `touched` (Resolve,
	// the token paths, revocation, Sweep) takes s.mu, so two joins on one
	// link raced here and could have panicked the process on a concurrent
	// map write.
	s.mu.Lock()
	s.touched[sess.ID] = now
	s.mu.Unlock()
	return sess, nil
}

// ListAccess returns one instance's credentials, oldest first. The
// secrets are not there to return: only names, prefixes, expiry and last
// use, which is what an operator needs to revoke the right one.
func (s *Service) ListAccess(instance string) ([]state.Access, error) {
	return s.store.ListAccess(instance)
}

// RevokeAccess removes one credential immediately. Sessions already
// joined are not swept here: they carry their own idle expiry, and the
// engine's grant bounds them — what revocation stops is the next join.
func (s *Service) RevokeAccess(instance, id, actor, mechanism string) error {
	now := s.now().UTC()
	err := s.store.DeleteAccessAudited(instance, id, state.Audit{
		At: now, Instance: instance, Action: "access-revoke", Actor: actor, Mechanism: mechanism, Detail: id,
	})
	if err != nil {
		if errors.Is(err, state.ErrNotFound) {
			e := pdr.New(pdr.CodeTokenNotFound, "no access credential %s on instance %s", id, instance)
			e.Next = "podaro access list " + instance
			return e
		}
		return err
	}
	return nil
}
