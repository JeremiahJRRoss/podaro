// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

func newService(t *testing.T) (*Service, *state.Memory, *time.Time) {
	t.Helper()
	store := state.NewMemory()
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	svc := NewService(store, filepath.Join(t.TempDir(), "auth.json"))
	svc.SetClock(func() time.Time { return now })
	return svc, store, &now
}

func code(t *testing.T, err error, want string) *pdr.Error {
	t.Helper()
	var pe *pdr.Error
	if !errors.As(err, &pe) || pe.Code != want {
		t.Fatalf("want %s, got %v", want, err)
	}
	return pe
}

// The operator file: policy enforced before hashing, 0600 at rest, the
// hash verifies, a second setup is refused, reset rotates the key.
func TestOperatorLifecycle(t *testing.T) {
	svc, store, _ := newService(t)
	if err := svc.SetOperator("jross", "short", false, MechanismSocket); err == nil {
		t.Fatal("short password accepted")
	} else {
		code(t, err, pdr.CodePasswordPolicy)
	}
	code(t, svc.SetOperator("jross", "qwerty123456", false, MechanismSocket), pdr.CodePasswordPolicy) // on the common list
	code(t, svc.SetOperator("J Ross", "correct horse battery", false, MechanismSocket), pdr.CodePasswordPolicy)
	if _, err := svc.Operator(); !errors.Is(err, ErrNoOperator) {
		t.Fatalf("operator before setup: %v", err)
	}
	if err := svc.SetOperator("jross", "correct horse battery", false, MechanismSocket); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(svc.path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("auth.json mode: %v %v", fi, err)
	}
	raw, _ := os.ReadFile(svc.path)
	if strings.Contains(string(raw), "correct horse") {
		t.Fatal("password stored in clear")
	}
	op, err := svc.Operator()
	if err != nil || op.Username != "jross" || !op.Verify("correct horse battery") || op.Verify("correct horse batter") {
		t.Fatalf("operator: %+v %v", op, err)
	}
	code(t, svc.SetOperator("jross", "another long password", false, MechanismSocket), pdr.CodeOperatorExists)
	key1 := op.SessionKey()
	sess, err := svc.Login("203.0.113.9", "jross", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := svc.CookieValue(sess)
	if _, err := svc.SessionFromCookie(cookie); err != nil {
		t.Fatalf("session before reset: %v", err)
	}
	if err := svc.SetOperator("jross", "another long password", true, MechanismSocket); err != nil {
		t.Fatal(err)
	}
	op2, _ := svc.Operator()
	if string(op2.SessionKey()) == string(key1) {
		t.Fatal("reset did not rotate the session key")
	}
	if _, err := svc.SessionFromCookie(cookie); !errors.Is(err, ErrNoSession) {
		t.Fatalf("session survives reset: %v", err)
	}
	audit, _ := store.ListAudit("")
	var actions []string
	for _, a := range audit {
		actions = append(actions, a.Action)
	}
	if got := strings.Join(actions, " "); got != "operator-created login operator-reset" {
		t.Fatalf("audit: %s", got)
	}
}

// Throttle and lockout (API §2.1): backoff 1/2/4/8 s refuses attempts
// inside the window without counting them, the fifth failure locks for
// 15 minutes, the sweep releases and audits, success resets the count.
func TestThrottleAndLockout(t *testing.T) {
	svc, store, now := newService(t)
	if _, err := svc.Login("203.0.113.9", "jross", "whatever password"); err == nil {
		t.Fatal("login before setup")
	} else {
		code(t, err, pdr.CodeNoOperator)
	}
	if err := svc.SetOperator("jross", "correct horse battery", false, MechanismSocket); err != nil {
		t.Fatal(err)
	}
	src := "203.0.113.9"
	waits := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}
	for i, wait := range waits {
		_, err := svc.Login(src, "jross", "wrong password here")
		code(t, err, pdr.CodeLoginFailed)
		// Inside the backoff: throttled, not counted.
		_, err = svc.Login(src, "jross", "correct horse battery")
		var th *Throttled
		if !errors.As(err, &th) || th.Env.Code != pdr.CodeLoginThrottled || th.RetryAfter != wait {
			t.Fatalf("attempt %d: want throttled %s, got %v", i+1, wait, err)
		}
		if ls, _ := store.GetLoginState(src); ls.Failures != i+1 {
			t.Fatalf("throttled attempt counted: %+v", ls)
		}
		*now = now.Add(wait)
	}
	// Another source is unaffected.
	if _, err := svc.Login("198.51.100.4", "jross", "correct horse battery"); err != nil {
		t.Fatalf("other source: %v", err)
	}
	// Fifth failure: lockout.
	_, err := svc.Login(src, "jross", "wrong password here")
	code(t, err, pdr.CodeLoginFailed)
	ls, _ := store.GetLoginState(src)
	if ls.LockedUntil == nil || !ls.LockedUntil.Equal(now.Add(LockoutDuration)) {
		t.Fatalf("no lockout after %d failures: %+v", LockoutAfter, ls)
	}
	_, err = svc.Login(src, "jross", "correct horse battery")
	var th *Throttled
	if !errors.As(err, &th) || th.Env.Code != pdr.CodeLoginLocked || th.RetryAfter != LockoutDuration {
		t.Fatalf("locked: %v", err)
	}
	*now = now.Add(LockoutDuration - time.Second)
	svc.Sweep()
	if ls, _ := store.GetLoginState(src); ls.LockedUntil == nil {
		t.Fatal("sweep released early")
	}
	*now = now.Add(time.Second)
	svc.Sweep()
	if ls, _ := store.GetLoginState(src); ls.LockedUntil != nil || ls.Failures != 0 {
		t.Fatalf("sweep did not release: %+v", ls)
	}
	if _, err := svc.Login(src, "jross", "correct horse battery"); err != nil {
		t.Fatalf("login after release: %v", err)
	}
	audit, _ := store.ListAudit("")
	var actions []string
	for _, a := range audit {
		actions = append(actions, a.Action)
	}
	want := "operator-created login-failed login-failed login-failed login-failed login login-failed lockout lockout-released login"
	if got := strings.Join(actions, " "); got != want {
		t.Fatalf("audit:\n got %s\nwant %s", got, want)
	}
	// Lazy release: a locked source whose lockout lapsed without a sweep.
	for i := 0; i < LockoutAfter; i++ {
		_, _ = svc.Login(src, "jross", "wrong password here")
		*now = now.Add(backoffMax)
	}
	if ls, _ := store.GetLoginState(src); ls.LockedUntil == nil {
		t.Fatal("expected lockout")
	}
	*now = now.Add(LockoutDuration)
	if _, err := svc.Login(src, "jross", "correct horse battery"); err != nil {
		t.Fatalf("lazy release: %v", err)
	}
}

// Sessions: signed cookie, idle expiry that slides on use, logout.
func TestSessions(t *testing.T) {
	svc, store, now := newService(t)
	if err := svc.SetOperator("jross", "correct horse battery", false, MechanismSocket); err != nil {
		t.Fatal(err)
	}
	sess, err := svc.Login("203.0.113.9", "jross", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if sess.CSRF == "" || sess.Subject != "jross" || sess.Mechanism != MechanismSession || !sess.Expires.Equal(now.Add(SessionIdle)) {
		t.Fatalf("session: %+v", sess)
	}
	cookie, _ := svc.CookieValue(sess)
	flipped := "0" + cookie[1:]
	if cookie[0] == '0' {
		flipped = "1" + cookie[1:]
	}
	for _, bad := range []string{"", "x", sess.ID, sess.ID + ".", sess.ID + ".AAAA", flipped, cookie + "x"} {
		if _, err := svc.SessionFromCookie(bad); !errors.Is(err, ErrNoSession) {
			t.Errorf("cookie %q accepted", bad)
		}
	}
	got, err := svc.SessionFromCookie(cookie)
	if err != nil || got.ID != sess.ID {
		t.Fatalf("cookie: %v", err)
	}
	*now = now.Add(11 * time.Hour)
	if got, err := svc.SessionFromCookie(cookie); err != nil || !got.Expires.Equal(now.Add(SessionIdle)) {
		t.Fatalf("idle expiry did not slide: %+v %v", got, err)
	}
	*now = now.Add(SessionIdle + time.Second)
	if _, err := svc.SessionFromCookie(cookie); !errors.Is(err, ErrNoSession) {
		t.Fatal("expired session accepted")
	}
	if _, err := store.GetSession(sess.ID); !errors.Is(err, state.ErrNotFound) {
		t.Fatal("expired session not removed")
	}
	sess2, _ := svc.Login("203.0.113.9", "jross", "correct horse battery")
	svc.Logout(sess2)
	c2, _ := svc.CookieValue(sess2)
	if _, err := svc.SessionFromCookie(c2); !errors.Is(err, ErrNoSession) {
		t.Fatal("session survives logout")
	}
}

// Tokens: shown once, hashed at rest, scoped, unique by name, revocable,
// last use tracked.
func TestTokens(t *testing.T) {
	svc, store, now := newService(t)
	if _, _, err := svc.CreateToken("ci", "root", "jross", MechanismSocket); err == nil {
		t.Fatal("bad scope accepted")
	}
	if _, _, err := svc.CreateToken("Bad Name", "read", "jross", MechanismSocket); err == nil {
		t.Fatal("bad name accepted")
	}
	secret, tok, err := svc.CreateToken("ci", "read", "jross", MechanismSocket)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, TokenPrefix) || len(secret) < 40 || tok.Prefix != secret[4:12] || tok.Scope != "read" {
		t.Fatalf("token: %s %+v", secret, tok)
	}
	stored, _ := store.GetTokenByHash(hashToken(secret))
	if stored == nil || stored.Hash == secret || strings.Contains(stored.Hash, secret[4:]) {
		t.Fatalf("secret stored: %+v", stored)
	}
	_, _, err = svc.CreateToken("ci", "admin", "jross", MechanismSocket)
	code(t, err, pdr.CodeTokenExists)
	for _, bad := range []string{"", "Bearer", "Bearer nope", "Basic " + secret, "Bearer " + secret + "x", "Bearer pdr_" + strings.Repeat("A", 43)} {
		if _, err := svc.TokenFromBearer(bad); !errors.Is(err, ErrNoSession) {
			t.Errorf("header %q accepted", bad)
		}
	}
	got, err := svc.TokenFromBearer("bearer " + secret)
	if err != nil || got.ID != tok.ID || got.LastUsed == nil || !got.LastUsed.Equal(*now) {
		t.Fatalf("bearer: %+v %v", got, err)
	}
	if !Allows(got.Scope, ScopeRead) || Allows(got.Scope, ScopeOperate) || Allows(got.Scope, ScopeAdmin) || !Allows(ScopeAdmin, ScopeOperate) || Allows("", ScopeRead) {
		t.Fatal("scope ordering")
	}
	list, _ := svc.ListTokens()
	if len(list) != 1 || list[0].Name != "ci" {
		t.Fatalf("list: %+v", list)
	}
	code(t, svc.RevokeToken("nope", "jross", MechanismSocket), pdr.CodeTokenNotFound)
	if err := svc.RevokeToken("ci", "jross", MechanismSocket); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.TokenFromBearer("Bearer " + secret); !errors.Is(err, ErrNoSession) {
		t.Fatal("revoked token accepted")
	}
	audit, _ := store.ListAudit("")
	var actions []string
	for _, a := range audit {
		actions = append(actions, a.Action)
	}
	if got := strings.Join(actions, " "); got != "token-created token-revoked" {
		t.Fatalf("audit: %s", got)
	}
}

func TestCommonPasswordListIsLoaded(t *testing.T) {
	if n := len(commonPasswords()); n < 1000 {
		t.Fatalf("common list has %d entries", n)
	}
	if err := CheckPassword("Correct-Horse-Battery-Staple"); err != nil {
		t.Fatalf("good password refused: %v", err)
	}
	if err := CheckPassword("QWERTY123456"); err == nil {
		t.Fatal("case-variant of a common password accepted")
	}
}

// auditFault is a store whose audit writes fail on demand.
type auditFault struct {
	state.Store
	fail bool
}

func (f *auditFault) AppendAudit(a state.Audit) error {
	if f.fail {
		return errors.New("disk full")
	}
	return f.Store.AppendAudit(a)
}

func (f *auditFault) PutSessionAudited(sess state.Session, a state.Audit) error {
	if f.fail {
		return errors.New("disk full")
	}
	return f.Store.PutSessionAudited(sess, a)
}

func (f *auditFault) PutLoginStateAudited(ls state.LoginState, records ...state.Audit) error {
	if f.fail {
		return errors.New("disk full")
	}
	return f.Store.PutLoginStateAudited(ls, records...)
}

func (f *auditFault) PutTokenAudited(tok state.Token, a state.Audit) error {
	if f.fail {
		return errors.New("disk full")
	}
	return f.Store.PutTokenAudited(tok, a)
}

func (f *auditFault) DeleteTokenAudited(id string, a state.Audit) error {
	if f.fail {
		return errors.New("disk full")
	}
	return f.Store.DeleteTokenAudited(id, a)
}

func (f *auditFault) DeleteSessionAudited(id string, a state.Audit) error {
	if f.fail {
		return errors.New("disk full")
	}
	return f.Store.DeleteSessionAudited(id, a)
}

// Audit records are load-bearing (API §2.5): an act whose record cannot
// be written does not happen — no operator file, no session, no token,
// no revocation, no sign-out — and the caller sees the store's fault.
func TestUnauditedActsDoNotHappen(t *testing.T) {
	store := state.NewMemory()
	faulty := &auditFault{Store: store, fail: true}
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "auth.json")
	svc := NewService(faulty, path)
	svc.SetClock(func() time.Time { return now })
	if err := svc.SetOperator("jross", "correct horse battery", false, MechanismSocket); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("operator creation must report the refused record: %v", err)
	}
	if svc.HasOperator() {
		t.Fatal("an unaudited operator file must not be moved into place")
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("the temporary operator file must be removed")
	}
	faulty.fail = false
	if err := svc.SetOperator("jross", "correct horse battery", false, MechanismSocket); err != nil {
		t.Fatal(err)
	}
	sess, err := svc.Login("203.0.113.9", "jross", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := svc.CookieValue(sess)
	faulty.fail = true
	if _, err := svc.Login("203.0.113.9", "jross", "correct horse battery"); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("a login whose record is refused must fail with the fault: %v", err)
	}
	// Five wrong passwords under a refusing stream: each surfaces the
	// fault, none is counted or throttled, and no lockout stands — the
	// right password then signs in at once.
	for i := 0; i < LockoutAfter; i++ {
		var pe *pdr.Error
		_, err := svc.Login("203.0.113.9", "jross", "wrong password here")
		if err == nil || !strings.Contains(err.Error(), "disk full") || errors.As(err, &pe) {
			t.Fatalf("attempt %d: a failure whose record is refused must surface the fault, not an envelope: %v", i+1, err)
		}
	}
	faulty.fail = false
	sess2, err := svc.Login("203.0.113.9", "jross", "correct horse battery")
	if err != nil {
		t.Fatalf("uncounted failures must not lock or throttle the source: %v", err)
	}
	if err := svc.Logout(sess2); err != nil {
		t.Fatal(err)
	}
	faulty.fail = true
	if err := svc.Logout(sess); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("a sign-out whose record is refused must fail: %v", err)
	}
	if _, err := svc.SessionFromCookie(cookie); err != nil {
		t.Fatal("the session must stand until its sign-out is on record")
	}
	if _, _, err := svc.CreateToken("ci", ScopeRead, "jross", MechanismSocket); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("a token whose record is refused must not be created: %v", err)
	}
	if list, _ := svc.ListTokens(); len(list) != 0 {
		t.Fatalf("no token may exist unaudited: %+v", list)
	}
	faulty.fail = false
	secret, tok, err := svc.CreateToken("ci", ScopeRead, "jross", MechanismSocket)
	if err != nil {
		t.Fatal(err)
	}
	faulty.fail = true
	if err := svc.RevokeToken(tok.Name, "jross", MechanismSocket); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("a revocation whose record is refused must fail: %v", err)
	}
	if got, err := svc.TokenFromBearer("Bearer " + secret); err != nil || got.ID != tok.ID {
		t.Fatal("the token must keep working until its revocation is on record")
	}
	// Only the audited session exists.
	if n, _ := store.PurgeSessions(now.AddDate(1, 0, 0)); n != 1 {
		t.Fatalf("sessions in the store: %d, want the one audited login", n)
	}
}

// sessionWriteFault is a store whose session writes fail on demand and
// are counted.
type sessionWriteFault struct {
	state.Store
	fail  bool
	tries int
}

func (f *sessionWriteFault) PutSession(sess state.Session) error {
	f.tries++
	if f.fail {
		return errors.New("disk full")
	}
	return f.Store.PutSession(sess)
}

func (f *sessionWriteFault) TouchSession(id string, lastSeen, expires time.Time) error {
	f.tries++
	if f.fail {
		return errors.New("disk full")
	}
	return f.Store.TouchSession(id, lastSeen, expires)
}

// A slide is reported only once the record holds it: a refused write
// leaves the expiry, the cookie and the retry as they were.
func TestSlideIsReportedOnlyWhenStored(t *testing.T) {
	store := state.NewMemory()
	faulty := &sessionWriteFault{Store: store}
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	svc := NewService(faulty, filepath.Join(t.TempDir(), "auth.json"))
	svc.SetClock(func() time.Time { return now })
	if err := svc.SetOperator("jross", "correct horse battery", false, MechanismSocket); err != nil {
		t.Fatal(err)
	}
	sess, err := svc.Login("203.0.113.9", "jross", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := svc.CookieValue(sess)
	expires := sess.Expires
	faulty.fail = true
	now = now.Add(2 * time.Minute)
	before := faulty.tries
	got, slid, err := svc.Resolve(cookie)
	if err != nil || slid {
		t.Fatalf("a refused write must not report a slide: slid=%v err=%v", slid, err)
	}
	if !got.Expires.Equal(expires) {
		t.Fatalf("the session handed back must carry the stored expiry %s, not %s", expires, got.Expires)
	}
	if stored, _ := store.GetSession(sess.ID); !stored.Expires.Equal(expires) {
		t.Fatalf("the record must be unchanged: %s", stored.Expires)
	}
	if _, slid, _ := svc.Resolve(cookie); slid || faulty.tries != before+2 {
		t.Fatalf("the next request must try again (writes attempted: %d, want %d)", faulty.tries-before, 2)
	}
	faulty.fail = false
	if _, slid, err := svc.Resolve(cookie); err != nil || !slid {
		t.Fatalf("once the write succeeds the slide is reported: slid=%v err=%v", slid, err)
	}
	if stored, _ := store.GetSession(sess.ID); !stored.Expires.Equal(now.Add(SessionIdle)) {
		t.Fatalf("the stored expiry must have moved: %s", stored.Expires)
	}
}

// raceStore lets a test land a store-level deletion between a service's
// read of a record and its write-back: before runs once, on the first
// write it intercepts, in the caller's goroutine — the interleaving a
// concurrent sign-out or revocation produces.
type raceStore struct {
	state.Store
	before func()
	// skip lets that many interceptions pass before before fires: a call
	// the service makes twice (the lookup, then the check that the row is
	// still there) can be raced on the second.
	skip int
}

func (r *raceStore) intercept() {
	if r.before == nil {
		return
	}
	if r.skip > 0 {
		r.skip--
		return
	}
	f := r.before
	r.before = nil
	f()
}

func (r *raceStore) GetSession(id string) (*state.Session, error) {
	r.intercept()
	return r.Store.GetSession(id)
}

func (r *raceStore) GetTokenByHash(hash string) (*state.Token, error) {
	r.intercept()
	return r.Store.GetTokenByHash(hash)
}

func (r *raceStore) PutSession(sess state.Session) error {
	r.intercept()
	return r.Store.PutSession(sess)
}

func (r *raceStore) TouchSession(id string, lastSeen, expires time.Time) error {
	r.intercept()
	return r.Store.TouchSession(id, lastSeen, expires)
}

func (r *raceStore) PutToken(tok state.Token) error {
	r.intercept()
	return r.Store.PutToken(tok)
}

func (r *raceStore) TouchToken(id string, lastUsed time.Time) error {
	r.intercept()
	return r.Store.TouchToken(id, lastUsed)
}

// A sign-out is never undone by a slide: the slide
// moves the record in place, so a request that read the session before
// the sign-out removed it finds nothing to move, is refused, and leaves
// no record behind — never a resurrected session with a re-issued cookie.
func TestASignOutIsNeverUndoneByASlide(t *testing.T) {
	inner := state.NewMemory()
	store := &raceStore{Store: inner}
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	svc := NewService(store, filepath.Join(t.TempDir(), "auth.json"))
	svc.SetClock(func() time.Time { return now })
	if err := svc.SetOperator("jross", "correct horse battery", false, MechanismSocket); err != nil {
		t.Fatal(err)
	}
	sess, err := svc.Login("203.0.113.9", "jross", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := svc.CookieValue(sess)
	now = now.Add(2 * time.Minute)
	store.skip = 1          // let the cookie's own read pass; race the write after it
	store.before = func() { // the sign-out's deletion lands between the read and the slide's write
		if err := inner.DeleteSession(sess.ID); err != nil {
			t.Fatal(err)
		}
	}
	got, slid, err := svc.Resolve(cookie)
	if err == nil || slid || got != nil {
		t.Fatalf("a request racing the sign-out must be refused: %+v slid=%v err=%v", got, slid, err)
	}
	if _, err := inner.GetSession(sess.ID); err != state.ErrNotFound {
		t.Fatalf("the slide brought the signed-out session back: %v", err)
	}
	if _, err := svc.Peek(cookie); err == nil {
		t.Fatal("the cookie must be dead after the sign-out")
	}
}

// A revocation is never undone by the last-used mark:
// the mark updates the existing row, so a request that looked the
// token up before the revocation removed it finds nothing to mark, is
// refused, and the secret stays dead.
func TestARevocationIsNeverUndoneByALastUsedMark(t *testing.T) {
	inner := state.NewMemory()
	store := &raceStore{Store: inner}
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	svc := NewService(store, filepath.Join(t.TempDir(), "auth.json"))
	svc.SetClock(func() time.Time { return now })
	secret, tok, err := svc.CreateToken("ci", ScopeRead, "jross", MechanismSocket)
	if err != nil {
		t.Fatal(err)
	}
	store.before = func() { // the revocation's deletion lands between the lookup and the mark
		if err := inner.DeleteToken(tok.ID); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := svc.TokenFromBearer("Bearer " + secret); err == nil || got != nil {
		t.Fatalf("a request racing the revocation must be refused: %+v %v", got, err)
	}
	if list, _ := inner.ListTokens(); len(list) != 0 {
		t.Fatalf("the last-used mark brought the revoked token back: %+v", list)
	}
	if _, err := svc.TokenFromBearer("Bearer " + secret); err == nil {
		t.Fatal("the revoked secret must stay dead")
	}
}

// Two operator records never share a temporary file:
// each SaveTemp writes a file of its own, so a replacement that
// audits its record can only ever move that record into place, and two
// written at once cannot leave one malformed file.
func TestOperatorRecordsNeverShareATemporaryFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	op, err := NewOperator("jross", "correct horse battery", now)
	if err != nil {
		t.Fatal(err)
	}
	a, err := op.SaveTemp(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := op.SaveTemp(path)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("two records share one temporary file: %s", a)
	}
	for _, tmp := range []string{a, b} {
		st, err := os.Stat(tmp)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: mode %o", tmp, st.Mode().Perm())
		}
		if filepath.Dir(tmp) != filepath.Dir(path) {
			t.Fatalf("%s is not beside %s", tmp, path)
		}
		if got, err := LoadOperator(tmp); err != nil || got.Username != "jross" {
			t.Fatalf("%s: %v", tmp, err)
		}
	}
}

// Operator replacements happen one at a time:
// concurrent resets leave one whole record in place — the one the last
// audit record names — and no temporary file behind, not even one a
// crash left there.
func TestConcurrentOperatorResetsLeaveOneWholeRecord(t *testing.T) {
	svc, store, _ := newService(t)
	if err := svc.SetOperator("jross", "correct horse battery", false, MechanismSocket); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(svc.path+".crashed.tmp", []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- svc.SetOperator(fmt.Sprintf("operator%d", i), "correct horse battery", true, MechanismSocket)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	op, err := LoadOperator(svc.path)
	if err != nil {
		t.Fatalf("the record in place must be whole: %v", err)
	}
	audit, _ := store.ListAudit("")
	last := audit[len(audit)-1]
	if last.Action != "operator-reset" || last.Actor != op.Username {
		t.Fatalf("the record in place must be the one last audited: %s by %s, on disk %s", last.Action, last.Actor, op.Username)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(svc.path), "*.tmp")); len(left) != 0 {
		t.Fatalf("temporary files left behind: %v", left)
	}
}

// A login in flight at a reset is signed out by it:
// the login holds the operator lock's read side from loading the record
// to storing its session, so a reset that lands in that window waits for
// it and then purges what it stored; the old password never signs in
// after the reset, whichever began first.
func TestALoginInFlightAtAResetIsDroppedByIt(t *testing.T) {
	svc, store, _ := newService(t)
	if err := svc.SetOperator("jross", "correct horse battery", false, MechanismSocket); err != nil {
		t.Fatal(err)
	}
	reset := make(chan error, 1)
	var once sync.Once
	svc.afterOperatorLoad = func() {
		once.Do(func() {
			// The reset lands in the window between the load and the
			// verification. Without the lock it runs to completion here;
			// with it, it waits for this login and the window closes.
			go func() { reset <- svc.SetOperator("jross", "another long password", true, MechanismSocket) }()
			select {
			case err := <-reset:
				reset <- err
			case <-time.After(2 * time.Second):
			}
		})
	}
	sess, err := svc.Login("203.0.113.9", "jross", "correct horse battery")
	if err != nil {
		t.Fatalf("the login that began before the reset completes: %v", err)
	}
	if err := <-reset; err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSession(sess.ID); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("the session of a login the reset raced must be signed out by it: %v", err)
	}
	if _, err := svc.Login("203.0.113.9", "jross", "correct horse battery"); err == nil {
		t.Fatal("the old password must not sign in after the reset")
	} else {
		code(t, err, pdr.CodeLoginFailed)
	}
	if _, err := svc.Login("203.0.113.10", "jross", "another long password"); err != nil {
		t.Fatalf("the new password signs in: %v", err)
	}
}

// The mark is what catches a sign-out that landed since the cookie was
// verified — and inside the touch's minute there is no mark, so the
// throttled path asks the store instead: a session deleted between the
// verification and the answer is never authenticated by a request that
// happens to arrive soon after the last one.
func TestAThrottledSlideStillObservesASignOut(t *testing.T) {
	inner := state.NewMemory()
	store := &raceStore{Store: inner}
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	svc := NewService(store, filepath.Join(t.TempDir(), "auth.json"))
	svc.SetClock(func() time.Time { return now })
	if err := svc.SetOperator("jross", "correct horse battery", false, MechanismSocket); err != nil {
		t.Fatal(err)
	}
	sess, err := svc.Login("203.0.113.9", "jross", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := svc.CookieValue(sess)
	// A request inside the login's minute: the touch is throttled.
	now = now.Add(10 * time.Second)
	store.skip = 1 // the cookie's own read passes; the check after it is raced
	store.before = func() {
		if err := inner.DeleteSession(sess.ID); err != nil {
			t.Fatal(err)
		}
	}
	got, slid, err := svc.Resolve(cookie)
	if err == nil || slid || got != nil {
		t.Fatalf("a throttled request racing the sign-out must be refused: %+v slid=%v err=%v", got, slid, err)
	}
	if _, err := svc.Peek(cookie); err == nil {
		t.Fatal("the cookie must be dead after the sign-out")
	}
}

// The same on the token path: inside the mark's minute the token is
// looked up once more rather than trusted, so a revocation that landed
// since the lookup is observed.
func TestAThrottledMarkStillObservesARevocation(t *testing.T) {
	inner := state.NewMemory()
	store := &raceStore{Store: inner}
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	svc := NewService(store, filepath.Join(t.TempDir(), "auth.json"))
	svc.SetClock(func() time.Time { return now })
	if err := svc.SetOperator("jross", "correct horse battery", false, MechanismSocket); err != nil {
		t.Fatal(err)
	}
	secret, tok, err := svc.CreateToken("ci", ScopeRead, "jross", MechanismSocket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.TokenFromBearer("Bearer " + secret); err != nil {
		t.Fatalf("the token must authenticate: %v", err)
	}
	// Inside the mark's minute: the write is throttled.
	now = now.Add(10 * time.Second)
	store.skip = 1          // the lookup passes; the check after it is raced
	store.before = func() { // the revocation lands in the store, as another request's would
		if err := inner.DeleteToken(tok.ID); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := svc.TokenFromBearer("Bearer " + secret); err == nil || got != nil {
		t.Fatalf("a throttled request racing the revocation must be refused: %+v %v", got, err)
	}
	if list, _ := inner.ListTokens(); len(list) != 0 {
		t.Fatalf("the revocation must stand: %+v", list)
	}
}
