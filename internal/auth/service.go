// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jeremiahjrross/podaro/internal/fsx"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// Scopes (API §2.3), lowest to highest.
const (
	ScopeRead    = "read"
	ScopeOperate = "operate"
	ScopeAdmin   = "admin"
)

// Mechanisms recorded in the audit stream (API §2.5).
const (
	MechanismSocket  = "socket"
	MechanismSession = "session"
	MechanismToken   = "token"
)

// Session and token constants (API §2.2–§2.3).
const (
	CookieName   = "podaro_session"
	CSRFHeader   = "X-Podaro-CSRF"
	SessionIdle  = 12 * time.Hour
	TokenPrefix  = "pdr_"
	tokenIDBytes = 8
)

// Throttle policy (API §2.1): consecutive failures back off 1 s, 2 s,
// 4 s, 8 s; the fifth locks the source for 15 minutes.
const (
	LockoutAfter    = 5
	LockoutDuration = 15 * time.Minute
	backoffBase     = time.Second
	backoffMax      = 8 * time.Second
)

// Scopes lists the token scopes in rank order (API §2.3).
var Scopes = []string{ScopeRead, ScopeOperate, ScopeAdmin}

// ScopeInstance is the scope of an instance-bound session (API §2.4):
// below read — its own instance's resources and its own session, nothing
// else — and never a token's scope. The handlers enforce the resource
// half; the gateway enforces the hostname half.
const ScopeInstance = "instance"

// ScopeRank orders scopes: instance < read < operate < admin; unknown
// scopes rank below all.
func ScopeRank(scope string) int {
	if scope == ScopeInstance {
		return 1
	}
	for i, s := range Scopes {
		if s == scope {
			return i + 2
		}
	}
	return 0
}

// Allows reports whether scope `have` covers `need`.
func Allows(have, need string) bool { return ScopeRank(have) >= ScopeRank(need) }

// ValidScope reports whether s is one of the three token scopes.
func ValidScope(s string) bool {
	for _, v := range Scopes {
		if v == s {
			return true
		}
	}
	return false
}

// Throttled is the login refusal carrying its Retry-After.
type Throttled struct {
	Env        *pdr.Error
	RetryAfter time.Duration
}

func (t *Throttled) Error() string { return t.Env.Error() }

// Unwrap exposes the envelope to errors.As.
func (t *Throttled) Unwrap() error { return t.Env }

// Service is the identity layer over a Store and the operator file.
type Service struct {
	store state.Store
	path  string
	now   func() time.Time
	// Logf receives what the background sweep cannot return (an audit
	// record it could not write); nil discards.
	Logf func(format string, args ...any)

	mu       sync.Mutex
	cached   *Operator
	cachedAt time.Time
	touched  map[string]time.Time
	// opMu orders operator replacement against itself and against
	// logins: a reset holds its write side across write, audit, rename,
	// cache clear and purge; a login holds its read side from the moment
	// it loads the operator until its session and record are stored. A
	// login that began before a reset completes before it — and is
	// signed out by it — and none that begins after it sees the record
	// the reset replaced.
	opMu sync.RWMutex
	// afterOperatorLoad is a test seam: called by a login in the window
	// between loading the operator and verifying the password.
	afterOperatorLoad func()
}

// NewService builds the layer; operatorPath is auth.json.
func NewService(store state.Store, operatorPath string) *Service {
	return &Service{store: store, path: operatorPath, now: func() time.Time { return time.Now().UTC() }, touched: map[string]time.Time{}}
}

// SetClock overrides time (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Operator loads auth.json, caching by modification time so per-request
// cookie checks cost a stat, not a parse.
func (s *Service) Operator() (*Operator, error) {
	fi, err := os.Stat(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.mu.Lock()
			s.cached = nil
			s.mu.Unlock()
			return nil, ErrNoOperator
		}
		return nil, err
	}
	s.mu.Lock()
	if s.cached != nil && fi.ModTime().Equal(s.cachedAt) {
		op := s.cached
		s.mu.Unlock()
		return op, nil
	}
	s.mu.Unlock()
	op, err := LoadOperator(s.path)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.cached, s.cachedAt = op, fi.ModTime()
	s.mu.Unlock()
	return op, nil
}

// HasOperator reports whether auth setup has run.
func (s *Service) HasOperator() bool {
	_, err := s.Operator()
	return err == nil
}

// SetOperator creates the operator account (INSTALL §2 step 5) or, with
// replace, resets it (podaro auth reset): the session-signing key rotates
// and every session is dropped. Both are audited under the mechanism
// given (socket).
func (s *Service) SetOperator(username, password string, replace bool, mechanism string) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	// A record a replacement left behind (a crash between its write and
	// its audit) is removed first: under the lock no other is in flight.
	if stale, _ := filepath.Glob(s.path + ".*.tmp"); len(stale) > 0 {
		for _, f := range stale {
			_ = os.Remove(f)
		}
	}
	if err := CheckUsername(username); err != nil {
		return err
	}
	if err := CheckPassword(password); err != nil {
		return err
	}
	if _, err := s.Operator(); err == nil && !replace {
		e := pdr.New(pdr.CodeOperatorExists, "operator account already exists")
		e.Next = "podaro auth reset — replaces the account and signs every session out"
		return e
	} else if err != nil && !errors.Is(err, ErrNoOperator) {
		return err
	}
	op, err := NewOperator(username, password, s.now())
	if err != nil {
		return err
	}
	// The record is written beside the operator file, audited, and only
	// then moved into place: an act whose audit record cannot be written
	// does not happen (API §2.5).
	tmp, err := op.SaveTemp(s.path)
	if err != nil {
		return err
	}
	action := "operator-created"
	if replace {
		action = "operator-reset"
	}
	if err := s.Audit(state.Audit{Action: action, Actor: username, Mechanism: mechanism}); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := fsx.SyncDir(filepath.Dir(s.path)); err != nil { // the rename durable before the act is reported
		return err
	}
	s.mu.Lock()
	s.cached = nil
	s.mu.Unlock()
	if replace {
		if _, err := s.store.PurgeSessions(s.now().AddDate(1000, 0, 0)); err != nil {
			return err
		}
	}
	return nil
}

// Audit appends an event to the system (or instance) stream, stamping
// the time.
func (s *Service) Audit(a state.Audit) error {
	if a.At.IsZero() {
		a.At = s.now()
	}
	if err := s.store.AppendAudit(a); err != nil {
		return fmt.Errorf("audit %s: %w", a.Action, err)
	}
	return nil
}

// Login authenticates username/password from a source (a client
// address), enforcing the throttle and lockout, and returns a fresh
// session. Errors are PDR envelopes: E306 no operator, E302 throttled,
// E303 locked (both *Throttled with RetryAfter), E301 wrong credentials.
func (s *Service) Login(source, username, password string) (*state.Session, error) {
	s.opMu.RLock()
	defer s.opMu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	ls, err := s.store.GetLoginState(source)
	if err != nil {
		return nil, err
	}
	if ls == nil {
		ls = &state.LoginState{Source: source}
	}
	if ls.LockedUntil != nil {
		if now.Before(*ls.LockedUntil) {
			wait := ls.LockedUntil.Sub(now)
			e := pdr.New(pdr.CodeLoginLocked, "too many failed logins from %s", source)
			e.Cause = fmt.Sprintf("%d consecutive failures locked the source out for %s", LockoutAfter, LockoutDuration)
			e.Next = fmt.Sprintf("wait %s and try again", ceilSeconds(wait))
			return nil, &Throttled{Env: e, RetryAfter: wait}
		}
		if err := s.releaseLocked(ls, now); err != nil {
			return nil, err
		}
	} else if ls.Failures > 0 {
		wait := backoff(ls.Failures)
		if until := ls.LastFailure.Add(wait); now.Before(until) {
			left := until.Sub(now)
			e := pdr.New(pdr.CodeLoginThrottled, "login throttled after %d failed attempt(s) from %s", ls.Failures, source)
			e.Cause = fmt.Sprintf("backoff of %s since the last failure", wait)
			e.Next = fmt.Sprintf("wait %s and try again", ceilSeconds(left))
			return nil, &Throttled{Env: e, RetryAfter: left}
		}
	}
	op, err := s.operatorLocked()
	if errors.Is(err, ErrNoOperator) {
		e := pdr.New(pdr.CodeNoOperator, "no operator account exists yet")
		e.Next = "podaro auth setup"
		return nil, e
	}
	if err != nil {
		return nil, err
	}
	// Verify unconditionally so a wrong username costs the same as a
	// wrong password.
	ok := op.Verify(password) && subtle.ConstantTimeCompare([]byte(username), []byte(op.Username)) == 1
	if !ok {
		// The count — and the lockout — land with their records as one
		// write (API §2.5): a stream that refuses counts nothing, and no
		// crash between the two can leave a throttle the audit does not
		// know about, since there is no between.
		ls.Failures++
		ls.LastFailure = now
		detail := fmt.Sprintf("failure %d", ls.Failures)
		if ls.Failures >= LockoutAfter {
			until := now.Add(LockoutDuration)
			ls.LockedUntil = &until
			detail += fmt.Sprintf(" · locked until %s", until.Format(time.RFC3339))
		}
		records := []state.Audit{{At: now, Action: "login-failed", Actor: username, Mechanism: MechanismSession, Detail: source + " · " + detail}}
		if ls.LockedUntil != nil {
			records = append(records, state.Audit{At: now, Action: "lockout", Actor: username, Mechanism: MechanismSession, Detail: fmt.Sprintf("%s · %d failures · %s", source, ls.Failures, LockoutDuration)})
		}
		// A failure the audit stream cannot hold is reported as the store's
		// fault, not as the wrong password: the caller must know the
		// record is incomplete (API §2.5).
		if err := s.store.PutLoginStateAudited(*ls, records...); err != nil {
			return nil, fmt.Errorf("audit login-failed: %w", err)
		}
		e := pdr.New(pdr.CodeLoginFailed, "username or password is wrong")
		e.Next = "check the credentials; podaro auth reset at the socket replaces a lost password"
		return nil, e
	}
	if ls.Failures > 0 {
		if err := s.store.PutLoginState(state.LoginState{Source: source}); err != nil {
			return nil, err
		}
	}
	// The session and its login record are one write (API §2.5): no
	// session exists that the stream does not know about — not for a
	// refused record, and not for a crash between the two, since there
	// is no between.
	return s.newSession(op.Username, MechanismSession, "", now, state.Audit{At: now, Action: "login", Actor: op.Username, Mechanism: MechanismSession, Detail: source})
}

func (s *Service) operatorLocked() (*Operator, error) {
	// Operator() takes s.mu itself; release around it.
	s.mu.Unlock()
	defer s.mu.Lock()
	op, err := s.Operator()
	if s.afterOperatorLoad != nil {
		s.afterOperatorLoad()
	}
	return op, err
}

func (s *Service) releaseLocked(ls *state.LoginState, now time.Time) error {
	// The release and its record are one write: a lockout stands until
	// the stream holds its release.
	cleared := state.LoginState{Source: ls.Source}
	if err := s.store.PutLoginStateAudited(cleared, state.Audit{Action: "lockout-released", Mechanism: MechanismSession, Detail: ls.Source, At: now}); err != nil {
		return fmt.Errorf("audit lockout-released: %w", err)
	}
	*ls = cleared
	return nil
}

func backoff(failures int) time.Duration {
	d := backoffBase << (failures - 1)
	if d > backoffMax || d <= 0 {
		return backoffMax
	}
	return d
}

func ceilSeconds(d time.Duration) string {
	secs := int((d + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	return fmt.Sprintf("%ds", secs)
}

// RetryAfterSeconds renders a Retry-After value, rounded up.
func RetryAfterSeconds(d time.Duration) int {
	secs := int((d + time.Second - 1) / time.Second)
	if secs < 1 {
		return 1
	}
	return secs
}

func (s *Service) newSession(subject, mechanism, instance string, now time.Time, record state.Audit) (*state.Session, error) {
	id, err := randomBytes(24)
	if err != nil {
		return nil, err
	}
	csrf, err := randomBytes(24)
	if err != nil {
		return nil, err
	}
	sess := &state.Session{
		ID: hex.EncodeToString(id), Subject: subject, Mechanism: mechanism, Instance: instance,
		CSRF: base64.RawURLEncoding.EncodeToString(csrf), Created: now, LastSeen: now, Expires: now.Add(SessionIdle),
	}
	if err := s.store.PutSessionAudited(*sess, record); err != nil {
		return nil, fmt.Errorf("audit %s: %w", record.Action, err)
	}
	// A fresh record needs no slide for a minute: the cookie issued with
	// it already carries the full idle window.
	s.touched[sess.ID] = now
	return sess, nil
}

// CookieValue signs the session id into the cookie value: `<id>.<hmac>`.
func (s *Service) CookieValue(sess *state.Session) (string, error) {
	op, err := s.Operator()
	if err != nil {
		return "", err
	}
	return sess.ID + "." + sign(op.SessionKey(), sess.ID), nil
}

func sign(key []byte, id string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(id))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// SessionFromCookie verifies the cookie's signature, loads the record,
// enforces the idle expiry, and slides it (touching the store at most
// once a minute per session). Any failure is ErrNoSession.
func (s *Service) SessionFromCookie(value string) (*state.Session, error) {
	sess, _, err := s.Resolve(value)
	return sess, err
}

// Resolve is SessionFromCookie reporting whether this call slid the idle
// expiry — the moment the cookie itself must be re-issued with a fresh
// Max-Age, so the browser's copy expires with the record and not twelve
// hours after the login (API §2.2: the expiry slides on use).
func (s *Service) Resolve(value string) (sess *state.Session, slid bool, err error) {
	sess, now, err := s.verify(value)
	if err != nil {
		return nil, false, err
	}
	id := sess.ID
	s.mu.Lock()
	defer s.mu.Unlock()
	last, seen := s.touched[id]
	if !seen || now.Sub(last) >= time.Minute {
		// A slide is reported only once the record holds it: a refused
		// write leaves the record, the cookie and the touch cache as they
		// were, and the next request tries again — never a browser cookie
		// that outlives the expiry the store still enforces. The record is
		// moved in place, never written back whole: a sign-out that landed
		// between the read and this write has removed it, and the request
		// racing the sign-out is refused rather than bringing back the
		// session it read.
		expires := now.Add(SessionIdle)
		switch err := s.store.TouchSession(id, now, expires); {
		case err == nil:
			s.touched[id] = now
			sess.LastSeen, sess.Expires = now, expires
			slid = true
		case errors.Is(err, state.ErrNotFound):
			delete(s.touched, id)
			return nil, false, ErrNoSession
		}
	} else if _, err := s.store.GetSession(id); errors.Is(err, state.ErrNotFound) {
		// The mark is what catches a sign-out or a reset that landed since
		// the cookie was verified, and inside the touch's minute there is
		// no mark: the throttled path asks the store instead of writing to
		// it, so a session that is gone is never authenticated by a
		// request that happens to arrive soon after the last one. Any
		// other fault is left for the next request, as a refused mark is.
		delete(s.touched, id)
		return nil, false, ErrNoSession
	}
	return sess, slid, nil
}

// Peek is Resolve without the slide: the session a cookie names, valid
// now, with nothing touched — for checks that must not count as use.
func (s *Service) Peek(value string) (*state.Session, error) {
	sess, _, err := s.verify(value)
	return sess, err
}

// verify checks the cookie's signature, loads the record and enforces
// the idle expiry (an expired record is removed). Any failure is
// ErrNoSession.
func (s *Service) verify(value string) (*state.Session, time.Time, error) {
	id, sig, ok := strings.Cut(value, ".")
	if !ok || id == "" {
		return nil, time.Time{}, ErrNoSession
	}
	op, err := s.Operator()
	if err != nil {
		return nil, time.Time{}, ErrNoSession
	}
	if subtle.ConstantTimeCompare([]byte(sig), []byte(sign(op.SessionKey(), id))) != 1 {
		return nil, time.Time{}, ErrNoSession
	}
	sess, err := s.store.GetSession(id)
	if err != nil {
		return nil, time.Time{}, ErrNoSession
	}
	now := s.now()
	if !now.Before(sess.Expires) {
		_ = s.store.DeleteSession(id)
		return nil, time.Time{}, ErrNoSession
	}
	return sess, now, nil
}

// IsPodaroBearer reports whether an Authorization header carries a Podaro
// token (`Bearer pdr_…`) — the gateway's own credential, as opposed to a
// product's own scheme riding through the proxy.
func IsPodaroBearer(header string) bool {
	scheme, value, ok := strings.Cut(strings.TrimSpace(header), " ")
	return ok && strings.EqualFold(scheme, "Bearer") && strings.HasPrefix(strings.TrimSpace(value), TokenPrefix)
}

// ErrNoSession reports an absent, forged, or expired session.
var ErrNoSession = errors.New("no session")

// Logout audits the sign-out, then deletes the session: a sign-out the
// stream cannot record does not happen, and the caller says so (API
// §2.5).
func (s *Service) Logout(sess *state.Session) error {
	record := state.Audit{At: s.now(), Action: "logout", Actor: sess.Subject, Mechanism: sess.Mechanism}
	if err := s.store.DeleteSessionAudited(sess.ID, record); err != nil {
		return fmt.Errorf("audit logout: %w", err)
	}
	s.mu.Lock()
	delete(s.touched, sess.ID)
	s.mu.Unlock()
	return nil
}

// CreateToken issues a bearer token (API §2.3) and returns the secret
// once; only its hash is stored. Errors: E308 name exists, E307 for a
// bad name or scope.
func (s *Service) CreateToken(name, scope, actor, mechanism string) (secret string, tok *state.Token, err error) {
	secret, err = NewTokenSecret()
	if err != nil {
		return "", nil, err
	}
	tok, err = s.CreateTokenWithSecret(name, scope, secret, actor, mechanism)
	if err != nil {
		return "", nil, err
	}
	return secret, tok, nil
}

// NewTokenSecret makes a token secret: the prefix and 32 random bytes,
// base64url — what CreateToken issues, and what a caller that keeps the
// secret itself (the CLI's file-backed flow, API §2.3) makes before
// asking for the token.
func NewTokenSecret() (string, error) {
	raw, err := randomBytes(32)
	if err != nil {
		return "", err
	}
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// SecretPrefix is the part of a secret a listing shows (API §2.3): the
// eight characters after the prefix — what a holder compares to tell a
// listed token's secret from another.
func SecretPrefix(secret string) string {
	rest := strings.TrimPrefix(secret, TokenPrefix)
	if len(rest) < 8 {
		return rest
	}
	return rest[:8]
}

// WellFormedSecret reports whether a secret has the shape NewTokenSecret
// makes: the prefix and exactly 32 bytes of base64url.
func WellFormedSecret(secret string) bool {
	rest, ok := strings.CutPrefix(secret, TokenPrefix)
	if !ok {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	return err == nil && len(raw) == 32
}

// CreateTokenWithSecret issues a token for a secret the caller made and
// already holds — the CLI's file-backed flow, where the secret is on
// disk before the token exists (API §2.3) — so only its hash is ever
// stored. The secret must have NewTokenSecret's shape (E307 otherwise).
func (s *Service) CreateTokenWithSecret(name, scope, secret, actor, mechanism string) (*state.Token, error) {
	if err := CheckUsername(name); err != nil {
		e := pdr.New(pdr.CodePasswordPolicy, "token name %q: lowercase letters, digits, '-', '.', '_' only, 1–32 characters", name)
		e.Next = "podaro auth token create --name ci --scope read"
		return nil, e
	}
	if !ValidScope(scope) {
		e := pdr.New(pdr.CodePasswordPolicy, "scope %q is not one of read · operate · admin", scope)
		e.Next = "--scope read | operate | admin (API §2.3)"
		return nil, e
	}
	if !WellFormedSecret(secret) {
		e := pdr.New(pdr.CodePasswordPolicy, "malformed token secret: the prefix %s and 32 bytes of base64url", TokenPrefix)
		e.Next = "omit the secret and the engine makes one"
		return nil, e
	}
	idb, err := randomBytes(tokenIDBytes)
	if err != nil {
		return nil, err
	}
	now := s.now()
	tok := &state.Token{ID: "tok_" + hex.EncodeToString(idb), Name: name, Prefix: SecretPrefix(secret), Hash: hashToken(secret), Scope: scope, Created: now}
	// The token and its record are one write (API §2.5): no credential
	// exists that the audit does not know about — not for a refused
	// record, and not for a crash between the two, since there is no
	// between.
	record := state.Audit{At: now, Action: "token-created", Actor: actor, Mechanism: mechanism, Detail: name + " · " + scope}
	if err := s.store.PutTokenAudited(*tok, record); err != nil {
		if errors.Is(err, state.ErrConflict) {
			e := pdr.New(pdr.CodeTokenExists, "a token named %q already exists", name)
			e.Next = "podaro auth token revoke " + name + " · or choose another name"
			return nil, e
		}
		return nil, fmt.Errorf("record token %s: %w", name, err)
	}
	return tok, nil
}

func hashToken(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// TokenFromBearer resolves an Authorization value to its token and
// records last use.
func (s *Service) TokenFromBearer(header string) (*state.Token, error) {
	scheme, value, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return nil, ErrNoSession
	}
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, TokenPrefix) {
		return nil, ErrNoSession
	}
	tok, err := s.store.GetTokenByHash(hashToken(value))
	if err != nil {
		return nil, ErrNoSession
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	last, seen := s.touched[tok.ID]
	if !seen || now.Sub(last) >= time.Minute {
		// The mark is an update of the existing row, never a write-back of
		// the token: a revocation that landed between the lookup and this
		// write stays a revocation, and the request racing it is refused.
		// Any other fault leaves the mark for the next request.
		switch err := s.store.TouchToken(tok.ID, now); {
		case err == nil:
			s.touched[tok.ID] = now
			tok.LastUsed = &now
		case errors.Is(err, state.ErrNotFound):
			delete(s.touched, tok.ID)
			return nil, ErrNoSession
		}
	} else if _, err := s.store.GetTokenByHash(hashToken(value)); errors.Is(err, state.ErrNotFound) {
		// Same on the throttled path: the mark is the only check that a
		// revocation has not landed since the lookup, so without it the
		// token is looked up once more rather than trusted for a minute.
		delete(s.touched, tok.ID)
		return nil, ErrNoSession
	}
	return tok, nil
}

// ListTokens lists tokens (never secrets).
func (s *Service) ListTokens() ([]state.Token, error) {
	list, err := s.store.ListTokens()
	if list == nil {
		list = []state.Token{}
	}
	return list, err
}

// RevokeToken deletes a token by name or id; E309 when absent.
func (s *Service) RevokeToken(nameOrID, actor, mechanism string) error {
	list, err := s.store.ListTokens()
	if err != nil {
		return err
	}
	for _, t := range list {
		if t.ID == nameOrID || t.Name == nameOrID {
			// The token and its token-revoked record go as one write (API
			// §2.5): a revocation the stream cannot record does not happen
			// — the token stands, still valid, and the caller sees the
			// fault — and a crash between the two cannot leave a revoked
			// credential nobody can account for, since there is no
			// between.
			record := state.Audit{At: s.now(), Action: "token-revoked", Actor: actor, Mechanism: mechanism, Detail: t.Name}
			if err := s.store.DeleteTokenAudited(t.ID, record); err != nil {
				return fmt.Errorf("revoke token %s: %w", t.Name, err)
			}
			s.mu.Lock()
			delete(s.touched, t.ID)
			s.mu.Unlock()
			return nil
		}
	}
	e := pdr.New(pdr.CodeTokenNotFound, "no token named %q", nameOrID)
	e.Next = "podaro auth token list"
	return e
}

// Sweep releases expired lockouts (audited) and purges expired sessions.
// The engine runs it periodically; tests call it directly.
func (s *Service) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if locked, err := s.store.ListLockedSources(); err == nil {
		for i := range locked {
			if ls := locked[i]; ls.LockedUntil != nil && !now.Before(*ls.LockedUntil) {
				if err := s.releaseLocked(&ls, now); err != nil && s.Logf != nil {
					// Left locked: the next attempt from the source releases
					// it lazily, audited then (Login).
					s.Logf("auth: lockout of %s not released: %v", ls.Source, err)
				}
			}
		}
	}
	_, _ = s.store.PurgeSessions(now)
	for id, t := range s.touched {
		if now.Sub(t) > SessionIdle {
			delete(s.touched, id)
		}
	}
}

// Run sweeps every interval until ctx ends.
func (s *Service) Run(stop <-chan struct{}, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.Sweep()
		}
	}
}

// RandomID returns n random bytes as hex (join tokens and the like).
func RandomID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
