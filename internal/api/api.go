// SPDX-License-Identifier: AGPL-3.0-only

// Package api is the engine's HTTP API (API §1: one API, three doors).
// One mux serves every door; the doors differ only in how the caller is
// identified: the local socket door trusts the operating-system user
// (full operator rights), the network door (plan S5) resolves a session
// cookie or a bearer token and denies until authenticated. Every handler
// answers JSON, and the ones the console reads answer server-rendered
// fragments to `Accept: text/html` from the same code path (ADR-0003).
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/console"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/legal"
	"github.com/jeremiahjrross/podaro/internal/observe"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
	"github.com/jeremiahjrross/podaro/internal/sysinfo"
)

// Prefix is the versioned path root.
const Prefix = "/api/v1alpha1"

// Options wire the server.
type Options struct {
	Engine *engine.Engine
	// System renders GET /system.
	System func() sysinfo.Info
	// Auth is the identity layer; required for the network door.
	Auth    *auth.Service
	Console *console.Renderer
	// Address reports the gateway domain and port ("" before setup).
	Address func() (domain string, port int)
	// Reload is POST /system/reload (socket only): re-read configuration
	// and (re)open the gateway.
	Reload func(ctx context.Context) (sysinfo.Gateway, error)
	// Observe is the observability export; nil when the operator
	// configured none, which every method on it handles.
	Observe *observe.Exporter
	// Legal is GET /system/legal's value (internal/legal): built from the
	// binary and the operator's legal.source_url, static between reloads.
	// Nil builds it from the binary alone, once.
	Legal func() legal.Info
}

// Server routes the API.
type Server struct {
	o   Options
	mux *http.ServeMux
	// tokenMu orders token listings after token creations in flight: a
	// client reconciling an answer lost on the socket (API §2.3) reads
	// the outcome of the creation it lost, never the moment before it.
	tokenMu sync.RWMutex
	// public is the per-source allowance of the public routes (legal.go).
	public *publicLimiter
}

// Principal is the authenticated caller.
type Principal struct {
	Mechanism string
	Subject   string
	Scope     string
	Session   *state.Session
	Token     *state.Token
	// refresh is the cookie value to re-issue when this request slid the
	// session's idle expiry (API §2.2): the browser's copy must expire
	// with the record, not twelve hours after the login.
	refresh string
}

// Allows reports whether the principal's scope covers the requirement.
func (p *Principal) Allows(scope string) bool { return p != nil && auth.Allows(p.Scope, scope) }

// Whoami renders the principal as GET /auth/session's body.
func (p *Principal) Whoami() auth.Whoami {
	w := auth.Whoami{Subject: p.Subject, Mechanism: p.Mechanism, Scope: p.Scope}
	if p.Session != nil {
		exp := p.Session.Expires
		w.Expires = &exp
		w.CSRF = p.Session.CSRF
		w.Instance = p.Session.Instance
	}
	return w
}

type ctxKey struct{}

// PrincipalFrom returns the request's principal, or nil.
func PrincipalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}

// WithPrincipal attaches a principal (the doors use it).
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// New builds the handler set.
func New(o Options) *Server {
	if o.Console == nil {
		o.Console = console.Must()
	}
	if o.Address == nil {
		o.Address = func() (string, int) { return "", 0 }
	}
	if o.System == nil {
		o.System = func() sysinfo.Info { return sysinfo.Info{} }
	}
	if o.Legal == nil {
		// The binary's own summary, with no operator statement; a binary
		// whose embedded notices do not parse is refused by the tests
		// (internal/legal) before one is ever built.
		info, _ := legal.Build("")
		o.Legal = func() legal.Info { return info }
	}
	s := &Server{o: o, mux: http.NewServeMux(), public: newPublicLimiter()}
	// Routes at the instance scope are the reads API §2.4's fixed grant
	// lists; each enforces the resource half of the grant itself
	// (boundTo). The grant's three *writes* keep their token minimum and
	// admit an instance-bound session by name — see `granted` in this
	// file. The door such a session comes through is `accessRoutes`: the
	// `pdi_` token, `/join`, expiry and revocation, walked end to end by
	// hack/attendee_matrix.sh (plan S9).
	s.handle("GET /healthz", auth.ScopeInstance, s.healthz)
	s.handle("GET /system", auth.ScopeRead, s.getSystem)
	s.handle("GET /system/errors/{code}", auth.ScopeRead, s.getErrorHelp)
	// The one /api route that needs no credential (legal.go): the licence,
	// the notices and the source offer, for anyone who can reach the
	// gateway — rate-limited per source, static, stateless.
	s.open("GET /system/legal", s.getLegal)
	s.socketOnly("POST /system/reload", s.reload)
	s.socketOnly("GET /system/audit", s.audit)
	s.observeRoutes()
	s.logRoutes()
	s.open("POST /auth/session", s.login)
	s.handle("GET /auth/session", auth.ScopeInstance, s.whoami)
	s.handle("DELETE /auth/session", auth.ScopeInstance, s.logout)
	s.socketOnly("POST /auth/operator", s.setOperator)
	s.handle("GET /auth/tokens", auth.ScopeAdmin, s.listTokens)
	s.handle("POST /auth/tokens", auth.ScopeAdmin, s.createToken)
	s.handle("DELETE /auth/tokens/{id}", auth.ScopeAdmin, s.deleteToken)
	s.handle("GET /instances", auth.ScopeInstance, s.listInstances)
	s.handle("POST /instances", auth.ScopeAdmin, s.createInstance)
	s.handle("GET /instances/{name}", auth.ScopeInstance, s.getInstance)
	s.handle("DELETE /instances/{name}", auth.ScopeAdmin, s.deleteInstance)
	s.handle("GET /jobs/{id}", auth.ScopeInstance, s.getJob)
	s.labRoutes()    // seeds, verify, reset, checkpoints, playbooks, secrets, evidence (plan S6)
	s.accessRoutes() // instance access and the join exchange (API §2.4, plan S9)
	return s
}

// handle registers a route needing a principal with at least scope.
func (s *Server) handle(pattern, scope string, h http.HandlerFunc) {
	s.route(pattern, scope, false, h)
}

// granted registers a route that §2.4's fixed attendee grant includes:
// the minimum *token* scope stays what §11's index says, and an
// instance-bound session is admitted as well.
//
// The grant is a set, not a rank. `instance` ranks below `read` because
// that is what it is for a token — its own instance's resources and
// nothing else — but §2.4 lists writes in it (step seeds, attest, the
// learner's position) that sit above `read` on the ladder, and §11's
// legend has always said a session qualifies. Ranking alone therefore
// refused an attendee exactly the three writes the grant promises them,
// so both shipped playbooks stopped at their first actionable step.
//
// Lowering the routes to `instance` instead would have handed a
// *read-scoped token* the right to seed, attest and rewrite progress.
// The rank is left alone and the session is admitted by name.
//
// The resource half is unchanged and is still the handler's: `scoped`
// answers not-found for any instance but the session's own, so this
// admits an attendee to their own lab and to nothing else. What the
// grant excludes — reset, destroy, logs, other instances, the auth and
// authoring surfaces — is registered with `handle` and refuses them as
// it did before.
func (s *Server) granted(pattern, scope string, h http.HandlerFunc) {
	s.route(pattern, scope, true, h)
}

func (s *Server) route(pattern, scope string, attendee bool, h http.HandlerFunc) {
	method, path, _ := strings.Cut(pattern, " ")
	s.mux.HandleFunc(method+" "+Prefix+path, func(w http.ResponseWriter, r *http.Request) {
		p := PrincipalFrom(r.Context())
		if p == nil {
			s.writeError(w, r, unauthenticated())
			return
		}
		if !p.Allows(scope) && !(attendee && p.Scope == auth.ScopeInstance) {
			e := pdr.New(pdr.CodeScopeInsufficient, "this endpoint requires the %s scope", scope)
			e.Cause = "the " + p.Mechanism + " credential carries " + p.Scope
			e.Next = "podaro auth token create --name <name> --scope " + scope
			e.Details = []pdr.Detail{{Path: "required_scope", Hint: scope}}
			s.writeError(w, r, e)
			return
		}
		h(w, r)
	})
}

// open registers a route that needs no principal (login).
func (s *Server) open(pattern string, h http.HandlerFunc) {
	method, path, _ := strings.Cut(pattern, " ")
	s.mux.HandleFunc(method+" "+Prefix+path, h)
}

// socketOnly registers a route that exists only on the local socket
// door; on the network it is structurally absent (a plain 404).
func (s *Server) socketOnly(pattern string, h http.HandlerFunc) {
	method, path, _ := strings.Cut(pattern, " ")
	s.mux.HandleFunc(method+" "+Prefix+path, func(w http.ResponseWriter, r *http.Request) {
		if p := PrincipalFrom(r.Context()); p == nil || p.Mechanism != auth.MechanismSocket {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	})
}

// ServeHTTP serves the raw mux (tests inject a principal themselves).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// SocketHandler is the local door: possession of the socket is the
// credential, with full operator rights.
func (s *Server) SocketHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &Principal{Mechanism: auth.MechanismSocket, Subject: "operator", Scope: auth.ScopeAdmin}
		s.mux.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

// NetworkHandler is the gateway door: cookie or bearer, deny until
// authenticated, CSRF on cookie-authenticated writes (API §2.2).
func (s *Server) NetworkHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := s.Authenticate(r)
		s.RefreshCookie(w, p)
		login := r.Method == http.MethodPost && r.URL.Path == Prefix+"/auth/session"
		if p != nil && p.Mechanism == auth.MechanismSession && !safeMethod(r.Method) && !login {
			if r.Header.Get(auth.CSRFHeader) != p.Session.CSRF {
				e := pdr.New(pdr.CodeCSRF, "cookie-authenticated writes must carry %s", auth.CSRFHeader)
				e.Next = "GET " + Prefix + "/auth/session and echo its csrf value in the header"
				s.writeError(w, r, e)
				return
			}
		}
		s.mux.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

// Authenticate resolves a bearer token or session cookie to a principal;
// nil when the request carries neither, or a bad one.
func (s *Server) Authenticate(r *http.Request) *Principal {
	if s.o.Auth == nil {
		return nil
	}
	// Only a Podaro bearer is the gateway's credential; any other
	// Authorization scheme belongs to a product behind the proxy and is
	// neither judged here nor a reason to ignore the session cookie.
	if h := r.Header.Get("Authorization"); auth.IsPodaroBearer(h) {
		tok, err := s.o.Auth.TokenFromBearer(h)
		if err != nil {
			return nil
		}
		return &Principal{Mechanism: auth.MechanismToken, Subject: tok.Name, Scope: tok.Scope, Token: tok}
	}
	if c, err := r.Cookie(auth.CookieName); err == nil {
		sess, slid, err := s.o.Auth.Resolve(c.Value)
		if err != nil {
			return nil
		}
		// The operator's session acts as the operator (admin). An
		// instance-bound session is never the operator: it carries the
		// instance scope — below read: its own instance's resources and
		// nothing else (API §2.4, threat model D4), enforced by resource in
		// the handlers (boundTo) and by hostname at the gateway. The grant
		// itself is a set rather than a rank, so the writes it lists are
		// registered with `granted`; plan S9 brings the door such a session
		// comes through.
		scope := auth.ScopeAdmin
		if sess.Instance != "" {
			scope = auth.ScopeInstance
		}
		p := &Principal{Mechanism: auth.MechanismSession, Subject: sess.Subject, Scope: scope, Session: sess}
		if slid {
			p.refresh = c.Value
		}
		return p
	}
	return nil
}

// boundTo names the one instance an instance-bound session (API §2.4)
// may see; "" for every other principal. The grant is enforced by
// resource here, not by hostname alone: the bound instance is the only
// one its listing shows and the only one its reads answer for — anything
// else is not found, exactly as an instance that does not exist.
func boundTo(r *http.Request) string {
	if p := PrincipalFrom(r.Context()); p != nil && p.Session != nil {
		return p.Session.Instance
	}
	return ""
}

// isNotFound reports the engine's not-found envelope, which for a bound
// bearer is also the answer for a lab that is no longer its generation.
func isNotFound(err error) bool {
	var pe *pdr.Error
	return errors.As(err, &pe) && pe.Code == pdr.CodeInstanceNotFound
}

// notFound is the engine's own not-found envelope, so a resource outside
// a bound session's grant is indistinguishable from one that is absent.
func notFound(kind, id string) *pdr.Error {
	pe := pdr.New(pdr.CodeInstanceNotFound, "no such %s %q", kind, id)
	pe.Next = "podaro status"
	return pe
}

// actorOf names the caller for the audit stream: the principal's subject
// and mechanism on the network door, the socket on the local one.
func actorOf(r *http.Request) engine.Actor {
	if p := PrincipalFrom(r.Context()); p != nil {
		return p.Actor()
	}
	return engine.Socket
}

// Actor is who the engine is asked as, for this principal. An attendee
// is entitled to one generation of one lab, and the engine compares it
// inside its own resolution; an operator carries no generation and is
// bound to none.
//
// It is a method rather than a function of the request because the
// gateway authenticates without a request context of ours: its
// server-rendered lab page asked the engine as `engine.Socket` and so
// painted whatever lab held the name, which is the one read on the
// attendee's path that never had the comparison.
func (p *Principal) Actor() engine.Actor {
	if p == nil {
		return engine.Socket
	}
	a := engine.Actor{Subject: p.Subject, Mechanism: p.Mechanism}
	if p.Session != nil && p.Session.Instance != "" {
		gen := p.Session.Gen
		a.Gen = &gen
	}
	return a
}

// PeekSession resolves a cookie-authenticated request's session without
// sliding it: for checks that must not count as use — the gateway's
// hostname binding — so that Authenticate remains the one place that
// slides the record and re-issues the cookie (API §2.2).
func (s *Server) PeekSession(r *http.Request) *state.Session {
	if s.o.Auth == nil {
		return nil
	}
	// The precedence is Authenticate's: a Podaro bearer is the request's
	// credential and the cookie beside it is not judged — so a valid
	// token is never refused for a bound cookie the client also holds.
	if auth.IsPodaroBearer(r.Header.Get("Authorization")) {
		return nil
	}
	c, err := r.Cookie(auth.CookieName)
	if err != nil {
		return nil
	}
	sess, err := s.o.Auth.Peek(c.Value)
	if err != nil {
		return nil
	}
	return sess
}

// RefreshCookie re-issues the session cookie with a fresh Max-Age when
// the request slid the session (API §2.2): without it a continuously
// active user would be signed out twelve hours after the login, the
// record alive and the browser's cookie gone. Nothing happens for other
// principals or when the expiry did not move.
func (s *Server) RefreshCookie(w http.ResponseWriter, p *Principal) {
	if p == nil || p.refresh == "" {
		return
	}
	http.SetCookie(w, s.sessionCookie(p.refresh, int(auth.SessionIdle/time.Second)))
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

func unauthenticated() *pdr.Error {
	e := pdr.New(pdr.CodeUnauthenticated, "credentials required")
	e.Cause = "no valid session cookie or bearer token accompanied the request"
	e.Next = "sign in at the console, or send Authorization: Bearer pdr_… (podaro auth token create)"
	return e
}

// --- system -----------------------------------------------------------

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// getErrorHelp expands a PDR code from the embedded registry (API §5,
// plan S9) — the same answer `podaro explain` prints, for the clients
// that are not the CLI. It reads no state and touches no instance, so it
// answers while the engine is otherwise unwell, which is when an
// explanation is worth most.
func (s *Server) getErrorHelp(w http.ResponseWriter, r *http.Request) {
	code := pdr.NormalizeCode(r.PathValue("code"))
	entry, ok := pdr.Lookup(code)
	if !ok {
		e := pdr.New(pdr.CodeExplainUnknown, "no such error code: %s", r.PathValue("code"))
		e.Cause = "this release's registry does not hold that code"
		// Not a listing route: this server registers
		// `GET /system/errors/{code}` and nothing at `/system/errors`,
		// so the old advice answered the client with a second 404. The
		// CLI's `--list` is where the whole registry actually lives.
		e.Next = "podaro explain --list — or GET /system/errors/{code} with a code this release knows"
		s.writeError(w, r, e)
		return
	}
	// JSON only: the console has no page that asks for one code's help,
	// and a fragment may render only what its JSON twin contains (ADR
	// 0003) — an HTML twin arrives with the surface that needs it.
	s.respond(w, r, http.StatusOK, map[string]any{"error_help": entry}, "", nil)
}

func (s *Server) getSystem(w http.ResponseWriter, r *http.Request) {
	info := s.o.System()
	s.respond(w, r, http.StatusOK, info, console.FragmentSystem, info)
}

func (s *Server) reload(w http.ResponseWriter, r *http.Request) {
	if s.o.Reload == nil {
		writeJSON(w, http.StatusOK, map[string]any{"gateway": sysinfo.Gateway{}})
		return
	}
	gw, err := s.o.Reload(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"gateway": gw})
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	list, err := s.o.Engine.Audit(r.URL.Query().Get("instance"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": list})
}

// --- auth -------------------------------------------------------------

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Next     string `json:"next,omitempty"`
}

func (s *Server) readCredentials(w http.ResponseWriter, r *http.Request) (credentials, bool) {
	var c credentials
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	switch ct {
	case "application/json":
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			e := pdr.New(pdr.CodeLoginFailed, "malformed login body: %v", err)
			e.Next = `POST {"username","password"}`
			s.writeError(w, r, e)
			return c, false
		}
	default:
		if err := r.ParseForm(); err != nil {
			e := pdr.New(pdr.CodeLoginFailed, "malformed login form: %v", err)
			s.writeError(w, r, e)
			return c, false
		}
		c.Username, c.Password, c.Next = r.PostForm.Get("username"), r.PostForm.Get("password"), r.PostForm.Get("next")
	}
	return c, true
}

// login is POST /auth/session: throttled, audited, sets the domain cookie.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.o.Auth == nil {
		s.writeError(w, r, pdr.New(pdr.CodeNoOperator, "authentication is not configured on this door"))
		return
	}
	c, ok := s.readCredentials(w, r)
	if !ok {
		return
	}
	sess, err := s.o.Auth.Login(clientSource(r), c.Username, c.Password)
	if err != nil {
		if wantsHTML(r) && r.Header.Get("HX-Request") == "" {
			// A plain form post: re-render the login page around the error
			// — a store or operator-file fault included, wrapped as the
			// JSON path wraps it, never dereferenced as an envelope it is not.
			var pe *pdr.Error
			if !errors.As(err, &pe) {
				pe = pdr.New(pdr.CodeRuntimeFailed, "%s", err.Error())
			}
			s.setRetryAfter(w, err)
			body, _ := s.o.Console.Fragment(console.FragmentLogin, console.LoginData{Username: c.Username, Next: s.safeNext(c.Next), Error: pe})
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(Status(pe.Code))
			_ = s.o.Console.Page(w, console.ShellData{Title: console.PageTitle("Sign in"), Version: podaro.Version(), HomeURL: s.homeURL(), Body: body})
			return
		}
		s.writeError(w, r, err)
		return
	}
	value, err := s.o.Auth.CookieValue(sess)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	http.SetCookie(w, s.sessionCookie(value, int(auth.SessionIdle/time.Second)))
	target := s.safeNext(c.Next)
	if target == "" {
		target = "/"
	}
	if wantsHTML(r) {
		if r.Header.Get("HX-Request") != "" {
			w.Header().Set("HX-Redirect", target)
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}
	p := &Principal{Mechanism: auth.MechanismSession, Subject: sess.Subject, Scope: auth.ScopeAdmin, Session: sess}
	writeJSON(w, http.StatusOK, map[string]any{"session": p.Whoami()})
}

// SafeNext keeps post-login redirects inside the gateway's domain: a
// site-relative path, or an https URL under the domain on the gateway
// port; anything else becomes "".
func (s *Server) SafeNext(next string) string { return s.safeNext(next) }

func (s *Server) safeNext(next string) string {
	if next == "" {
		return ""
	}
	// Browsers read a backslash as a slash in https URLs and drop tabs
	// and newlines before parsing, so `/\evil.example` and `/\t/evil.example`
	// are `//evil.example` — a network-path reference to another host —
	// while this check sees a site-relative path. Neither character has
	// a place in a target: either refuses it.
	if strings.Contains(next, "\\") || strings.ContainsFunc(next, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return ""
	}
	if strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") {
		return next
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "https" {
		return ""
	}
	domain, port := s.o.Address()
	if domain == "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host != domain && !strings.HasSuffix(host, "."+domain) {
		return ""
	}
	// The effective port is compared, not the written one: an absolute
	// URL that omits it sends the browser to 443, which on a gateway
	// serving another port is a different service on the same hostname.
	effective := u.Port()
	if effective == "" {
		effective = "443"
	}
	if effective != strconv.Itoa(port) {
		return ""
	}
	return u.String()
}

func (s *Server) homeURL() string {
	domain, port := s.o.Address()
	if domain == "" {
		return ""
	}
	if port == 443 {
		return "https://" + domain
	}
	return "https://" + domain + ":" + strconv.Itoa(port)
}

func (s *Server) sessionCookie(value string, maxAge int) *http.Cookie {
	domain, _ := s.o.Address()
	return &http.Cookie{
		Name: auth.CookieName, Value: value, Path: "/", Domain: domain,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge,
	}
}

func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	who := PrincipalFrom(r.Context()).Whoami()
	s.respond(w, r, http.StatusOK, map[string]any{"session": who}, console.FragmentSession, who)
}

// Logout ends the request's session (the page route /logout uses it too).
func (s *Server) Logout(w http.ResponseWriter, p *Principal) error {
	if p != nil && p.Session != nil && s.o.Auth != nil {
		if err := s.o.Auth.Logout(p.Session); err != nil {
			return err // the session stands: a sign-out the audit cannot record did not happen
		}
	}
	http.SetCookie(w, s.sessionCookie("", -1))
	return nil
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if err := s.Logout(w, PrincipalFrom(r.Context())); err != nil {
		s.writeError(w, r, err)
		return
	}
	if wantsHTML(r) {
		if r.Header.Get("HX-Request") != "" {
			w.Header().Set("HX-Redirect", "/login")
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) setOperator(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Replace  bool   `json:"replace"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		e := pdr.New(pdr.CodePasswordPolicy, "malformed operator body: %v", err)
		s.writeError(w, r, e)
		return
	}
	if err := s.o.Auth.SetOperator(req.Username, req.Password, req.Replace, auth.MechanismSocket); err != nil {
		s.writeError(w, r, err)
		return
	}
	op, err := s.o.Auth.Operator()
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	status := http.StatusCreated
	if req.Replace {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"operator": map[string]any{"username": op.Username, "created": op.Created}})
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	s.tokenMu.RLock()
	defer s.tokenMu.RUnlock()
	list, err := s.o.Auth.ListTokens()
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": list})
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	s.tokenMu.Lock()
	defer s.tokenMu.Unlock()
	var req struct {
		Name   string `json:"name"`
		Scope  string `json:"scope"`
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		e := pdr.New(pdr.CodePasswordPolicy, "malformed token body: %v", err)
		e.Next = `POST {"name","scope"}`
		s.writeError(w, r, e)
		return
	}
	p := PrincipalFrom(r.Context())
	if req.Secret != "" {
		// A secret the caller made and already holds (API §2.3: the CLI
		// saves it before the token exists); the response carries none.
		tok, err := s.o.Auth.CreateTokenWithSecret(req.Name, req.Scope, req.Secret, p.Subject, p.Mechanism)
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"token": tok})
		return
	}
	secret, tok, err := s.o.Auth.CreateToken(req.Name, req.Scope, p.Subject, p.Mechanism)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"token": tok, "secret": secret})
}

func (s *Server) deleteToken(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	if err := s.o.Auth.RevokeToken(r.PathValue("id"), p.Subject, p.Mechanism); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- instances --------------------------------------------------------

func (s *Server) listInstances(w http.ResponseWriter, r *http.Request) {
	var views []engine.InstanceView
	if bound := boundTo(r); bound != "" {
		// A bound bearer is asked the same question the single-instance
		// read answers, rather than filtered out of the operator's
		// listing: `View` compares the generation where it resolves the
		// lab *and* confirms it after building the view, and filtering
		// a list built without that confirmation would hand over a view
		// whose services and jobs came from the replacement while its
		// row came from the lab that is gone.
		//
		// It is asked *instead of* the operator's listing, not after it:
		// running that first made an attendee's answer depend on every
		// other lab on the host, so a fault reading one of them refused
		// them their own — naming a lab their grant does not cover.
		switch v, err := s.o.Engine.View(bound, actorOf(r)); {
		case err == nil:
			views = []engine.InstanceView{*v}
		case isNotFound(err):
			// The lab is gone, or the name is a different lab now: an
			// empty listing is the right answer, and the same one an
			// instance outside the grant gets.
		default:
			// Anything else is a fault, not an absence. Swallowing it
			// turned a store error into a 200 with nothing in it, which
			// reads to an attendee as a lab that is simply empty.
			s.writeError(w, r, err)
			return
		}
	} else {
		all, err := s.o.Engine.Views()
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		views = all
	}
	s.respond(w, r, http.StatusOK, map[string]any{"instances": views}, console.FragmentInstances, views)
}

func (s *Server) createInstance(w http.ResponseWriter, r *http.Request) {
	var req engine.CreateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	err := dec.Decode(&req)
	if err == nil {
		// One JSON object is the documented body: anything after it is
		// not ignored, it is a malformed request.
		if terr := dec.Decode(new(json.RawMessage)); terr != io.EOF {
			err = errors.New("trailing data after the create object")
		}
	}
	if err != nil {
		pe := pdr.New(pdr.CodeCreateRequest, "malformed create body: %v", err)
		pe.Next = "POST {\"template\"|\"path\", \"name\", \"profile\", \"mode\", \"accept_licenses\"} (API §7.1)"
		s.writeError(w, r, pe)
		return
	}
	req.Actor = actorOf(r) // who accepted the terms, for the audit stream (API §6.2)
	job, err := s.o.Engine.Create(r.Context(), req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (s *Server) getInstance(w http.ResponseWriter, r *http.Request) {
	if bound, name := boundTo(r), r.PathValue("name"); bound != "" && name != bound {
		s.writeError(w, r, notFound("instance", name))
		return
	}
	v, err := s.o.Engine.View(r.PathValue("name"), actorOf(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if wantsHTML(r) {
		// The console's live region is this read (labsurface.html). One
		// event changes more of the page than the ladder: the start-here
		// card offers Begin once a lab is ready and stops offering it
		// after a reset, and the status bar carries the same rungs. They
		// are refreshed here, as htmx out-of-band swaps, rather than by
		// three connections asking three questions on every event —
		// which is what left them stale.
		//
		// The binding rule holds: every part of this answer is a
		// projection of a twin this same caller may fetch — the instance
		// view, its playbooks and their progress — and no part of it is
		// a fact the JSON side does not carry. The JSON representation is
		// unchanged.
		s.respond(w, r, http.StatusOK, map[string]any{"instance": v}, console.FragmentInstanceLive,
			console.InstanceLive{Instance: *v, StartHere: s.startHereFor(r, *v)})
		return
	}
	s.respond(w, r, http.StatusOK, map[string]any{"instance": v}, console.FragmentInstance, *v)
}

// startHereFor projects the card from the twins the page itself would
// fetch: the instance view, its playbooks, and the progress of the one
// the card would open.
func (s *Server) startHereFor(r *http.Request, v engine.InstanceView) console.StartHere {
	pbs, err := s.o.Engine.Playbooks(v.Name, actorOf(r))
	if err != nil {
		pbs = nil
	}
	var progress *state.Progress
	if len(pbs) > 0 {
		if p, err := s.o.Engine.Progress(v.Name, pbs[0].Name, actorOf(r)); err == nil {
			progress = p
		}
	}
	return console.StartHereFor(v, pbs, progress)
}

func (s *Server) deleteInstance(w http.ResponseWriter, r *http.Request) {
	job, err := s.o.Engine.DestroyAs(r.Context(), r.PathValue("name"), r.URL.Query().Get("confirm"), actorOf(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request) {
	job, err := s.o.Engine.Job(r.PathValue("id"), actorOf(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if bound := boundTo(r); bound != "" {
		// The name is not enough: a job of the lab that took this name
		// belongs to a different generation, and its journal is not
		// this bearer's to read. Instance refuses on the generation it
		// resolves.
		if _, err := s.o.Engine.Instance(job.Instance, actorOf(r)); job.Instance != bound || err != nil {
			s.writeError(w, r, notFound("job", job.ID))
			return
		}
	}
	events, err := s.o.Engine.Events(job.ID, actorOf(r))
	if err != nil {
		// Job plus journal is the promise (API §4): a journal the store
		// could not read is an error, never an empty events[].
		s.writeError(w, r, err)
		return
	}
	if events == nil {
		events = []state.Event{} // an empty journal is [], never null
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job, "events": events})
}

// --- representation ---------------------------------------------------

// wantsHTML is the content negotiation (API §1): the console sends
// Accept: text/html (htmx marks its requests too); everything else is
// JSON. text/html must outrank application/json in the Accept header.
func wantsHTML(r *http.Request) bool {
	if r.Header.Get("HX-Request") != "" {
		return true
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	html := strings.Index(accept, "text/html")
	if html < 0 {
		return false
	}
	if j := strings.Index(accept, "application/json"); j >= 0 && j < html {
		return false
	}
	return true
}

// respond writes the JSON body, or the named fragment of data when the
// caller asked for HTML — the same handler, two representations.
func (s *Server) respond(w http.ResponseWriter, r *http.Request, status int, body any, fragment string, data any) {
	if fragment != "" && wantsHTML(r) {
		html, err := s.o.Console.Fragment(fragment, data)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": pdr.New(pdr.CodeRuntimeFailed, "%s", err.Error())})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(html))
		return
	}
	writeJSON(w, status, body)
}

// Status maps a PDR code to its HTTP status (API §3).
func Status(code string) int {
	switch code {
	case pdr.CodeLabUnreadable, pdr.CodeLabSchema, pdr.CodeLabReference, pdr.CodeLabStructure, pdr.CodeLabComposition,
		pdr.CodeLabRetired, pdr.CodeInstanceName, pdr.CodeDestroyConfirm, pdr.CodeCreateRequest, pdr.CodePasswordPolicy,
		pdr.CodeProgressRefused, pdr.CodeAttestRefused:
		return http.StatusBadRequest
	case pdr.CodeUnauthenticated, pdr.CodeLoginFailed, pdr.CodeNoOperator:
		return http.StatusUnauthorized
	case pdr.CodeScopeInsufficient, pdr.CodeCSRF, pdr.CodeSessionRefused:
		return http.StatusForbidden
	case pdr.CodeInstanceNotFound, pdr.CodeTemplateNotFound, pdr.CodeTemplateRetired, pdr.CodeTokenNotFound,
		pdr.CodeCheckpointNotFound, pdr.CodeSeedNotFound, pdr.CodePlaybookNotFound, pdr.CodeSecretNotFound, pdr.CodeEvidenceNotFound,
		pdr.CodeServiceNotFound, pdr.CodeExplainUnknown:
		return http.StatusNotFound
	case pdr.CodeInstanceExists, pdr.CodeInstanceBusy, pdr.CodeInstanceUnsupported, pdr.CodeTokenExists, pdr.CodeOperatorExists:
		return http.StatusConflict
	case pdr.CodeLicenseRequired:
		return http.StatusPreconditionRequired
	case pdr.CodeLoginThrottled, pdr.CodeLoginLocked, pdr.CodePublicThrottled:
		return http.StatusTooManyRequests
	}
	return http.StatusInternalServerError
}

func (s *Server) setRetryAfter(w http.ResponseWriter, err error) {
	var th *auth.Throttled
	if errors.As(err, &th) {
		w.Header().Set("Retry-After", strconv.Itoa(auth.RetryAfterSeconds(th.RetryAfter)))
	}
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var pe *pdr.Error
	if !errors.As(err, &pe) {
		pe = pdr.New(pdr.CodeRuntimeFailed, "%s", err.Error())
	}
	s.setRetryAfter(w, err)
	s.respond(w, r, Status(pe.Code), map[string]any{"error": pe}, console.FragmentError, pe)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// clientSource is the login throttle key: the peer address, never a
// forwarded header (which a caller could set to dodge the throttle).
// Socket peers have no address and share the key "socket".
func clientSource(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		if r.RemoteAddr == "" || r.RemoteAddr == "@" {
			return "socket"
		}
		return r.RemoteAddr
	}
	return host
}
