// SPDX-License-Identifier: AGPL-3.0-only

// Package gateway is the engine's network door (plan S5; INSTALL §2 step
// 4; threat model B1–B3): one TLS listener on the gateway port, routed by
// Host header — the operator console at the apex, one console per
// instance, one vhost per product UI proxied to its loopback-published
// port — with unknown hostnames dropped (the legacy 444), WebSocket
// upgrades passed through, framing headers rewritten on product vhosts
// only, and the console itself never frameable.
package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/api"
	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/console"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
	"github.com/jeremiahjrross/podaro/internal/sysinfo"
	"github.com/jeremiahjrross/podaro/internal/tlsca"
)

// Options wire the gateway.
type Options struct {
	API     *api.Server
	Engine  *engine.Engine
	Console *console.Renderer
	// Assets is the console's static bundle, served at /assets/.
	Assets fs.FS
	Logf   func(format string, args ...any)
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Proxy specifics carried over from the legacy nginx gateway (extraction
// §2): large response headers, 90 s reads and 100 MiB request bodies —
// what product UIs and bulk APIs behind the gateway can need.
const (
	upstreamHeaderTimeout = 90 * time.Second
	upstreamHeaderBytes   = 1 << 20
	maxProxiedBody        = 100 << 20
	renewCheckEvery       = 6 * time.Hour
)

// Gateway is the listener plus the router.
type Gateway struct {
	o Options

	mu       sync.Mutex
	domain   string
	port     int
	managed  bool
	certFile string
	keyFile  string
	caPaths  tlsca.Paths
	ln       net.Listener
	srv      *http.Server
	cert     atomic.Pointer[tls.Certificate]
	leaf     atomic.Pointer[x509.Certificate]
	upstream *http.Transport
	dialer   *net.Dialer
}

// New builds a gateway; Apply opens it.
func New(o Options) *Gateway {
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	if o.Console == nil {
		o.Console = console.Must()
	}
	g := &Gateway{o: o, dialer: &net.Dialer{Timeout: 10 * time.Second}}
	g.upstream = &http.Transport{
		Proxy:                  nil,
		DialContext:            g.dialUpstream,
		ResponseHeaderTimeout:  upstreamHeaderTimeout,
		MaxResponseHeaderBytes: upstreamHeaderBytes,
		IdleConnTimeout:        90 * time.Second,
		// Lab products speak self-signed TLS to the gateway (some
		// products' web UIs do); the gateway asks "is it answering", not
		// "is it trusted" — operator-facing TLS is never configured this
		// way.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // lab-internal upstreams on loopback
	}
	return g
}

// upstreamSuffix ends the name a product's upstream goes by inside the
// proxy: `<service>.<instance>` under a suffix that never resolves. The
// name is resolved by dialUpstream when the connection is opened (never
// by DNS), and it keys the transport's connection pool per service, so
// an idle connection is only ever reused for the service it was opened
// for — never for whatever holds a host port later.
const upstreamSuffix = ".upstream.podaro.invalid"

func upstreamHost(instance, service string) string {
	return service + "." + instance + upstreamSuffix
}

// upstreamHostFor is the upstream a *bearer* addresses: the same name
// with its generation in it. `http.Transport` pools connections by the
// address it is asked for, so two generations that share a name would
// otherwise share a pooled connection — and a check made before the
// transport picks one cannot prevent that, whatever it concludes. Two
// generations now never share a pool key, so the question of reusing
// each other's connections does not arise.
//
// The operator, entitled to no generation in particular, keeps the plain
// name and the pool it has always used.
func upstreamHostFor(instance, service string, gen *int64) string {
	if gen == nil {
		return upstreamHost(instance, service)
	}
	return service + "." + instance + ".g" + strconv.FormatInt(*gen, 10) + upstreamSuffix
}

// dialUpstream is the proxy transport's dialer. The route is resolved by
// the engine at the moment the connection is opened, under the lock its
// withdrawal takes: the row the request was classified from is a copy,
// and a destroy can withdraw the route — and free the host port for
// another lab's container — while the request is between its
// classification and its connection. Its answer for a route that is
// gone is engine.ErrNoRoute, rendered by serveProduct.
func (g *Gateway) dialUpstream(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	instance, service, ok := upstreamParts(host)
	if !ok {
		return nil, fmt.Errorf("gateway: %q is not a product upstream", host)
	}
	// The bearer's entitlement rides the outbound request's context: a
	// transport's dial takes no arguments of ours, and this is the one
	// place the proxy and the engine meet.
	return g.o.Engine.DialService(ctx, instance, service, engine.Actor{Gen: generationFrom(ctx)}, g.dialer.DialContext)
}

// generationKey carries the generation a proxied request is entitled to,
// from serveProduct to the dial the transport makes for it.
type generationKey struct{}

func withGeneration(ctx context.Context, gen *int64) context.Context {
	if gen == nil {
		return ctx
	}
	return context.WithValue(ctx, generationKey{}, gen)
}

func generationFrom(ctx context.Context) *int64 {
	gen, _ := ctx.Value(generationKey{}).(*int64)
	return gen
}

// upstreamParts reads the instance and service out of a product's
// upstream name (with or without a port).
func upstreamParts(host string) (instance, service string, ok bool) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	name, ok := strings.CutSuffix(host, upstreamSuffix)
	if !ok {
		return "", "", false
	}
	service, instance, ok = strings.Cut(name, ".")
	if !ok || service == "" || instance == "" {
		return "", "", false
	}
	// A bearer's upstream carries its generation, which is part of the
	// pool key and no part of the instance's name.
	if rest, gen, cut := strings.Cut(instance, ".g"); cut && gen != "" && allDigitsOrSign(gen) {
		instance = rest
	}
	if instance == "" {
		return "", "", false
	}
	return instance, service, true
}

// allDigitsOrSign reports whether s is a decimal integer, which is what
// a generation is written as. `-1` is one: a job or a row whose
// generation is not known carries it.
func allDigitsOrSign(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '-' {
		s = s[1:]
	}
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// routeGuard asks the engine whether the route still stands before every
// round trip. The dialer decides where a *new* connection goes, but an
// idle keep-alive connection is reused without dialling: without this, a
// request arriving after a withdrawal — a destroy, a stale container
// being replaced — would ride the pooled connection to the container
// that is going, until its removal closed it.
type routeGuard struct {
	rt  http.RoundTripper
	eng *engine.Engine
}

func (g routeGuard) RoundTrip(r *http.Request) (*http.Response, error) {
	instance, service, ok := upstreamParts(r.URL.Host)
	if !ok {
		return nil, fmt.Errorf("gateway: %q is not a product upstream", r.URL.Host)
	}
	// The generation is checked here as well as in the dial, and here is
	// the one that covers every request: a pooled keep-alive connection
	// is reused without dialling, so a request authenticated before a
	// destroy could ride a connection a current-generation request had
	// opened. The dial guard never sees that round trip.
	if gen := generationFrom(r.Context()); gen != nil {
		if _, err := g.eng.Instance(instance, engine.Actor{Gen: gen}); err != nil {
			return nil, engine.ErrNoRoute
		}
	}
	if err := g.eng.RouteLive(instance, service); err != nil {
		return nil, err
	}
	return g.rt.RoundTrip(r)
}

// Address reports the domain and port the gateway serves ("" before
// setup): the engine renders console and service URLs from it.
func (g *Gateway) Address() (string, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.domain, g.port
}

// SetAddress fixes the address without listening (tests drive the
// handler through httptest).
func (g *Gateway) SetAddress(domain string, port int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.domain, g.port = domain, port
}

// Status is the /system gateway posture.
func (g *Gateway) Status() sysinfo.Gateway {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ln == nil {
		return sysinfo.Gateway{}
	}
	st := sysinfo.Gateway{Listening: true, Address: ":" + strconv.Itoa(g.port), Domain: g.domain, Certificate: "bring-your-own"}
	if g.managed {
		st.Certificate = "local-ca"
	}
	if leaf := g.leaf.Load(); leaf != nil {
		st.Expires = leaf.NotAfter.UTC().Format(time.RFC3339)
		st.Fingerprint = tlsca.Fingerprint(leaf)
	}
	return st
}

// Apply (re)configures the gateway from config: no domain → closed;
// otherwise load (and, for the managed CA, renew) the leaf, then listen
// on the port — or just swap the certificate when already listening
// there. Errors are PDR-E023 (no CA: setup has not run) or PDR-E024
// (cannot bind or load).
func (g *Gateway) Apply(cfg *config.Config, stateDir string) (sysinfo.Gateway, error) {
	st, old, err := g.applyLocked(cfg, stateDir)
	// The replaced server drains after the lock is released: every
	// request takes the lock at entry (routing reads the address), so a
	// drain under it would wait for handlers that wait for it — the full
	// timeout on every reload that races a request.
	old.drain()
	return st, err
}

func (g *Gateway) applyLocked(cfg *config.Config, stateDir string) (st sysinfo.Gateway, old detached, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if cfg == nil || cfg.Domain == "" {
		old = g.detachLocked()
		g.domain, g.port = "", 0
		return sysinfo.Gateway{}, old, nil
	}
	paths := tlsca.NewPaths(stateDir)
	managed := cfg.TLS == nil
	certFile, keyFile := paths.LeafFile(), paths.LeafFile()
	if !managed {
		certFile, keyFile = cfg.TLS.CertFile, cfg.TLS.KeyFile
	}
	now := g.o.Now()
	if managed {
		// A publish interrupted by a crash is completed before the set is
		// read, so the engine never starts without its certificate.
		ca, err := tlsca.LoadCA(paths)
		if rerr := tlsca.Recover(paths); rerr != nil {
			err = rerr
		} else if err != nil {
			ca, err = tlsca.LoadCA(paths)
		}
		if err != nil {
			e := pdr.New(pdr.CodeSetupFailed, "no local certificate authority for %s", cfg.Domain)
			e.Cause = err.Error()
			e.Next = "podaro setup --domain " + cfg.Domain
			return sysinfo.Gateway{}, old, e
		}
		_, leaf, err := tlsca.LoadLeaf(certFile, keyFile)
		if err != nil || tlsca.NeedsReissue(leaf, ca.Cert, cfg.Domain, now) {
			if _, err := ca.IssueWildcard(paths, cfg.Domain, tlsca.LeafValidity, now); err != nil {
				e := pdr.New(pdr.CodeGatewayBind, "cannot issue the wildcard certificate for *.%s", cfg.Domain)
				e.Cause = err.Error()
				return sysinfo.Gateway{}, old, e
			}
			g.o.Logf("gateway: issued *.%s (valid %s)", cfg.Domain, tlsca.LeafValidity)
		}
	}
	pair, leaf, err := tlsca.LoadLeaf(certFile, keyFile)
	if err != nil {
		e := pdr.New(pdr.CodeGatewayBind, "cannot load the gateway certificate")
		e.Cause = err.Error()
		e.Next = "check tls.cert_file and tls.key_file in " + config.Path() + " · or remove the tls block to use the local CA"
		return sysinfo.Gateway{}, old, e
	}
	if err := tlsca.Serves(leaf, cfg.Domain, now); err != nil {
		e := pdr.New(pdr.CodeGatewayBind, "the certificate cannot serve %s and *.%s now", cfg.Domain, cfg.Domain)
		e.Cause = err.Error()
		e.Next = "bring a valid certificate covering *." + cfg.Domain + " and " + cfg.Domain + ", or remove the tls block"
		return sysinfo.Gateway{}, old, e
	}
	// A port change binds the replacement before the current listener
	// goes, and nothing of the new configuration is applied until it has:
	// a port that turns out to be taken leaves the working door serving
	// exactly as it was (E024 names both ports), never the only network
	// door closed by a reload.
	rebind := g.ln == nil || g.port != cfg.Gateway.Port
	var ln net.Listener
	if rebind {
		l, err := net.Listen("tcp", ":"+strconv.Itoa(cfg.Gateway.Port))
		if err != nil {
			e := pdr.New(pdr.CodeGatewayBind, "cannot listen on :%d", cfg.Gateway.Port)
			e.Cause = err.Error()
			if g.ln != nil {
				e.Cause += fmt.Sprintf("; the gateway keeps serving on :%d for *.%s", g.port, g.domain)
			}
			e.Next = "podaro doctor · free the port or set gateway.port in " + config.Path()
			return sysinfo.Gateway{}, old, e
		}
		ln = l
	}
	g.cert.Store(&pair)
	g.leaf.Store(leaf)
	g.domain, g.managed, g.certFile, g.keyFile, g.caPaths = cfg.Domain, managed, certFile, keyFile, paths
	if !rebind {
		return g.statusLocked(), old, nil
	}
	old = g.detachLocked()
	g.port = cfg.Gateway.Port
	g.ln = tls.NewListener(ln, g.tlsConfig())
	g.srv = &http.Server{
		Handler:           g,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          newQuietLog(g.o.Logf),
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){}, // HTTP/1.1 only: hijack-able drops, WebSocket upgrades
	}
	srv, l := g.srv, g.ln
	go func() {
		if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			g.o.Logf("gateway: %v", err)
		}
	}()
	g.o.Logf("gateway: listening on :%d (TLS) for *.%s", g.port, g.domain)
	return g.statusLocked(), old, nil
}

func (g *Gateway) statusLocked() sysinfo.Gateway {
	st := sysinfo.Gateway{Listening: true, Address: ":" + strconv.Itoa(g.port), Domain: g.domain, Certificate: "bring-your-own"}
	if g.managed {
		st.Certificate = "local-ca"
	}
	if leaf := g.leaf.Load(); leaf != nil {
		st.Expires = leaf.NotAfter.UTC().Format(time.RFC3339)
		st.Fingerprint = tlsca.Fingerprint(leaf)
	}
	return st
}

// detached is a server and listener taken out of the gateway under the
// lock, to be drained after it: an active handler may be waiting for
// the lock itself.
type detached struct {
	srv *http.Server
	ln  net.Listener
}

func (g *Gateway) detachLocked() detached {
	d := detached{srv: g.srv, ln: g.ln}
	g.srv, g.ln = nil, nil
	return d
}

// drain finishes the detached server's requests (five seconds at most)
// and closes its listener. Never call it with the lock held.
func (d detached) drain() {
	if d.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = d.srv.Shutdown(ctx)
		cancel()
	}
	if d.ln != nil {
		_ = d.ln.Close()
	}
}

// Close stops listening.
func (g *Gateway) Close() {
	g.mu.Lock()
	old := g.detachLocked()
	g.mu.Unlock()
	old.drain()
}

// tlsConfig serves the current leaf and refuses server names outside the
// domain before any HTTP happens; a client sending no name (an IP
// literal) gets the certificate and is dropped at the Host check.
func (g *Gateway) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if name := strings.ToLower(strings.TrimSuffix(hello.ServerName, ".")); name != "" {
				domain, _ := g.Address()
				if name != domain && !strings.HasSuffix(name, "."+domain) {
					return nil, errUnknownHost
				}
			}
			c := g.cert.Load()
			if c == nil {
				return nil, errors.New("gateway: no certificate loaded")
			}
			return c, nil
		},
	}
}

var errUnknownHost = errors.New("unknown host")

// RenewIfDue re-issues a managed leaf inside its renewal window and
// swaps it into the live listener.
func (g *Gateway) RenewIfDue(now time.Time) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.managed || g.domain == "" {
		return false, nil
	}
	// The CA in place decides: a leaf inside its window that this CA did
	// not sign — a partial restore — is re-issued rather than served on.
	ca, err := tlsca.LoadCA(g.caPaths)
	if err != nil {
		return false, err
	}
	if !tlsca.NeedsReissue(g.leaf.Load(), ca.Cert, g.domain, now) {
		return false, nil
	}
	// The issue and the read that follows it are one holder's: `podaro
	// setup` publishes a staged set as one swap, and a swap landing
	// between them would have this renewal read another generation's leaf
	// — the candidate's, for another domain — and put it into a listener
	// still serving this one. A setup holding the
	// lock means the set is changing under us: the leaf in place keeps
	// serving and the next tick renews against whatever the swap settled
	// on, which is what a renewal window of days is for.
	stateDir := filepath.Dir(g.caPaths.Dir)
	unlock, err := tlsca.Lock(stateDir)
	if errors.Is(err, tlsca.ErrLocked) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer unlock()
	// Under the lock, the CA is read again: the one this renewal judged
	// the leaf against may have been replaced by the setup that just
	// finished.
	if ca, err = tlsca.LoadCA(g.caPaths); err != nil {
		return false, err
	}
	if !tlsca.NeedsReissue(g.leaf.Load(), ca.Cert, g.domain, now) {
		return false, nil
	}
	if _, err := ca.IssueWildcard(g.caPaths, g.domain, tlsca.LeafValidity, now); err != nil {
		return false, err
	}
	pair, leaf, err := tlsca.LoadLeaf(g.certFile, g.keyFile)
	if err != nil {
		return false, err
	}
	// What was read must serve this gateway's domain: a set that changed
	// despite the lock — a restore by hand, a set from another
	// generation — is never installed over the leaf in place.
	if err := tlsca.Serves(leaf, g.domain, now); err != nil {
		return false, fmt.Errorf("the certificate set changed under the renewal: %w", err)
	}
	g.cert.Store(&pair)
	g.leaf.Store(leaf)
	g.o.Logf("gateway: renewed *.%s until %s", g.domain, leaf.NotAfter.Format(time.RFC3339))
	return true, nil
}

// Run checks renewal periodically until stop closes.
func (g *Gateway) Run(stop <-chan struct{}) {
	t := time.NewTicker(renewCheckEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if _, err := g.RenewIfDue(g.o.Now()); err != nil {
				g.o.Logf("gateway: renewal failed: %v", err)
			}
		}
	}
}

// --- routing ----------------------------------------------------------

type routeKind int

const (
	routeUnknown routeKind = iota
	routeApex
	routeInstance
	routeService
)

type route struct {
	kind     routeKind
	instance *state.Instance
	service  *state.Service
}

// classify maps a Host to a route (User Manual §5): the apex, an
// instance console, or `<service>-<instance>` for a product UI. Instance
// names may contain hyphens, so the split is tried at every hyphen after
// the exact-instance match fails.
func (g *Gateway) classify(host, domain string) route {
	if domain == "" {
		return route{}
	}
	if host == domain {
		return route{kind: routeApex}
	}
	if !strings.HasSuffix(host, "."+domain) {
		return route{}
	}
	label := strings.TrimSuffix(host, "."+domain)
	if label == "" || strings.Contains(label, ".") {
		return route{}
	}
	if inst, err := g.o.Engine.Instance(label, engine.Socket); err == nil {
		return route{kind: routeInstance, instance: inst}
	}
	for i := 1; i < len(label)-1; i++ {
		if label[i] != '-' {
			continue
		}
		svcName, instName := label[:i], label[i+1:]
		inst, err := g.o.Engine.Instance(instName, engine.Socket)
		if err != nil {
			continue
		}
		svc, _ := g.o.Engine.Service(instName, svcName)
		if svc != nil && svc.UIPort > 0 && svc.Embed != "api-only" && proxiable(svc.UIScheme) {
			return route{kind: routeService, instance: inst, service: svc}
		}
	}
	return route{}
}

// proxiable reports whether a ui endpoint's scheme is one the proxy can
// reach: http or https (the schema's default is http). A ui endpoint on
// tcp is refused by lab validate (PDR-E103); a row carrying one anyway
// gets no hostname rather than one every request fails on.
func proxiable(scheme string) bool {
	return scheme == "" || scheme == "http" || scheme == "https"
}

func hostOf(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// ServeHTTP is the host router.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	domain, port := g.Address()
	rt := g.classify(hostOf(r.Host), domain)
	switch rt.kind {
	case routeApex:
		g.serveConsole(w, r, domain, port, nil)
	case routeInstance:
		g.serveConsole(w, r, domain, port, rt.instance)
	case routeService:
		g.serveProduct(w, r, domain, port, rt)
	default:
		drop(w)
	}
}

// drop closes the connection without a response — the legacy 444 for
// unknown hostnames (threat model B1: an internet-facing host advertises
// nothing).
func drop(w http.ResponseWriter) {
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			_ = conn.Close()
			return
		}
	}
	panic(http.ErrAbortHandler)
}

// --- console hostnames ------------------------------------------------

func (g *Gateway) securityHeaders(h http.Header, domain string, port int) {
	frame := "https://*." + domain
	if port != 443 {
		frame += ":" + strconv.Itoa(port)
	}
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-src "+frame+"; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	h.Set("Strict-Transport-Security", "max-age=31536000")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
}

func (g *Gateway) homeURL(domain string, port int) string {
	if port == 443 {
		return "https://" + domain
	}
	return "https://" + domain + ":" + strconv.Itoa(port)
}

func (g *Gateway) serveConsole(w http.ResponseWriter, r *http.Request, domain string, port int, inst *state.Instance) {
	g.securityHeaders(w.Header(), domain, port)
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/assets/"):
		g.serveAsset(w, r)
	case path == "/legal" || path == api.Prefix+"/system/legal":
		// The two public routes (API §2; threat model B1): the licence, the
		// notices and the source offer, for anyone who can reach this
		// gateway — an attendee and a signed-out visitor must reach the
		// source offer (the reconciliation §7.2). Served before any session
		// is looked at, the hostname binding included: they read no
		// session, write no state, and answer the same to everyone.
		w.Header().Set("Cache-Control", "no-store")
		if path == "/legal" {
			g.legalPage(w, r)
			return
		}
		g.o.API.ServeHTTP(w, r)
	case path == api.Prefix || strings.HasPrefix(path, api.Prefix+"/"):
		w.Header().Set("Cache-Control", "no-store")
		// An instance-bound session (API §2.4) reaches the API only on its
		// own instance's console host: the hostname binding is enforced
		// here, before dispatch, as it is on the pages and the product
		// vhosts (threat model A2) — never left to the handlers. The check
		// peeks: the handler's own authentication is the one use that
		// slides the session and re-issues the cookie (API §2.2).
		if sess := g.o.API.PeekSession(r); sess != nil && sess.Instance != "" && (inst == nil || sess.Instance != inst.Name) {
			e := pdr.New(pdr.CodeSessionRefused, "this session is bound to instance %q", sess.Instance)
			g.jsonError(w, http.StatusForbidden, e)
			return
		}
		g.o.API.NetworkHandler().ServeHTTP(w, r)
	case path == "/login":
		g.loginPage(w, r, domain, port)
	case path == "/logout":
		g.logout(w, r)
	case path == "/":
		g.homePage(w, r, domain, port, inst)
	default:
		w.Header().Set("Cache-Control", "no-store")
		http.NotFound(w, r)
	}
}

func (g *Gateway) serveAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// The embedded bundle is rooted at console/, so the URL path minus its
	// leading slash is the file's name (assets/console.css).
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "assets/" || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	f, err := g.o.Assets.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	rs, ok := f.(interface {
		fs.File
		Seek(int64, int) (int64, error)
	})
	if !ok {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, name, time.Time{}, rs)
}

func (g *Gateway) page(w http.ResponseWriter, status int, data console.ShellData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	data.Version = podaro.Version()
	if err := g.o.Console.Page(w, data); err != nil {
		g.o.Logf("gateway: render: %v", err)
	}
}

func (g *Gateway) loginPage(w http.ResponseWriter, r *http.Request, domain string, port int) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if p := g.o.API.Authenticate(r); p != nil {
		// A signed-in visitor is sent home; the visit counted as use, so
		// when it slid the session the cookie is re-issued here — the
		// pages the redirect leads to are inside the touch throttle's
		// minute and would not (API §2.2).
		g.o.API.RefreshCookie(w, p)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	body, _ := g.o.Console.Fragment(console.FragmentLogin, console.LoginData{Next: g.o.API.SafeNext(r.URL.Query().Get("next"))})
	g.page(w, http.StatusOK, console.ShellData{Title: console.PageTitle("Sign in"), HomeURL: g.homeURL(domain, port), Body: body})
}

// legalPage is GET /legal: the licence and source page, framed by the
// shell around the same fragment GET /system/legal answers to
// `Accept: text/html`, from the same value (ADR-0003). It carries no
// session — no "signed in as", no sign-out, a wordmark that goes to this
// host's own root — so it is the same page for an operator, an attendee
// on their lab's hostname, and a visitor who has never signed in; and it
// is admitted per source like the route it frames.
func (g *Gateway) legalPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := g.o.API.AdmitPublic(r); err != nil {
		var th *auth.Throttled
		if errors.As(err, &th) {
			w.Header().Set("Retry-After", strconv.Itoa(auth.RetryAfterSeconds(th.RetryAfter)))
			g.errorPage(w, r, http.StatusTooManyRequests, th.Env, nil)
			return
		}
		g.errorPage(w, r, http.StatusInternalServerError, pdr.New(pdr.CodeRuntimeFailed, "%s", err.Error()), nil)
		return
	}
	body, err := g.o.Console.Fragment(console.FragmentLegal, g.o.API.Legal())
	if err != nil {
		g.errorPage(w, r, http.StatusInternalServerError, pdr.New(pdr.CodeRuntimeFailed, "%s", err.Error()), nil)
		return
	}
	g.page(w, http.StatusOK, console.ShellData{Title: console.PageTitle("Licence and source"), Body: body})
}

// logout is the no-JavaScript form path; the API's DELETE /auth/session
// is the same act for htmx and scripts.
func (g *Gateway) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p := g.o.API.Authenticate(r)
	if p == nil || p.Session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()
	if r.PostForm.Get("csrf") != p.Session.CSRF {
		e := pdr.New(pdr.CodeCSRF, "sign-out form is missing its CSRF token")
		e.Next = "reload the page and try again"
		g.errorPage(w, r, http.StatusForbidden, e, nil)
		return
	}
	if err := g.o.API.Logout(w, p); err != nil {
		e := pdr.New(pdr.CodeRuntimeFailed, "%s", err.Error())
		e.Next = "try again; the session stands until its sign-out is on record"
		g.errorPage(w, r, http.StatusInternalServerError, e, nil)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (g *Gateway) errorPage(w http.ResponseWriter, r *http.Request, status int, e *pdr.Error, session *console.SessionView) {
	domain, port := g.Address()
	body, _ := g.o.Console.Fragment(console.FragmentError, e)
	g.page(w, status, console.ShellData{Title: console.PageTitle(e.Code), HomeURL: g.homeURL(domain, port), Session: session, Body: body})
}

func (g *Gateway) homePage(w http.ResponseWriter, r *http.Request, domain string, port int, inst *state.Instance) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p := g.o.API.Authenticate(r)
	if p == nil {
		target := "/login"
		if inst != nil {
			target += "?next=" + url.QueryEscape(g.homeURL(inst.Name+"."+domain, port)+"/")
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	g.o.API.RefreshCookie(w, p)
	session := &console.SessionView{Subject: p.Subject}
	if p.Session != nil {
		session.CSRF = p.Session.CSRF
		// What this session may do, as the shell needs to know it: an
		// instance-bound session is an attendee's, below read (API §2.4).
		session.Instance = p.Session.Instance
		if p.Session.Instance != "" && (inst == nil || p.Session.Instance != inst.Name) {
			e := pdr.New(pdr.CodeSessionRefused, "this session is bound to instance %q", p.Session.Instance)
			e.Next = g.homeURL(p.Session.Instance+"."+domain, port)
			g.errorPage(w, r, http.StatusForbidden, e, nil)
			return
		}
	}
	home := g.homeURL(domain, port)
	if inst == nil {
		views, err := g.o.Engine.Views()
		if err != nil {
			g.errorPage(w, r, http.StatusInternalServerError, pdr.New(pdr.CodeRuntimeFailed, "%s", err.Error()), session)
			return
		}
		body, _ := g.o.Console.Fragment(console.FragmentInstances, views)
		g.page(w, http.StatusOK, console.ShellData{Title: console.PageTitle(), HomeURL: home, Session: session, Poll: api.Prefix + "/instances", Body: body})
		return
	}
	// Asked as the caller, not as the local door: an attendee's grant
	// names one generation of one lab, and this page's reads are the
	// ones that were still asking for whichever lab holds the name.
	by := p.Actor()
	view, err := g.o.Engine.View(inst.Name, by)
	if err != nil {
		var pe *pdr.Error
		if !errors.As(err, &pe) {
			pe = pdr.New(pdr.CodeRuntimeFailed, "%s", err.Error())
		}
		g.errorPage(w, r, api.Status(pe.Code), pe, session)
		return
	}
	// The lab surface, assembled server-side: the ladder, the one
	// start-here card, the tab strip and the rail's region in one paint
	// (UX §7's tour; §11's first paint). Its parts are twins the console
	// could fetch separately — this spares the first paint a round trip
	// each. A playbook list the engine cannot answer is not fatal: the
	// rail's region renders empty and the page still stands.
	lab := console.LabData{Instance: *view, Tabs: console.TabsFor(*view)}
	if session != nil {
		lab.CSRF = session.CSRF
	}
	if pbs, err := g.o.Engine.Playbooks(inst.Name, by); err == nil {
		lab.Playbooks = pbs
	}
	var prog *state.Progress
	if len(lab.Playbooks) > 0 {
		if pr, err := g.o.Engine.Progress(inst.Name, lab.Playbooks[0].Name, by); err == nil {
			prog = pr
		}
	}
	lab.StartHere = console.StartHereFor(*view, lab.Playbooks, prog)
	body, _ := g.o.Console.Fragment(console.FragmentLab, lab)
	// An instance page has one stream, so it listens rather than polls
	// (UX §11 freshness, ADR-0003's SSE extension). Poll stays set: it is
	// the path the region re-reads *on* an event, not a timer.
	base := api.Prefix + "/instances/" + url.PathEscape(inst.Name)
	g.page(w, http.StatusOK, console.ShellData{Title: console.PageTitle(inst.Name), HomeURL: home, Instance: view, Session: session,
		Poll: base, Feed: base + "/events", Body: body})
}

// --- product vhosts ---------------------------------------------------

// serveProduct proxies `<service>-<instance>` to the service's loopback-
// published ui port. Every lab hostname requires a valid session (or
// token) before proxying (threat model B3); framing headers are rewritten
// so the console can embed the product; nothing else is touched.
func (g *Gateway) serveProduct(w http.ResponseWriter, r *http.Request, domain string, port int, rt route) {
	p := g.o.API.Authenticate(r)
	if p == nil {
		if r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html") {
			next := g.homeURL(hostOf(r.Host), port) + r.URL.RequestURI()
			http.Redirect(w, r, g.homeURL(domain, port)+"/login?next="+url.QueryEscape(next), http.StatusFound)
			return
		}
		g.jsonError(w, http.StatusUnauthorized, unauthenticated())
		return
	}
	if p.Session != nil && p.Session.Instance != "" && p.Session.Instance != rt.instance.Name {
		e := pdr.New(pdr.CodeSessionRefused, "this session is bound to instance %q", p.Session.Instance)
		g.jsonError(w, http.StatusForbidden, e)
		return
	}
	// The route was classified before there was anyone to authenticate,
	// so it may name a lab that has since been destroyed and its name
	// taken again. The bearer's generation is compared here and carried
	// to the dial, which checks it again under the lock a withdrawal
	// takes.
	var want *int64
	if p.Session != nil && p.Session.Instance != "" {
		gen := p.Session.Gen
		want = &gen
		if rt.instance.AuditFrom != gen {
			e := pdr.New(pdr.CodeInstanceNotFound, "no such instance %q", rt.instance.Name)
			e.Next = "podaro status"
			g.jsonError(w, http.StatusNotFound, e)
			return
		}
	}
	g.o.API.RefreshCookie(w, p)
	scheme := rt.service.UIScheme
	if scheme == "" {
		scheme = "http"
	}
	// The host port is not taken from the route: the engine resolves it
	// when the connection is opened (dialUpstream), under the lock a
	// withdrawal takes, so a destroy racing this request finds it
	// "not up" rather than connected to whatever holds the port now.
	target := &url.URL{Scheme: scheme, Host: upstreamHostFor(rt.instance.Name, rt.service.Name, want)}
	consoleOrigin := g.homeURL(rt.instance.Name+"."+domain, port)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out = pr.Out.WithContext(withGeneration(pr.Out.Context(), want))
			pr.Out.Host = pr.In.Host
			stripGatewayCredentials(pr.Out.Header)
			pr.SetXForwarded()
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
			if ip, _, err := net.SplitHostPort(pr.In.RemoteAddr); err == nil {
				pr.Out.Header.Set("X-Real-IP", ip)
			}
		},
		Transport:     routeGuard{rt: g.upstream, eng: g.o.Engine},
		FlushInterval: -1,
		ModifyResponse: func(resp *http.Response) error {
			RewriteFrameHeaders(resp.Header, consoleOrigin)
			stripGatewayCookies(resp.Header)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, engine.ErrNoRoute) {
				e := pdr.New(pdr.CodeRuntimeFailed, "%s is not up yet", rt.service.Name)
				e.Cause = "the service has no published port: it is still being created, or it is going"
				e.Next = "podaro status " + rt.instance.Name
				g.jsonError(w, http.StatusBadGateway, e)
				return
			}
			e := pdr.New(pdr.CodeRuntimeFailed, "%s did not answer", rt.service.Name)
			e.Cause = err.Error()
			e.Next = "podaro status " + rt.instance.Name
			g.jsonError(w, http.StatusBadGateway, e)
		},
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxProxiedBody)
	proxy.ServeHTTP(w, r)
}

func unauthenticated() *pdr.Error {
	e := pdr.New(pdr.CodeUnauthenticated, "credentials required")
	e.Cause = "lab hostnames are proxied only to a signed-in session or a bearer token (threat model B3)"
	e.Next = "sign in at the console"
	return e
}

func (g *Gateway) jsonError(w http.ResponseWriter, status int, e *pdr.Error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%s}`+"\n", mustJSON(e))
}

func mustJSON(v any) string {
	raw, err := jsonMarshal(v)
	if err != nil {
		return `{"code":"PDR-E204","message":"render failed"}`
	}
	return string(raw)
}

// stripGatewayCredentials removes the gateway's own credentials from a
// request bound for a product: the session cookie and a Podaro bearer
// token authenticate the *gateway*, and a product that received them
// could replay them against the console API (threat model B3). The
// product's own cookies and any other Authorization scheme pass.
func stripGatewayCredentials(h http.Header) {
	if auth.IsPodaroBearer(h.Get("Authorization")) {
		h.Del("Authorization")
	}
	raw := h.Values("Cookie")
	if len(raw) == 0 {
		return
	}
	jar := (&http.Request{Header: http.Header{"Cookie": raw}}).Cookies()
	kept := make([]string, 0, len(jar))
	for _, c := range jar {
		if c.Name != auth.CookieName {
			kept = append(kept, c.Name+"="+c.Value)
		}
	}
	h.Del("Cookie")
	if len(kept) > 0 {
		h.Set("Cookie", strings.Join(kept, "; "))
	}
}

// stripGatewayCookies drops a product's attempt to set the gateway's own
// cookie: browsers let a subdomain set a cookie for its parent domain, so
// a compromised lab answering `Set-Cookie: podaro_session=…; Domain=…`
// could overwrite, expire or shadow the operator's session on every
// load (threat model B3). The product's other cookies pass.
func stripGatewayCookies(h http.Header) {
	values := h.Values("Set-Cookie")
	if len(values) == 0 {
		return
	}
	kept := make([]string, 0, len(values))
	for _, v := range values {
		name, _, _ := strings.Cut(v, "=")
		if strings.EqualFold(strings.TrimSpace(name), auth.CookieName) {
			continue
		}
		kept = append(kept, v)
	}
	h.Del("Set-Cookie")
	for _, v := range kept {
		h.Add("Set-Cookie", v)
	}
}

// RewriteFrameHeaders applies the product-vhost rule (threat model B3,
// D-settled): X-Frame-Options is removed and the frame-ancestors
// directive is pointed at the instance's console origin — replaced where
// the product sent one, added where it sent none (a policy without it,
// or no policy at all, would leave the product frameable by any origin
// once X-Frame-Options is gone) — so the product renders inside the
// console's tab and nowhere else. A report-only policy is rewritten but
// never invented. Console responses never pass through here.
func RewriteFrameHeaders(h http.Header, consoleOrigin string) {
	h.Del("X-Frame-Options")
	for _, key := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
		enforced := key == "Content-Security-Policy"
		values := h.Values(key)
		if len(values) == 0 {
			if enforced {
				h.Set(key, "frame-ancestors "+consoleOrigin)
			}
			continue
		}
		out := make([]string, 0, len(values))
		for _, v := range values {
			out = append(out, replaceFrameAncestors(v, consoleOrigin, enforced))
		}
		h.Del(key)
		for _, v := range out {
			h.Add(key, v)
		}
	}
}

// replaceFrameAncestors points the policy's frame-ancestors directive at
// origin; addIfMissing appends one to a policy that has none.
func replaceFrameAncestors(csp, origin string, addIfMissing bool) string {
	parts := strings.Split(csp, ";")
	out := make([]string, 0, len(parts)+1)
	found := false
	for _, part := range parts {
		d := strings.TrimSpace(part)
		if d == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(d), "frame-ancestors") {
			d = "frame-ancestors " + origin
			found = true
		}
		out = append(out, d)
	}
	if !found && addIfMissing {
		out = append(out, "frame-ancestors "+origin)
	}
	return strings.Join(out, "; ")
}

// quietLog forwards net/http server errors to Logf, dropping the TLS
// handshake noise scanners generate against a refused server name.
type quietLog struct{ logf func(string, ...any) }

func (q quietLog) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(p))
	if !strings.Contains(line, "TLS handshake error") {
		q.logf("gateway: %s", line)
	}
	return len(p), nil
}

func newQuietLog(logf func(string, ...any)) *logLogger { return newLogger(quietLog{logf}) }
