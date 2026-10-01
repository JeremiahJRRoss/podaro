// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/api"
	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/runtime"
	"github.com/jeremiahjrross/podaro/internal/state"
	"github.com/jeremiahjrross/podaro/internal/tlsca"
)

const domain = "lab.test"

type rig struct {
	t      *testing.T
	st     state.Store
	gw     *Gateway
	srv    *httptest.Server
	port   int
	eng    *engine.Engine
	auth   *auth.Service
	client *http.Client
	cookie string
}

// newRig wires engine + auth + API + gateway behind an httptest TLS
// server and points every hostname at it, as a wildcard record would.
func newRig(t *testing.T) *rig {
	t.Helper()
	return newRigOn(t, state.NewMemory())
}

// newRigOn is newRig over the store given (a test double wrapping the
// memory store interleaves with the gateway's reads).
func newRigOn(t *testing.T, store state.Store) *rig {
	t.Helper()
	t.Setenv(runtime.EnvFakeReadyDelay, "100ms")
	dir := t.TempDir()
	fake, err := runtime.NewFake(filepath.Join(dir, "world.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fake.Close)
	var gw *Gateway
	eng := engine.New(engine.Options{Store: store, Runtime: fake, StateDir: dir, PollInterval: 20 * time.Millisecond,
		Address: func() (string, int) { return gw.Address() }})
	// Stopped before the temporary directory it writes into is removed:
	// a lab's create and a verify are jobs the engine launches, and they
	// outlive the test body that started them.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := eng.Shutdown(ctx); err != nil {
			t.Errorf("the engine did not stop before its directory was removed: %v", err)
		}
	})
	authSvc := auth.NewService(store, filepath.Join(dir, "auth.json"))
	if err := authSvc.SetOperator("jross", "correct horse battery", false, auth.MechanismSocket); err != nil {
		t.Fatal(err)
	}
	apiSrv := api.New(api.Options{Engine: eng, Auth: authSvc, Address: func() (string, int) { return gw.Address() }})
	gw = New(Options{API: apiSrv, Engine: eng, Assets: podaro.ConsoleAssets()})
	srv := httptest.NewUnstartedServer(gw)
	srv.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	gw.SetAddress(domain, port)
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // httptest certificate
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return net.Dial(network, srv.Listener.Addr().String())
			},
		},
	}
	r := &rig{t: t, st: store, gw: gw, srv: srv, port: port, eng: eng, auth: authSvc, client: client}
	sess, err := authSvc.Login("203.0.113.9", "jross", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	r.cookie, _ = authSvc.CookieValue(sess)
	return r
}

func (r *rig) get(host, path string, hdr map[string]string) *http.Response {
	r.t.Helper()
	return r.do(http.MethodGet, host, path, hdr, "")
}

func (r *rig) do(method, host, path string, hdr map[string]string, payload string) *http.Response {
	r.t.Helper()
	req, _ := http.NewRequest(method, fmt.Sprintf("https://%s:%d%s", host, r.port, path), strings.NewReader(payload))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		r.t.Fatalf("GET %s%s: %v", host, path, err)
	}
	return resp
}

func (r *rig) up(name string) {
	r.t.Helper()
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	job, err := r.eng.Create(context.Background(), engine.CreateRequest{Path: fixture, Name: name})
	if err != nil {
		r.t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if j, err := r.eng.Wait(ctx, job.ID); err != nil || j.State != state.JobSucceeded {
		r.t.Fatalf("up %s: %+v %v", name, j, err)
	}
}

func body(resp *http.Response) string {
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// The host router: apex and instance consoles answer with the console's
// security headers; anything else is dropped without a response.
func TestRoutingAndDrop(t *testing.T) {
	r := newRig(t)
	resp := r.get(domain, "/login", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("login page: %d", resp.StatusCode)
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "frame-src https://*."+domain+":"+strconv.Itoa(r.port)) {
		t.Fatalf("console CSP: %q", csp)
	}
	// Byte for byte, not merely containing the directives that matter:
	// the console's theme (plan S12) is applied by an external script
	// and styled by the stylesheet precisely because nothing may loosen
	// this policy, and a loosening that kept the three directives above
	// would have passed the check above.
	if want := "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-src https://*." + domain + ":" + strconv.Itoa(r.port) + "; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"; csp != want {
		t.Fatalf("console CSP changed:\n got %q\nwant %q", csp, want)
	}
	if resp.Header.Get("Strict-Transport-Security") == "" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("security headers: %v", resp.Header)
	}
	if !strings.Contains(body(resp), `name="password"`) {
		t.Fatal("login form missing")
	}
	resp = r.get(domain, "/", nil)
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/login" {
		t.Fatalf("unauthenticated home: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp = r.get(domain, "/", map[string]string{"Cookie": auth.CookieName + "=" + r.cookie})
	home := body(resp)
	if resp.StatusCode != 200 || !strings.Contains(home, "No instances yet") {
		t.Fatalf("home empty state: %d", resp.StatusCode)
	}
	// The asset URLs' cache key is the bundle's content revision, never
	// the release number: assets are served for a day, and an in-place
	// upgrade of a dev build changes the bundles without changing the
	// number, which left new markup running against the old script.
	if !strings.Contains(home, `/assets/console.js?v=`+podaro.ConsoleRevision()+`"`) || strings.Contains(home, `?v=`+podaro.Version()+`"`) {
		t.Fatalf("asset cache key: want ?v=%s (the bundle's revision), not the release number %s", podaro.ConsoleRevision(), podaro.Version())
	}
	resp = r.get(domain, "/assets/console.css", nil)
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "text/css") {
		t.Fatalf("asset: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	body(resp)
	for _, host := range []string{"nope." + domain, "deep.x." + domain, "other.example", "db-nope." + domain} {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s:%d/", host, r.port), nil)
		if resp, err := r.client.Do(req); err == nil {
			t.Errorf("%s answered %d instead of dropping", host, resp.StatusCode)
			resp.Body.Close()
		}
	}
}

// Product vhosts: session required (browser navigations bounce to the
// apex login with next=; API clients get 401), framing headers rewritten
// to the instance console, Host and forwarding headers set.
func TestProductVhost(t *testing.T) {
	r := newRig(t)
	r.up("t1")
	vhost := "web-t1." + domain
	resp := r.get(vhost, "/", nil)
	if resp.StatusCode != 401 {
		t.Fatalf("anonymous API client: %d", resp.StatusCode)
	}
	body(resp)
	resp = r.get(vhost, "/x", map[string]string{"Accept": "text/html"})
	loc := resp.Header.Get("Location")
	if resp.StatusCode != 302 || !strings.HasPrefix(loc, fmt.Sprintf("https://%s:%d/login?next=", domain, r.port)) || !strings.Contains(loc, "web-t1") {
		t.Fatalf("anonymous browser: %d %s", resp.StatusCode, loc)
	}
	resp = r.get(vhost, "/hello", map[string]string{"Cookie": auth.CookieName + "=" + r.cookie})
	if resp.StatusCode != 200 {
		t.Fatalf("proxied: %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Frame-Options") != "" {
		t.Error("X-Frame-Options not stripped")
	}
	if want := fmt.Sprintf("frame-ancestors https://t1.%s:%d", domain, r.port); !strings.Contains(resp.Header.Get("Content-Security-Policy"), want) {
		t.Errorf("CSP not rewritten: %q", resp.Header.Get("Content-Security-Policy"))
	}
	if got := resp.Header.Get("X-Fake-Host"); got != fmt.Sprintf("%s:%d", vhost, r.port) {
		t.Errorf("Host not preserved: %q", got)
	}
	if resp.Header.Get("X-Fake-Forwarded-Proto") != "https" || resp.Header.Get("X-Fake-Forwarded-For") == "" {
		t.Errorf("forwarding headers: %v", resp.Header)
	}
	if !strings.Contains(body(resp), "path /hello") {
		t.Error("path not proxied")
	}
	// The instance's own console renders its ladder.
	resp = r.get("t1."+domain, "/", map[string]string{"Cookie": auth.CookieName + "=" + r.cookie})
	if b := body(resp); resp.StatusCode != 200 || !strings.Contains(b, `<span class="instance-name">t1</span>`) || !strings.Contains(b, "healthy") {
		t.Fatalf("instance console: %d", resp.StatusCode)
	}
	// A bearer token reaches the product too (scripts driving a product API).
	secret, _, _ := r.auth.CreateToken("ci", auth.ScopeRead, "jross", auth.MechanismSocket)
	resp = r.get(vhost, "/", map[string]string{"Authorization": "Bearer " + secret})
	if resp.StatusCode != 200 {
		t.Fatalf("bearer on product vhost: %d", resp.StatusCode)
	}
	body(resp)
	// An instance-bound session (API §2.4, S9) is refused on other hosts.
	sess := &state.Session{ID: "s-alice", Subject: "alice", Mechanism: "instance-access", Instance: "other", CSRF: "c", Created: time.Now(), LastSeen: time.Now(), Expires: time.Now().Add(time.Hour)}
	_ = r.st.PutSession(*sess)
	c, _ := r.auth.CookieValue(sess)
	resp = r.get(vhost, "/", map[string]string{"Cookie": auth.CookieName + "=" + c})
	if resp.StatusCode != 403 || !strings.Contains(body(resp), "PDR-E311") {
		t.Fatalf("instance-bound session on another instance: %d", resp.StatusCode)
	}
	resp = r.get(domain, "/", map[string]string{"Cookie": auth.CookieName + "=" + c})
	if resp.StatusCode != 403 {
		t.Fatalf("instance-bound session on the operator console: %d", resp.StatusCode)
	}
	body(resp)
}

// WebSocket upgrades pass through the proxy: the 101 comes back and bytes
// flow both ways on the hijacked connection.
func TestWebSocketUpgradeThroughGateway(t *testing.T) {
	r := newRig(t)
	r.up("t1")
	conn, err := tls.Dial("tcp", r.srv.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, ServerName: "web-t1." + domain, NextProtos: []string{"http/1.1"}}) //nolint:gosec // httptest certificate
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: web-t1.%s:%d\r\nCookie: %s=%s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", domain, r.port, auth.CookieName, r.cookie)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get("X-Fake-Upgrade") == "" {
		t.Fatalf("upgrade: %d %v", resp.StatusCode, resp.Header)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping-through-the-gateway")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := br.Read(buf)
	if err != nil || string(buf[:n]) != "ping-through-the-gateway" {
		t.Fatalf("echo: %q %v", buf[:n], err)
	}
}

func TestRewriteFrameHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("X-Frame-Options", "DENY")
	h.Add("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; img-src *")
	h.Add("Content-Security-Policy", "frame-ancestors 'self'")
	h.Set("Content-Security-Policy-Report-Only", "frame-ancestors 'none'")
	h.Set("Set-Cookie", "app=1")
	RewriteFrameHeaders(h, "https://pii-lab.lab.example.com:8443")
	if h.Get("X-Frame-Options") != "" {
		t.Error("X-Frame-Options survived")
	}
	got := h.Values("Content-Security-Policy")
	if len(got) != 2 || got[0] != "default-src 'self'; frame-ancestors https://pii-lab.lab.example.com:8443; img-src *" || got[1] != "frame-ancestors https://pii-lab.lab.example.com:8443" {
		t.Errorf("CSP: %q", got)
	}
	if h.Get("Content-Security-Policy-Report-Only") != "frame-ancestors https://pii-lab.lab.example.com:8443" {
		t.Errorf("report-only: %q", h.Get("Content-Security-Policy-Report-Only"))
	}
	if h.Get("Set-Cookie") != "app=1" {
		t.Error("unrelated headers must pass untouched")
	}
	// A policy without the directive, or no policy at all, would leave the
	// product frameable by any origin once X-Frame-Options is gone: the
	// directive is added. A report-only policy is
	// rewritten, never invented.
	h2 := http.Header{"Content-Security-Policy": {"default-src 'self'"}}
	RewriteFrameHeaders(h2, "x")
	if h2.Get("Content-Security-Policy") != "default-src 'self'; frame-ancestors x" {
		t.Errorf("CSP without frame-ancestors must gain one: %q", h2.Get("Content-Security-Policy"))
	}
	h3 := http.Header{"X-Frame-Options": {"DENY"}}
	RewriteFrameHeaders(h3, "x")
	if h3.Get("Content-Security-Policy") != "frame-ancestors x" || h3.Get("X-Frame-Options") != "" {
		t.Errorf("no CSP at all must become frame-ancestors: %v", h3)
	}
	h4 := http.Header{"Content-Security-Policy-Report-Only": {"default-src 'self'"}}
	RewriteFrameHeaders(h4, "x")
	if h4.Get("Content-Security-Policy") != "frame-ancestors x" || h4.Get("Content-Security-Policy-Report-Only") != "default-src 'self'" {
		t.Errorf("report-only is not enforcement: %v", h4)
	}
}

// The gateway's own credentials never reach a product (threat model
// B3): the session cookie and a Podaro bearer are stripped from the
// proxied request, while the product's own cookies and any other
// Authorization scheme pass — and a foreign Authorization header does
// not stop the session cookie from authenticating the request.
func TestProductVhostNeverSeesGatewayCredentials(t *testing.T) {
	r := newRig(t)
	r.up("t1")
	vhost := "web-t1." + domain
	resp := r.get(vhost, "/", map[string]string{"Cookie": "app=1; " + auth.CookieName + "=" + r.cookie + "; theme=dark"})
	if resp.StatusCode != 200 {
		t.Fatalf("proxied: %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Fake-Cookie"); got != "app=1; theme=dark" {
		t.Errorf("the product saw cookies %q; want only its own", got)
	}
	body(resp)
	secret, _, _ := r.auth.CreateToken("ci", auth.ScopeRead, "jross", auth.MechanismSocket)
	resp = r.get(vhost, "/", map[string]string{"Authorization": "Bearer " + secret})
	if resp.StatusCode != 200 {
		t.Fatalf("bearer: %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Fake-Authorization"); got != "" {
		t.Errorf("the product saw the Podaro bearer: %q", got)
	}
	body(resp)
	resp = r.get(vhost, "/", map[string]string{"Cookie": auth.CookieName + "=" + r.cookie, "Authorization": "Basic Zm9vOmJhcg=="})
	if resp.StatusCode != 200 {
		t.Fatalf("session beside a product's own Authorization: %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Fake-Authorization"); got != "Basic Zm9vOmJhcg==" {
		t.Errorf("the product's own Authorization must pass: %q", got)
	}
	if got := resp.Header.Get("X-Fake-Cookie"); got != "" {
		t.Errorf("the session cookie leaked: %q", got)
	}
	body(resp)
}

// A bring-your-own certificate must cover the apex as well as the
// wildcard: the console lives at <domain>, and *.<domain> does not
// include it.
func TestApplyRefusesACertificateWithoutTheApex(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeSelfSigned(t, dir, []string{"*." + domain}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	gw := New(Options{API: api.New(api.Options{}), Engine: engine.New(engine.Options{Store: state.NewMemory()}), Assets: podaro.ConsoleAssets()})
	defer gw.Close()
	cfg := &config.Config{Domain: domain, Gateway: config.Gateway{Port: port}, TLS: &config.TLS{CertFile: certFile, KeyFile: keyFile}}
	_, err := gw.Apply(cfg, filepath.Join(dir, "state"))
	var pe *pdr.Error
	if !errors.As(err, &pe) || pe.Code != pdr.CodeGatewayBind || !strings.Contains(pe.Cause, domain+" is not covered") {
		t.Fatalf("a wildcard-only certificate must be refused naming the apex: %v", err)
	}
	if gw.Status().Listening {
		t.Fatal("the gateway must not listen behind a certificate that cannot serve the console")
	}
}

// Apply opens a real listener from configuration, issues the managed leaf
// when none exists, swaps the certificate in place on re-apply, renews
// inside the window, and closes when the domain goes away.
func TestApplyListensAndRenews(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	if _, _, err := tlsca.EnsureCA(tlsca.NewPaths(stateDir), now); err != nil {
		t.Fatal(err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	clock := now
	gw := New(Options{API: api.New(api.Options{}), Engine: engine.New(engine.Options{Store: state.NewMemory()}), Assets: podaro.ConsoleAssets(), Now: func() time.Time { return clock }})
	defer gw.Close()
	cfg := &config.Config{Domain: domain, Gateway: config.Gateway{Port: port}}
	st, err := gw.Apply(cfg, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Listening || st.Certificate != "local-ca" || st.Address != ":"+strconv.Itoa(port) || st.Domain != domain {
		t.Fatalf("status: %+v", st)
	}
	exp1, _ := time.Parse(time.RFC3339, st.Expires)
	if d := exp1.Sub(now); d < 360*24*time.Hour || d > tlsca.MaxLeafValidity {
		t.Fatalf("leaf validity %s", d)
	}
	if d, p := gw.Address(); d != domain || p != port {
		t.Fatalf("address: %s %d", d, p)
	}
	// Really listening, with the leaf, HTTP/1.1 only, refusing foreign names.
	conn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port), &tls.Config{InsecureSkipVerify: true, ServerName: "x." + domain, NextProtos: []string{"h2", "http/1.1"}}) //nolint:gosec // self-issued
	if err != nil {
		t.Fatal(err)
	}
	if cs := conn.ConnectionState(); cs.NegotiatedProtocol != "http/1.1" || cs.PeerCertificates[0].Subject.CommonName != "*."+domain {
		t.Fatalf("negotiated %q with %s", cs.NegotiatedProtocol, cs.PeerCertificates[0].Subject.CommonName)
	}
	conn.Close()
	if _, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port), &tls.Config{InsecureSkipVerify: true, ServerName: "evil.example"}); err == nil { //nolint:gosec // negative test
		t.Fatal("handshake for a foreign server name must fail")
	}
	// Re-apply on the same port keeps the listener (no bind race).
	if st2, err := gw.Apply(cfg, stateDir); err != nil || !st2.Listening {
		t.Fatalf("re-apply: %+v %v", st2, err)
	}
	// Renewal inside the window.
	if renewed, err := gw.RenewIfDue(now.Add(24 * time.Hour)); err != nil || renewed {
		t.Fatalf("early renewal: %v %v", renewed, err)
	}
	clock = now.Add(350 * 24 * time.Hour)
	renewed, err := gw.RenewIfDue(clock)
	if err != nil || !renewed {
		t.Fatalf("renewal due: %v %v", renewed, err)
	}
	exp2, _ := time.Parse(time.RFC3339, gw.Status().Expires)
	if !exp2.After(exp1) {
		t.Fatalf("expiry did not move: %s → %s", exp1, exp2)
	}
	// Domain removed → closed.
	if st3, err := gw.Apply(&config.Config{Gateway: config.Gateway{Port: port}}, stateDir); err != nil || st3.Listening {
		t.Fatalf("close: %+v %v", st3, err)
	}
	if _, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 200*time.Millisecond); err == nil {
		t.Fatal("port still open after the domain was removed")
	}
	// No CA → E023 with the setup next line.
	if _, err := gw.Apply(cfg, filepath.Join(dir, "nowhere")); err == nil || !strings.Contains(err.Error(), "PDR-E023") {
		t.Fatalf("missing CA: %v", err)
	}
}

// A renewal and a setup never observe two generations of the certificate
// set: they share one lock. A renewal that finds it held leaves the leaf
// in place and comes back at the next tick — a swap landing between the
// issue and the read would otherwise put the candidate's leaf, for
// another domain, into a listener still serving this one. And a set that
// changed anyway is never installed: what was read must serve this
// gateway's domain.
func TestARenewalNeverObservesTwoGenerations(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	if _, _, err := tlsca.EnsureCA(tlsca.NewPaths(stateDir), now); err != nil {
		t.Fatal(err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	clock := now
	gw := New(Options{API: api.New(api.Options{}), Engine: engine.New(engine.Options{Store: state.NewMemory()}), Assets: podaro.ConsoleAssets(), Now: func() time.Time { return clock }})
	defer gw.Close()
	if _, err := gw.Apply(&config.Config{Domain: domain, Gateway: config.Gateway{Port: port}}, stateDir); err != nil {
		t.Fatal(err)
	}
	before := gw.Status().Fingerprint
	due := now.Add(350 * 24 * time.Hour)
	// A setup holds the lock: the renewal stands aside entirely.
	unlock, err := tlsca.Lock(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if renewed, err := gw.RenewIfDue(due); err != nil || renewed {
		t.Fatalf("a renewal must stand aside while the set is being changed: %v %v", renewed, err)
	}
	if got := gw.Status().Fingerprint; got != before {
		t.Fatalf("the leaf in place must keep serving: %s → %s", before, got)
	}
	unlock()
	// The lock free, the next tick renews.
	if renewed, err := gw.RenewIfDue(due); err != nil || !renewed {
		t.Fatalf("renewal due: %v %v", renewed, err)
	}
	renewedPrint := gw.Status().Fingerprint
	if renewedPrint == before {
		t.Fatal("the leaf did not change")
	}
	// A set that changed anyway — a restore by hand, another generation
	// left in place — is never installed over the leaf that serves.
	otherState := filepath.Join(dir, "other")
	otherPaths := tlsca.NewPaths(otherState)
	ca, _, err := tlsca.EnsureCA(otherPaths, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.IssueWildcard(otherPaths, "other.test", tlsca.LeafValidity, now); err != nil {
		t.Fatal(err)
	}
	gw.certFile, gw.keyFile = otherPaths.LeafCert(), otherPaths.LeafKey()
	if renewed, err := gw.RenewIfDue(due.Add(350 * 24 * time.Hour)); renewed || err == nil || !strings.Contains(err.Error(), "changed under the renewal") {
		t.Fatalf("another domain's leaf must never be installed: %v %v", renewed, err)
	}
	if got := gw.Status().Fingerprint; got != renewedPrint {
		t.Fatalf("the leaf that serves must stand: %s → %s", renewedPrint, got)
	}
}

// writeSelfSigned writes a self-signed server certificate and its key
// for the given names and validity window.
func writeSelfSigned(t *testing.T, dir string, dnsNames []string, notBefore, notAfter time.Time) (certFile, keyFile string) {
	t.Helper()
	return writeSelfSignedFor(t, dir, dnsNames, notBefore, notAfter, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

// writeSelfSignedFor is writeSelfSigned with an explicit extended key usage.
func writeSelfSignedFor(t *testing.T, dir string, dnsNames []string, notBefore, notAfter time.Time, eku []x509.ExtKeyUsage) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: dnsNames[0]}, DNSNames: dnsNames,
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: eku,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile = filepath.Join(dir, "byo.crt"), filepath.Join(dir, "byo.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// A bring-your-own certificate outside its validity window is refused
// naming the boundary — never stored and reported listening while every
// browser refuses the handshake.
func TestApplyRefusesACertificateOutsideItsValidity(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		name                string
		notBefore, notAfter time.Time
		want                string
	}{
		{"expired", now.Add(-48 * time.Hour), now.Add(-24 * time.Hour), "expired at"},
		{"not yet valid", now.Add(24 * time.Hour), now.Add(48 * time.Hour), "not valid before"},
	} {
		dir := t.TempDir()
		certFile, keyFile := writeSelfSigned(t, dir, []string{domain, "*." + domain}, c.notBefore, c.notAfter)
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		port := l.Addr().(*net.TCPAddr).Port
		l.Close()
		gw := New(Options{API: api.New(api.Options{}), Engine: engine.New(engine.Options{Store: state.NewMemory()}), Assets: podaro.ConsoleAssets()})
		cfg := &config.Config{Domain: domain, Gateway: config.Gateway{Port: port}, TLS: &config.TLS{CertFile: certFile, KeyFile: keyFile}}
		_, err := gw.Apply(cfg, filepath.Join(dir, "state"))
		var pe *pdr.Error
		if !errors.As(err, &pe) || pe.Code != pdr.CodeGatewayBind || !strings.Contains(pe.Cause, c.want) {
			t.Errorf("%s certificate: want E024 naming %q, got %v", c.name, c.want, err)
		}
		if gw.Status().Listening {
			t.Errorf("%s certificate: the gateway must not listen", c.name)
		}
		gw.Close()
	}
}

// A product's Set-Cookie for the gateway's own cookie name never reaches
// the browser; its other cookies do.
func TestProductSetCookieForTheSessionNameIsDropped(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "PODARO_SESSION=evil; Domain=lab.test; Path=/")
	h.Add("Set-Cookie", "app=1; Path=/")
	h.Add("Set-Cookie", " podaro_session =evil2")
	h.Add("Set-Cookie", "theme=dark")
	stripGatewayCookies(h)
	if got := h.Values("Set-Cookie"); len(got) != 2 || got[0] != "app=1; Path=/" || got[1] != "theme=dark" {
		t.Fatalf("Set-Cookie after the strip: %q", got)
	}
	r := newRig(t)
	r.up("t1")
	resp := r.get("web-t1."+domain, "/", map[string]string{"Cookie": auth.CookieName + "=" + r.cookie, "X-Fake-Set-Cookie": "1"})
	body(resp)
	if resp.StatusCode != 200 {
		t.Fatalf("proxied: %d", resp.StatusCode)
	}
	var names []string
	for _, c := range resp.Cookies() {
		names = append(names, c.Name)
	}
	if len(names) != 1 || names[0] != "app" {
		t.Fatalf("cookies set through the gateway: %v; want only the product's own", names)
	}
}

// A reload binds the replacement before it drops the working listener:
// a port that turns out to be taken leaves the door open on the old
// port (E024 names both), and the move happens once the port is free.
func TestApplyKeepsTheWorkingDoorWhenTheNewPortIsTaken(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	if _, _, err := tlsca.EnsureCA(tlsca.NewPaths(stateDir), now); err != nil {
		t.Fatal(err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	portA := l.Addr().(*net.TCPAddr).Port
	l.Close()
	gw := New(Options{API: api.New(api.Options{}), Engine: engine.New(engine.Options{Store: state.NewMemory()}), Assets: podaro.ConsoleAssets(), Now: func() time.Time { return now }})
	defer gw.Close()
	if st, err := gw.Apply(&config.Config{Domain: domain, Gateway: config.Gateway{Port: portA}}, stateDir); err != nil || !st.Listening {
		t.Fatalf("first apply: %+v %v", st, err)
	}
	taken, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	portB := taken.Addr().(*net.TCPAddr).Port
	_, err = gw.Apply(&config.Config{Domain: domain, Gateway: config.Gateway{Port: portB}}, stateDir)
	var pe *pdr.Error
	if !errors.As(err, &pe) || pe.Code != pdr.CodeGatewayBind || !strings.Contains(pe.Cause, fmt.Sprintf("keeps serving on :%d", portA)) {
		t.Fatalf("a taken port must be E024 naming the door that stays: %v", err)
	}
	if st := gw.Status(); !st.Listening || st.Address != ":"+strconv.Itoa(portA) {
		t.Fatalf("the working door must stay exactly as it was: %+v", st)
	}
	conn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(portA), &tls.Config{InsecureSkipVerify: true, ServerName: "x." + domain}) //nolint:gosec // self-issued
	if err != nil {
		t.Fatalf("the old door must still answer: %v", err)
	}
	conn.Close()
	taken.Close()
	if st, err := gw.Apply(&config.Config{Domain: domain, Gateway: config.Gateway{Port: portB}}, stateDir); err != nil || !st.Listening || st.Address != ":"+strconv.Itoa(portB) {
		t.Fatalf("once the port is free the move happens: %+v %v", st, err)
	}
	if _, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(portA), 200*time.Millisecond); err == nil {
		t.Fatal("the old port must close after the move")
	}
}

// The hostname binding holds on the API path: an instance-bound session
// (API §2.4) is refused before dispatch on the apex and on another
// instance's host — it cannot mint a token there — and on its own host it
// reads but is never the operator.
func TestInstanceBoundSessionIsRefusedOnTheAPIPath(t *testing.T) {
	r := newRig(t)
	r.up("t1")
	bound := func(instance string) map[string]string {
		// The generation a join would have copied; a hand-built
		// instance-bound session without one is one no join could
		// produce.
		var gen int64
		if inst, err := r.st.GetInstance(instance); err == nil {
			gen = inst.AuditFrom
		}
		sess := &state.Session{ID: "s-" + instance, Subject: "alice", Mechanism: "instance-access", Instance: instance, Gen: gen, CSRF: "c-" + instance, Created: time.Now(), LastSeen: time.Now(), Expires: time.Now().Add(time.Hour)}
		if err := r.st.PutSession(*sess); err != nil {
			t.Fatal(err)
		}
		c, _ := r.auth.CookieValue(sess)
		return map[string]string{"Cookie": auth.CookieName + "=" + c, auth.CSRFHeader: sess.CSRF, "Content-Type": "application/json"}
	}
	other := bound("other")
	for _, host := range []string{domain, "t1." + domain} {
		resp := r.do(http.MethodPost, host, api.Prefix+"/auth/tokens", other, `{"name":"stolen","scope":"admin"}`)
		if b := body(resp); resp.StatusCode != 403 || !strings.Contains(b, "PDR-E311") {
			t.Fatalf("a session bound elsewhere on %s: %d %s", host, resp.StatusCode, b)
		}
	}
	if list, _ := r.auth.ListTokens(); len(list) != 0 {
		t.Fatalf("a token was minted through the wrong host: %+v", list)
	}
	own := bound("t1")
	resp := r.get("t1."+domain, api.Prefix+"/instances/t1", own)
	if resp.StatusCode != 200 {
		t.Fatalf("a bound session on its own host must read: %d", resp.StatusCode)
	}
	body(resp)
	resp = r.do(http.MethodPost, "t1."+domain, api.Prefix+"/auth/tokens", own, `{"name":"stolen","scope":"admin"}`)
	if b := body(resp); resp.StatusCode != 403 || !strings.Contains(b, "PDR-E304") {
		t.Fatalf("a bound session is never the operator: %d %s", resp.StatusCode, b)
	}
	if list, _ := r.auth.ListTokens(); len(list) != 0 {
		t.Fatalf("a token was minted by an instance-bound session: %+v", list)
	}
}

// A certificate whose extended key usage excludes server authentication
// is refused: browsers reject it for a server.
func TestApplyRefusesACertificateWithoutServerAuth(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeSelfSignedFor(t, dir, []string{domain, "*." + domain}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	gw := New(Options{API: api.New(api.Options{}), Engine: engine.New(engine.Options{Store: state.NewMemory()}), Assets: podaro.ConsoleAssets()})
	defer gw.Close()
	cfg := &config.Config{Domain: domain, Gateway: config.Gateway{Port: port}, TLS: &config.TLS{CertFile: certFile, KeyFile: keyFile}}
	_, err := gw.Apply(cfg, filepath.Join(dir, "state"))
	var pe *pdr.Error
	if !errors.As(err, &pe) || pe.Code != pdr.CodeGatewayBind || !strings.Contains(pe.Cause, "server authentication") {
		t.Fatalf("a client-only certificate must be refused naming the usage: %v", err)
	}
	if gw.Status().Listening {
		t.Fatal("the gateway must not listen behind a client-only certificate")
	}
}

// A reload never waits on the requests it is serving: the replaced
// listener drains after the gateway lock is released, so handlers that
// take the lock at entry finish and the drain completes at once — not at
// its full timeout with every reload that races a request.
func TestReloadDoesNotWaitOnHandlersHoldingTheLock(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	if _, _, err := tlsca.EnsureCA(tlsca.NewPaths(stateDir), now); err != nil {
		t.Fatal(err)
	}
	freePort := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	portA, portB := freePort(), freePort()
	gw := New(Options{API: api.New(api.Options{}), Engine: engine.New(engine.Options{Store: state.NewMemory()}), Assets: podaro.ConsoleAssets(), Now: func() time.Time { return now }})
	defer gw.Close()
	if st, err := gw.Apply(&config.Config{Domain: domain, Gateway: config.Gateway{Port: portA}}, stateDir); err != nil || !st.Listening {
		t.Fatalf("first apply: %+v %v", st, err)
	}
	// Traffic on the old door while the reload happens: every request a
	// fresh connection, so the drain is decided by the handlers alone.
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: domain}, //nolint:gosec // self-issued
	}}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var served int64
	var servedMu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/", portA), nil)
				req.Host = domain
				resp, err := client.Do(req)
				if err != nil {
					time.Sleep(5 * time.Millisecond)
					continue
				}
				io.Copy(io.Discard, resp.Body) //nolint:errcheck // draining
				resp.Body.Close()
				servedMu.Lock()
				served++
				servedMu.Unlock()
			}
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		servedMu.Lock()
		n := served
		servedMu.Unlock()
		if n >= 8 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	start := time.Now()
	st, err := gw.Apply(&config.Config{Domain: domain, Gateway: config.Gateway{Port: portB}}, stateDir)
	took := time.Since(start)
	close(stop)
	wg.Wait()
	if err != nil || !st.Listening || st.Address != ":"+strconv.Itoa(portB) {
		t.Fatalf("reload to a new port: %+v %v", st, err)
	}
	if took > 3*time.Second {
		t.Fatalf("the reload waited on its own handlers: %v", took)
	}
	conn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(portB), &tls.Config{InsecureSkipVerify: true, ServerName: domain}) //nolint:gosec // self-issued
	if err != nil {
		t.Fatalf("the new door must answer: %v", err)
	}
	conn.Close()
	if _, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(portA), 200*time.Millisecond); err == nil {
		t.Fatal("the old door must be closed after the move")
	}
}

// The console's polling slides the session through the gateway (API
// §2.2): the hostname binding check before dispatch does not count as
// use, so the API handler is the one that slides the record and the
// response re-issues the cookie with a fresh Max-Age.
func TestAPIPollingSlidesTheCookieThroughTheGateway(t *testing.T) {
	r := newRig(t)
	now := time.Now()
	r.auth.SetClock(func() time.Time { return now })
	hdr := map[string]string{"Cookie": auth.CookieName + "=" + r.cookie}
	sessionCookie := func(resp *http.Response) *http.Cookie {
		for _, c := range resp.Cookies() {
			if c.Name == auth.CookieName {
				return c
			}
		}
		return nil
	}
	resp := r.get(domain, api.Prefix+"/auth/session", hdr)
	body(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session over the gateway: %d", resp.StatusCode)
	}
	if c := sessionCookie(resp); c != nil {
		t.Fatalf("inside the login's minute nothing slides: %+v", c)
	}
	now = now.Add(2 * time.Minute)
	resp = r.get(domain, api.Prefix+"/auth/session", hdr)
	body(resp)
	c := sessionCookie(resp)
	if resp.StatusCode != http.StatusOK || c == nil || c.Value != r.cookie || c.MaxAge != int(auth.SessionIdle/time.Second) {
		t.Fatalf("the poll that slides the record must re-issue the cookie through the gateway: %d %+v", resp.StatusCode, c)
	}
	sess, err := r.auth.Peek(r.cookie)
	if err != nil || !sess.Expires.Equal(now.Add(auth.SessionIdle)) {
		t.Fatalf("the record slid with the poll: %+v %v", sess, err)
	}
}

// A Podaro bearer keeps its precedence on the binding check:
// a valid token beside a cookie bound to another instance is
// judged as the token — Authenticate's rule — never refused with E311
// for the cookie the client also holds; the cookie alone still is.
func TestBearerPrecedenceHoldsOnTheBindingCheck(t *testing.T) {
	r := newRig(t)
	r.up("t1")
	sess := &state.Session{ID: "s-other", Subject: "alice", Mechanism: "instance-access", Instance: "other", CSRF: "c-other", Created: time.Now(), LastSeen: time.Now(), Expires: time.Now().Add(time.Hour)}
	if err := r.st.PutSession(*sess); err != nil {
		t.Fatal(err)
	}
	bound, _ := r.auth.CookieValue(sess)
	secret, _, err := r.auth.CreateToken("ci", auth.ScopeAdmin, "jross", auth.MechanismSocket)
	if err != nil {
		t.Fatal(err)
	}
	hdr := map[string]string{"Cookie": auth.CookieName + "=" + bound, "Authorization": "Bearer " + secret, "Content-Type": "application/json"}
	resp := r.do(http.MethodPost, domain, api.Prefix+"/auth/tokens", hdr, `{"name":"made","scope":"read"}`)
	if b := body(resp); resp.StatusCode != http.StatusCreated || !strings.Contains(b, `"made"`) {
		t.Fatalf("the bearer is the credential, whatever cookie rides beside it: %d %s", resp.StatusCode, b)
	}
	resp = r.get(domain, api.Prefix+"/instances", map[string]string{"Cookie": auth.CookieName + "=" + bound})
	if b := body(resp); resp.StatusCode != 403 || !strings.Contains(b, "PDR-E311") {
		t.Fatalf("the bound cookie alone is refused where it does not belong: %d %s", resp.StatusCode, b)
	}
}

// A publish interrupted between its two renames is completed before the
// managed set is read: a live set left aside is
// moved back and the gateway opens with it, never a start without its
// certificate.
func TestApplyRecoversAnInterruptedPublish(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	paths := tlsca.NewPaths(stateDir)
	ca, _, err := tlsca.EnsureCA(paths, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.IssueWildcard(paths, domain, tlsca.LeafValidity, now); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(paths.Dir, paths.Dir+".previous"); err != nil {
		t.Fatal(err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	gw := New(Options{API: api.New(api.Options{}), Engine: engine.New(engine.Options{Store: state.NewMemory()}), Assets: podaro.ConsoleAssets(), Now: func() time.Time { return now }})
	defer gw.Close()
	st, err := gw.Apply(&config.Config{Domain: domain, Gateway: config.Gateway{Port: port}}, stateDir)
	if err != nil || !st.Listening || st.Certificate != "local-ca" {
		t.Fatalf("the gateway must open with the recovered set: %+v %v", st, err)
	}
	if _, err := os.Stat(paths.CACert()); err != nil {
		t.Fatalf("the set must be back in place: %v", err)
	}
	if _, err := os.Stat(paths.Dir + ".previous"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("nothing may be left aside")
	}
}

// withdrawOnRead is a store whose next read of an instance's services,
// once armed, hands the rows back as they were and withdraws their
// routes underneath: the withdrawal lands the moment after a reader took
// its copy.
type withdrawOnRead struct {
	state.Store
	mu    sync.Mutex
	armed bool
	fired int
}

func (w *withdrawOnRead) ListServices(instance string) ([]state.Service, error) {
	rows, err := w.Store.ListServices(instance)
	if err != nil {
		return rows, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.armed {
		return rows, nil
	}
	w.armed, w.fired = false, w.fired+1
	for _, row := range rows {
		row.Ports = nil
		if err := w.Store.PutService(row); err != nil {
			return nil, err
		}
	}
	return rows, nil
}

// A connection never follows a route read before its withdrawal (S5
// Review round 13): the row the gateway classified the request from is a
// copy, and a destroy can withdraw the route — and free the host port
// for another lab's container — while the request is between its
// classification and its connection. The port is resolved by the engine
// when the connection is opened, under the withdrawal's lock, so the
// request finds the service gone rather than whatever holds the port.
func TestAConnectionNeverFollowsARouteReadBeforeItsWithdrawal(t *testing.T) {
	w := &withdrawOnRead{Store: state.NewMemory()}
	r := newRigOn(t, w)
	r.up("t1")
	w.mu.Lock()
	w.armed = true
	w.mu.Unlock()
	resp := r.get("web-t1."+domain, "/hello", map[string]string{"Cookie": auth.CookieName + "=" + r.cookie})
	b := body(resp)
	w.mu.Lock()
	fired := w.fired
	w.mu.Unlock()
	if fired != 1 {
		t.Fatalf("the withdrawal must land after the gateway read the row: fired %d", fired)
	}
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(b, "is not up yet") {
		t.Fatalf("a route withdrawn after it was read must not be connected: %d %s", resp.StatusCode, b)
	}
}

// The login page's redirect of a signed-in visitor re-issues a slid
// cookie: the visit counts as use — it slides the
// record and restarts the touch throttle's minute — so the pages it
// leads to would not re-issue, and the browser's copy could expire under
// an active user. Inside the login's minute nothing slides and nothing
// is re-issued; two minutes on, the redirect carries the fresh cookie.
func TestTheLoginPageRedirectReissuesASlidCookie(t *testing.T) {
	r := newRig(t)
	now := time.Now()
	r.auth.SetClock(func() time.Time { return now })
	hdr := map[string]string{"Cookie": auth.CookieName + "=" + r.cookie}
	sessionCookie := func(resp *http.Response) *http.Cookie {
		for _, c := range resp.Cookies() {
			if c.Name == auth.CookieName {
				return c
			}
		}
		return nil
	}
	resp := r.get(domain, "/login", hdr)
	body(resp)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("a signed-in visitor is sent home: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if c := sessionCookie(resp); c != nil {
		t.Fatalf("inside the login's minute nothing slides: %+v", c)
	}
	now = now.Add(2 * time.Minute)
	resp = r.get(domain, "/login", hdr)
	body(resp)
	c := sessionCookie(resp)
	if resp.StatusCode != http.StatusFound || c == nil || c.Value != r.cookie || c.MaxAge != int(auth.SessionIdle/time.Second) {
		t.Fatalf("the redirect that slid the record must re-issue the cookie: %d %+v", resp.StatusCode, c)
	}
	sess, err := r.auth.Peek(r.cookie)
	if err != nil || !sess.Expires.Equal(now.Add(auth.SessionIdle)) {
		t.Fatalf("the record slid with the visit: %+v %v", sess, err)
	}
}

// A previous certificate set beside the live one survives a reload (S5
// Review round 16): it is a running setup's way back on the two-rename
// path, and the reload is that setup's next step — a reload that fails
// must still leave it for the rollback. The gateway completes an
// interrupted swap but removes nothing.
func TestApplyKeepsAPreviousSetBesideTheLiveOne(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	paths := tlsca.NewPaths(stateDir)
	ca, _, err := tlsca.EnsureCA(paths, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.IssueWildcard(paths, domain, tlsca.LeafValidity, now); err != nil {
		t.Fatal(err)
	}
	previous := tlsca.Paths{Dir: paths.Dir + ".previous"}
	old, _, err := tlsca.EnsureCA(previous, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.IssueWildcard(previous, "old."+domain, tlsca.LeafValidity, now); err != nil {
		t.Fatal(err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	gw := New(Options{API: api.New(api.Options{}), Engine: engine.New(engine.Options{Store: state.NewMemory()}), Assets: podaro.ConsoleAssets(), Now: func() time.Time { return now }})
	defer gw.Close()
	st, err := gw.Apply(&config.Config{Domain: domain, Gateway: config.Gateway{Port: port}}, stateDir)
	if err != nil || !st.Listening {
		t.Fatalf("the gateway must open with the live set: %+v %v", st, err)
	}
	if _, leaf, err := tlsca.LoadLeaf(previous.LeafCert(), previous.LeafKey()); err != nil || leaf.DNSNames[1] != "old."+domain {
		t.Fatalf("the previous set must survive the reload for the rollback: %v", err)
	}
}

// A ui endpoint on a scheme the proxy cannot reach gets no hostname (S5
// Review round 16): lab validate refuses a tcp ui endpoint, and a row
// carrying one anyway is not routed — the host is dropped like any
// unknown one, never proxied to a target every request would fail on.
func TestAUIEndpointOnAnotherSchemeGetsNoRoute(t *testing.T) {
	r := newRig(t)
	r.up("t1")
	rows, _ := r.st.ListServices("t1")
	if len(rows) != 1 {
		t.Fatalf("one service expected: %+v", rows)
	}
	row := rows[0]
	row.UIScheme = "tcp"
	if err := r.st.PutService(row); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://web-t1.%s:%d/", domain, r.port), nil)
	req.Header.Set("Cookie", auth.CookieName+"="+r.cookie)
	resp, err := r.client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		t.Fatalf("a tcp ui endpoint must get no route (the host dropped), got %d", resp.StatusCode)
	}
}

// A managed leaf the CA in place did not sign is re-issued, never
// served: a partial restore can leave a matching ca.crt/ca.key pair
// beside a leaf the CA before it signed — inside its validity, covering
// the domain, and refused by every client that trusts this ca.crt (S5
// Review round 22).
func TestApplyReissuesALeafFromAnotherCA(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	paths := tlsca.NewPaths(stateDir)
	foreign, _, err := tlsca.EnsureCA(paths, now)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := foreign.IssueWildcard(paths, domain, tlsca.LeafValidity, now)
	if err != nil {
		t.Fatal(err)
	}
	// The restore puts another CA's pair in place; the leaf stays.
	restored := tlsca.NewPaths(filepath.Join(t.TempDir(), "state"))
	ca, _, err := tlsca.EnsureCA(restored, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range [][2]string{{restored.CACert(), paths.CACert()}, {restored.CAKey(), paths.CAKey()}} {
		raw, err := os.ReadFile(f[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f[1], raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if stale.CheckSignatureFrom(ca.Cert) == nil {
		t.Fatal("precondition: the leaf must be the other CA's")
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	gw := New(Options{API: api.New(api.Options{}), Engine: engine.New(engine.Options{Store: state.NewMemory()}), Assets: podaro.ConsoleAssets(), Now: func() time.Time { return now }})
	defer gw.Close()
	st, err := gw.Apply(&config.Config{Domain: domain, Gateway: config.Gateway{Port: port}}, stateDir)
	if err != nil || !st.Listening {
		t.Fatalf("the gateway must open: %+v %v", st, err)
	}
	_, leaf, err := tlsca.LoadLeaf(paths.LeafCert(), paths.LeafKey())
	if err != nil {
		t.Fatal(err)
	}
	if leaf.SerialNumber.Cmp(stale.SerialNumber) == 0 {
		t.Fatal("the leaf the CA in place did not sign must be re-issued")
	}
	if err := leaf.CheckSignatureFrom(ca.Cert); err != nil {
		t.Fatalf("the leaf served must be this CA's: %v", err)
	}
	if st.Fingerprint != tlsca.Fingerprint(leaf) {
		t.Fatalf("the posture must report the re-issued leaf: %s", st.Fingerprint)
	}
}

// An idle keep-alive connection to a product is reused without dialling,
// so the route is judged again before every round trip: a request
// arriving after a withdrawal — a destroy, a stale container being
// replaced — is refused rather than riding the pooled connection to the
// container that is going.
func TestAPooledConnectionIsJudgedAgainstTheRoute(t *testing.T) {
	r := newRig(t)
	r.up("t1")
	vhost := "web-t1." + domain
	head := map[string]string{"Cookie": auth.CookieName + "=" + r.cookie}
	resp := r.get(vhost, "/", head)
	if resp.StatusCode != 200 {
		t.Fatalf("proxied: %d", resp.StatusCode)
	}
	body(resp) // read to completion: the upstream connection returns to the pool
	// The route is withdrawn as a destroy withdraws it, the container
	// still running and still answering on its port.
	rows, err := r.st.ListServices("t1")
	if err != nil || len(rows) != 1 || rows[0].Ports[rows[0].UIPort] == 0 {
		t.Fatalf("precondition: the route stands: %+v %v", rows, err)
	}
	row := rows[0]
	row.Ports = nil
	if err := r.st.PutService(row); err != nil {
		t.Fatal(err)
	}
	resp = r.get(vhost, "/", head)
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(body(resp), "not up yet") {
		t.Fatalf("a withdrawn route must not be proxied over a pooled connection: %d", resp.StatusCode)
	}
}
