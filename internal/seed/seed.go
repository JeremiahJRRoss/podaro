// SPDX-License-Identifier: AGPL-3.0-only

// Package seed is the built-in generator framework (plan S6; spec 0003
// §4; Spec 0002 §5): named deterministic data injections whose every
// random choice derives from the engine's seed_value, delivered to a
// service's declared endpoint on the host's loopback. The built-ins are
// http-requests (the small template's seed) and web-logs, whose
// newline-delimited JSON delivery (deliver) is the one every event
// generator shares. The two generators plan S8 added for the golden lab
// were retired with it on 2026-09-23 (the reconciliation plan's R2).
package seed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/wire"
)

// Resolver maps a service's container port to its loopback address.
type Resolver interface {
	Resolve(service string, port int) (string, error)
	// Dial connects to that address for one request, verifying the live
	// container around the dial as the gateway's route does (verify.Target says why).
	Dial(ctx context.Context, service string, port int) (net.Conn, error)
	// Endpoint returns a service's declared endpoint port for a purpose
	// ("" for the first declared) and whether it has one.
	Endpoint(service, purpose string) (port int, scheme string, ok bool)
}

// Run is one seed run's input.
type Run struct {
	Instance  string
	Name      string
	Generator string
	Count     int
	Params    map[string]any
	SeedValue string
	// Epoch anchors every timestamp a generator writes: the instance's
	// creation instant, so a re-pressed or reset-replayed seed sends the
	// very same events (Spec 0002 §5: same instance, same seed, same
	// payload). Zero derives an anchor from the seed value — never from
	// the clock.
	Epoch time.Time
}

// epochOf is the instant a run's events are timestamped from.
func epochOf(run Run) time.Time {
	if !run.Epoch.IsZero() {
		return run.Epoch.UTC()
	}
	// 2025-01-01T00:00:00Z plus up to a year, from the seed value alone.
	return time.Unix(1735689600+int64(rng(run.SeedValue+"/epoch").IntN(365*24*3600)), 0).UTC()
}

// Report is what a run sent.
type Report struct {
	Sent    map[string]any
	Message string
}

// SeedValue derives the stable per-(instance, seed) value from the
// instance's salt: 16 hex characters of sha256(salt/name) (Spec 0002 §5).
func SeedValue(salt, name string) string {
	sum := sha256.Sum256([]byte(salt + "/" + name))
	return hex.EncodeToString(sum[:8])
}

// rng seeds a PCG from the seed value: the same value, the same sequence,
// on every engine (math/rand/v2's PCG is a fixed algorithm).
func rng(seedValue string) *rand.Rand {
	sum := sha256.Sum256([]byte(seedValue))
	return rand.New(rand.NewPCG(binary.BigEndian.Uint64(sum[:8]), binary.BigEndian.Uint64(sum[8:16])))
}

// Runner delivers built-in seeds.
type Runner struct {
	Resolver Resolver
	Client   *http.Client
	// RequestTimeout bounds each request a built-in generator makes and
	// RunBudget bounds a whole run — a target that accepts a connection and
	// never answers, or never closes a body, cannot hold a create, a reset
	// or the instance's job slot forever.
	// Zero means the defaults.
	RequestTimeout time.Duration
	RunBudget      time.Duration
}

// The bounds a built-in seed runs under (spec 0003 §4): the exec path's
// run budget, and a per-request timeout no product should need.
const (
	DefaultRequestTimeout = 30 * time.Second
	DefaultRunBudget      = 5 * time.Minute
	// MaxWebLogBatch caps params.batch: a batch is rendered in memory
	// before it is sent, so an open batch size would let a schema-valid
	// seed hold the whole count at once.
	MaxWebLogBatch = 1000
)

func (r *Runner) requestTimeout() time.Duration {
	if r.RequestTimeout > 0 {
		return r.RequestTimeout
	}
	return DefaultRequestTimeout
}

func (r *Runner) runBudget() time.Duration {
	if r.RunBudget > 0 {
		return r.RunBudget
	}
	return DefaultRunBudget
}

func (r *Runner) client() *http.Client {
	if r.Client == nil {
		r.Client = &http.Client{
			Timeout:       r.requestTimeout(),
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // lab products present self-signed certificates
				DialContext:     dialVia,
				MaxIdleConns:    4,
			},
		}
	}
	return r.Client
}

// dialKey carries a request's connection factory in its context — the
// resolver's Dial for the service it addresses — and dialVia, the
// client's dialer, uses it when present (a plain loopback dial otherwise).
type dialKey struct{}

func withDialer(ctx context.Context, d func(context.Context) (net.Conn, error)) context.Context {
	return context.WithValue(ctx, dialKey{}, d)
}

func dialVia(ctx context.Context, network, addr string) (net.Conn, error) {
	if d, ok := ctx.Value(dialKey{}).(func(context.Context) (net.Conn, error)); ok && d != nil {
		return d(ctx)
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
}

// BuiltIn reports whether a generator name is a built-in of the frozen
// registry, and whether this release implements it.
func BuiltIn(name string) (registered, implemented bool) {
	switch name {
	case "http-requests", "web-logs":
		return true, true
	}
	return false, false
}

// GeneratorParams names the params each built-in generator reads (spec
// 0003 §4). A key a generator does not read is refused before anything is
// resolved or sent: a typo such as `methd` would otherwise be defaulted
// past, and the seed recorded as sent after doing something other than
// what was authored. `lab validate`
// applies the same lists at file:line (`seed-params`).
var GeneratorParams = map[string][]string{
	"http-requests": {"method", "path", "port", "purpose", "scheme", "service"},
	"web-logs":      {"batch", "headers", "path", "port", "purpose", "scheme", "service"},
}

// checkParams refuses a params key the run's generator does not read.
func checkParams(run Run) *pdr.Error {
	known, registered := GeneratorParams[run.Generator]
	if !registered {
		return nil
	}
	for _, k := range SortedKeys(run.Params) {
		if !slices.Contains(known, k) {
			e := pdr.New(pdr.CodeSeedFailed, "seed %s: params.%s is not a parameter the %s generator reads", run.Name, k, run.Generator)
			e.Cause = "the " + run.Generator + " generator reads " + strings.Join(known, ", ") + " (spec 0003 §4); a parameter it does not read would be skipped, and the seed recorded as sent after doing something other than authored"
			e.Next = "fix params." + k + " on the seed"
			return e
		}
	}
	return nil
}

// Run delivers a built-in seed.
func (r *Runner) Run(ctx context.Context, run Run) (*Report, *pdr.Error) {
	// The whole run is bounded: a generator that cannot finish within the
	// budget fails, it never holds the job (see RunBudget).
	ctx, cancel := context.WithTimeout(ctx, r.runBudget())
	defer cancel()
	if perr := checkParams(run); perr != nil {
		return nil, perr
	}
	switch run.Generator {
	case "http-requests":
		return r.httpRequests(ctx, run)
	case "web-logs":
		return r.webLogs(ctx, run)
	}
	e := pdr.New(pdr.CodeAdapterUnavailable, "generator %q is not a built-in", run.Generator)
	e.Cause = "built-ins: http-requests, web-logs (spec 0003 §4)"
	return nil, e
}

// target resolves where a seed delivers: params.service (required),
// params.port or the service's endpoint of params.purpose ("api" by
// default, then the first declared), params.path.
func (r *Runner) target(run Run, defaultPath string) (service, scheme, host, path string, dial func(context.Context) (net.Conn, error), perr *pdr.Error) {
	// The params are typed before anything is sent:
	// a present value of another shape is a configuration
	// error, never a silently substituted default that delivers the
	// payload to the wrong place and calls it sent.
	var purpose string
	for _, p := range []struct {
		key string
		dst *string
	}{{"service", &service}, {"purpose", &purpose}, {"scheme", &scheme}, {"path", &path}} {
		v, err := paramString(run, p.key)
		if err != nil {
			return "", "", "", "", nil, err
		}
		*p.dst = v
	}
	if service == "" {
		e := pdr.New(pdr.CodeSeedFailed, "seed %s has no delivery target", run.Name)
		e.Cause = "the " + run.Generator + " generator delivers to params.service (with params.path, params.port or params.purpose)"
		e.Next = "set params.service on the seed to the service that receives the data"
		return "", "", "", "", nil, e
	}
	port, perr := paramPort(run)
	if perr != nil {
		return "", "", "", "", nil, perr
	}
	declared := scheme
	scheme = "http"
	if port == 0 {
		var ok bool
		var s string
		if purpose != "" {
			port, s, ok = r.Resolver.Endpoint(service, purpose)
		} else if port, s, ok = r.Resolver.Endpoint(service, "api"); !ok {
			port, s, ok = r.Resolver.Endpoint(service, "")
		}
		if !ok {
			e := pdr.New(pdr.CodeSeedFailed, "seed %s: service %s declares no endpoint to deliver to", run.Name, service)
			e.Cause = "no params.port was given and the service declares no matching endpoint"
			e.Next = "set params.port, or params.purpose to one of the service's endpoint purposes"
			return "", "", "", "", nil, e
		}
		if s == "https" {
			scheme = s
		}
	}
	if declared != "" {
		scheme = declared
	}
	// Resolved so an unreachable service is reported before anything is
	// sent; the address is the dialer's business, not the URL's.
	if _, err := r.Resolver.Resolve(service, port); err != nil {
		e := pdr.New(pdr.CodeSeedFailed, "seed %s cannot reach %s:%d", run.Name, service, port)
		e.Cause = err.Error()
		e.Next = "podaro status " + labName(run) + " · the service must be running and the port a declared endpoint"
		return "", "", "", "", nil, e
	}
	// Every request of the run connects through the resolver: the live
	// container is verified around each dial.
	dial = func(c context.Context) (net.Conn, error) { return r.Resolver.Dial(c, service, port) }
	if path == "" {
		path = defaultPath
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	// The address is not returned: it is resolved above so an unreachable
	// service is reported before anything is sent, and the dial itself is
	// the dialer's. A URL built from it would set the TLS server name to
	// an IP (round 71).
	return service, scheme, service + ":" + strconv.Itoa(port), path, dial, nil
}

// httpRequests issues count requests against params.service/params.path
// (spec 0003 §4) — for labs whose products observe their own traffic. The
// order and the per-request marker derive from the seed value; every
// answer counts as sent (the product observed the request whatever it
// answered), and a connection failure ends the run.
func (r *Runner) httpRequests(ctx context.Context, run Run) (*Report, *pdr.Error) {
	service, scheme, host, path, dial, perr := r.target(run, "/")
	if perr != nil {
		return nil, perr
	}
	ctx = withDialer(ctx, dial)
	method := "GET"
	if m, err := paramString(run, "method"); err != nil {
		return nil, err
	} else if m != "" {
		method = strings.ToUpper(m)
	}
	count := run.Count
	if count <= 0 {
		count = 1
	}
	gen := rng(run.SeedValue)
	statuses := map[string]int{}
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			return nil, seedErr(run, fmt.Sprintf("interrupted after %d of %d requests", i, count), ctx.Err())
		}
		marker := fmt.Sprintf("%s-%04d-%08x", run.SeedValue, i, gen.Uint32())
		// The URL keeps the service's own host: the dialer ignores the
		// address, and net/http takes the TLS server name from the URL —
		// an IP there means the wrong virtual host, or no SNI at all.
		u := scheme + "://" + host + path
		req, err := http.NewRequestWithContext(ctx, method, u, nil)
		if err != nil {
			return nil, seedErr(run, "building request", err)
		}
		req.Host = host
		req.Header.Set("User-Agent", "podaro-seed/"+run.Name)
		req.Header.Set("X-Podaro-Seed", marker)
		resp, err := r.client().Do(req)
		if err != nil {
			e := seedErr(run, fmt.Sprintf("request %d of %d to %s%s failed", i+1, count, service, path), err)
			e.Next = "podaro status " + labName(run) + " · podaro logs " + labName(run) + " " + service + " · podaro seed " + labName(run) + " " + run.Name + " to run it again (safe by contract)"
			return nil, e
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		statuses[strconv.Itoa(resp.StatusCode)]++
	}
	return &Report{Sent: map[string]any{"requests": count, "statuses": statuses}, Message: fmt.Sprintf("%d %s requests to %s%s, seeded rng %s", count, method, service, path, run.SeedValue)}, nil
}

// paramString reads an optional string param: absent is ""; a present
// value of any other shape — a present null included, which the schema
// admits and which is not the absence it would otherwise read as
// — is a configuration error named by its type,
// never by its value, which a rendered param may have drawn from a secret.
func paramString(run Run, key string) (string, *pdr.Error) {
	v, ok := run.Params[key]
	if !ok {
		return "", nil
	}
	s, isString := v.(string)
	if !isString {
		e := pdr.New(pdr.CodeSeedFailed, "seed %s: params.%s must be a string, not %s", run.Name, key, typeWord(v))
		e.Cause = "the " + run.Generator + " generator reads params." + key + " as text (spec 0003 §4); a value of another shape cannot be delivered to and is not the default"
		e.Next = "fix params." + key + " on the seed"
		return "", e
	}
	return s, nil
}

// paramHeaders reads web-logs' optional params.headers, judged before the
// first batch: absent is none; present, it is a map of field names to
// string values, one field per name whatever its case — HTTP field names
// are case-insensitive, and http.Header would keep whichever spelling a
// map's unordered walk set last, so `Authorization` beside
// `authorization` would send either credential on any given run
// — each name a legal field name and each value
// free of CR, LF and NUL, as the init render requires (spec 0003 §9.1).
// Anything else is PDR-E404 naming the field, never its value, which a
// rendered param may have drawn from a secret. The fields come back in
// name order, so what is sent does not depend on the map's walk. A
// field named Host comes back apart: Go sends the wire Host from the
// request's own field, never from the header map, so an authored Host
// names the virtual host the collector is asked for — a legal host
// (RFC 9110 §7.2: a name or address, a port at most) — while the dial
// stays the service's.
func paramHeaders(run Run) (fields [][2]string, authoredHost string, perr *pdr.Error) {
	v, ok := run.Params["headers"]
	if !ok {
		return nil, "", nil
	}
	refuse := func(format string, args ...any) *pdr.Error {
		e := pdr.New(pdr.CodeSeedFailed, "seed %s: %s", run.Name, fmt.Sprintf(format, args...))
		e.Cause = "the " + run.Generator + " generator sends params.headers with every batch (spec 0003 §4): one value per HTTP field, each a string an HTTP field may hold"
		e.Next = "fix params.headers on the seed"
		return e
	}
	m, isMap := v.(map[string]any)
	if !isMap {
		return nil, "", refuse("params.headers must be a map of field names to values, not %s", typeWord(v))
	}
	seen := map[string]string{}
	out := make([][2]string, 0, len(m))
	for _, k := range SortedKeys(m) {
		if !wire.ValidFieldName(k) {
			return nil, "", refuse("params.headers names a field %q that is not a legal HTTP field name (RFC 9110 §5.1)", k)
		}
		if first, dup := seen[strings.ToLower(k)]; dup {
			return nil, "", refuse("params.headers declares field %q twice (%q and %q): HTTP field names are case-insensitive, one value per field", strings.ToLower(k), first, k)
		}
		seen[strings.ToLower(k)] = k
		s, isString := m[k].(string)
		if !isString {
			return nil, "", refuse("params.headers.%s must be a string, not %s", k, typeWord(m[k]))
		}
		if strings.ContainsAny(s, "\r\n\x00") {
			return nil, "", refuse("params.headers.%s holds a control character (CR, LF or NUL), which an HTTP field may not", k)
		}
		if strings.EqualFold(k, "Host") {
			// the grammar, not a character set: `tenant:abc`, `[` or `%20` are
			// refused here, never sent
			if !wire.ValidHost(s) {
				return nil, "", refuse("params.headers.%s is not a legal HTTP Host — a name or an IP address, a numeric port at most (RFC 9110 §7.2)", k)
			}
			authoredHost = s
			continue
		}
		out = append(out, [2]string{k, s})
	}
	return out, authoredHost, nil
}

// paramBatch reads web-logs' optional params.batch: absent is 100; present,
// it is a whole number of at least 1 — an integer, or a string of digits —
// and anything else, a present null, zero, a negative or a map included,
// is PDR-E404 before any batch, never the default silently kept while the
// receiver gets payloads grouped otherwise than declared.
// A batch above MaxWebLogBatch is capped by the caller.
func paramBatch(run Run) (int, *pdr.Error) {
	v, ok := run.Params["batch"]
	if !ok {
		return 100, nil
	}
	n, whole := wholeNumber(v)
	if !whole || n < 1 {
		e := pdr.New(pdr.CodeSeedFailed, "seed %s: params.batch must be a whole number of at least 1, not %s", run.Name, typeWord(v))
		e.Cause = "the " + run.Generator + " generator sends its events in batches of params.batch (spec 0003 §4); a value of another shape is not a batch size, and the default is not what was declared"
		e.Next = "fix params.batch on the seed, or drop it for batches of 100"
		return 0, e
	}
	return n, nil
}

// wholeNumber reads an integer from the shapes a decoded param can take.
func wholeNumber(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		if x > math.MaxInt32 || x < math.MinInt32 {
			return 0, false
		}
		return int(x), true
	case float64:
		if x != math.Trunc(x) || x > math.MaxInt32 || x < math.MinInt32 {
			return 0, false
		}
		return int(x), true
	case string:
		// digits only — no sign, no space
		return wire.Digits(x)
	}
	return 0, false
}

// paramPort reads an optional port: absent is 0 (the endpoint decides);
// an integer, or a string of digits, from 1 to 65535; anything else — a
// present null included — is a configuration error.
func paramPort(run Run) (int, *pdr.Error) {
	v, ok := run.Params["port"]
	if !ok {
		return 0, nil
	}
	bad := func() (int, *pdr.Error) {
		e := pdr.New(pdr.CodeSeedFailed, "seed %s: params.port must be a port number, not %s", run.Name, typeWord(v))
		e.Cause = "the " + run.Generator + " generator delivers to params.port, a number from 1 to 65535 (spec 0003 §4); a value of another shape is not the endpoint's port"
		e.Next = "fix params.port on the seed, or drop it to deliver to the service's declared endpoint"
		return 0, e
	}
	var port int
	switch t := v.(type) {
	case int:
		port = t
	case int64:
		port = int(t)
	case float64:
		if t != float64(int(t)) {
			return bad()
		}
		port = int(t)
	case string:
		// digits only — no sign, no space
		n, ok := wire.Digits(t)
		if !ok {
			return bad()
		}
		port = n
	default:
		return bad()
	}
	if port < 1 || port > 65535 {
		return bad()
	}
	return port, nil
}

// typeWord names a param's shape for an error — its Go type with the
// article, "null" for a present null — never its value.
func typeWord(v any) string {
	if v == nil {
		return "null"
	}
	return fmt.Sprintf("a %T", v)
}

func seedErr(run Run, what string, err error) *pdr.Error {
	e := pdr.New(pdr.CodeSeedFailed, "seed %s failed: %s", run.Name, what)
	if err != nil {
		e.Cause = err.Error()
	}
	e.Next = "podaro seed " + labName(run) + " " + run.Name + " to run it again (safe by contract)"
	return e
}

// labName is the instance a run belongs to, for a `next` an operator can
// copy instead of edit (User Manual §14: next is an action). The runner is
// told the name — Run.Instance — so an error about this lab names it; a
// run made without one keeps the placeholder rather than a blank.
func labName(run Run) string {
	if run.Instance == "" {
		return "<instance>"
	}
	return run.Instance
}

// WebLog is one generated access event.
type WebLog struct {
	Timestamp string `json:"@timestamp"`
	Host      string `json:"host"`
	ClientIP  string `json:"client_ip"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	Bytes     int    `json:"bytes"`
	UserAgent string `json:"user_agent"`
	Referrer  string `json:"referrer,omitempty"`
	Latency   int    `json:"latency_ms"`
	Sequence  int    `json:"seq"`
	Source    string `json:"source"`
}

var (
	webPaths   = []string{"/", "/index.html", "/products", "/products/42", "/cart", "/checkout", "/api/v1/orders", "/api/v1/status", "/login", "/logout", "/static/app.js", "/static/style.css", "/images/logo.png", "/search?q=widgets", "/account"}
	webMethods = []string{"GET", "GET", "GET", "GET", "GET", "POST", "PUT", "DELETE"}
	webAgents  = []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/605.1", "Mozilla/5.0 (X11; Linux x86_64) Firefox/129.0", "curl/8.9.0", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5) Mobile/15E148"}
	webHosts   = []string{"web-01", "web-02", "web-03"}
	webStatus  = []int{200, 200, 200, 200, 200, 200, 301, 302, 304, 400, 401, 403, 404, 404, 500, 503}
)

// GenerateWebLogs renders count events from the seed value: field values
// and their order are identical for one value on every run (Spec 0002
// §5); timestamps spread over the ten minutes before now so time-window
// queries see them — the payload's identity is its fields, not its clock.
func GenerateWebLogs(seedValue string, count int, now time.Time) []WebLog {
	g := newWebLogGen(seedValue, now)
	out := make([]WebLog, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, g.next())
	}
	return out
}

// webLogGen renders web-server events one at a time from the seed value —
// the same fields in the same order for one value on every run — so a
// delivery holds one batch in memory, never the whole count.
type webLogGen struct {
	gen    *rand.Rand
	now    time.Time
	source string
	seq    int
}

func newWebLogGen(seedValue string, now time.Time) *webLogGen {
	return &webLogGen{gen: rng(seedValue), now: now, source: "podaro-seed/" + seedValue}
}

// onWebLog is a test seam: called with each event's sequence number as it
// is rendered, so a test can count what a delivery materialised. Nil in
// production.
var onWebLog func(seq int)

func (g *webLogGen) next() WebLog {
	gen := g.gen
	// The spread has to sit comfortably inside the NARROWEST window that
	// reads these events, or the lab loses them to the clock: the
	// reference playbook's `ingest-parity` asks about ten minutes, and
	// spreading over ten minutes meant the oldest event was already
	// outside by the time the seed finished and the learner pressed
	// Verify. Five minutes leaves five minutes of headroom — for a seed
	// that takes longer on a 16 GB host than it does here, and for a
	// learner who reads the step before pressing anything. The fake used
	// to file an event under its arrival, which hid this entirely.
	offset := time.Duration(gen.IntN(300)) * time.Second
	ev := WebLog{
		Timestamp: g.now.Add(-offset).UTC().Format(time.RFC3339),
		Host:      webHosts[gen.IntN(len(webHosts))],
		ClientIP:  fmt.Sprintf("203.0.113.%d", 1+gen.IntN(254)),
		Method:    webMethods[gen.IntN(len(webMethods))],
		Path:      webPaths[gen.IntN(len(webPaths))],
		Status:    webStatus[gen.IntN(len(webStatus))],
		Bytes:     200 + gen.IntN(48000),
		UserAgent: webAgents[gen.IntN(len(webAgents))],
		Latency:   1 + gen.IntN(900),
		Sequence:  g.seq,
		Source:    g.source,
	}
	if onWebLog != nil {
		onWebLog(g.seq)
	}
	g.seq++
	return ev
}

// --- one delivery -----------------------------------------------------

// deliver sends count events to the seed's target as newline-delimited
// JSON, one batch rendered, sent and released at a time — the run's
// memory is bounded by the batch, not by the count.
// It is the delivery every event generator shares.
func (r *Runner) deliver(ctx context.Context, run Run, defaultPath string, defaultCount int, next func() any) (*Report, *pdr.Error) {
	service, scheme, host, path, dial, perr := r.target(run, defaultPath)
	if perr != nil {
		return nil, perr
	}
	ctx = withDialer(ctx, dial)
	count := run.Count
	if count <= 0 {
		count = defaultCount
	}
	batch, perr := paramBatch(run)
	if perr != nil {
		return nil, perr
	}
	if batch > MaxWebLogBatch {
		batch = MaxWebLogBatch
	}
	headers, authoredHost, perr := paramHeaders(run)
	if perr != nil {
		return nil, perr
	}
	// The authored Host is the wire Host and only that: it never becomes
	// the URL's host, because the URL is where net/http takes the TLS
	// server name from. SNI names the service being connected to, the
	// Host header names the virtual host asked of it, and holding both in
	// one variable made the second answer the first.
	wireHost := host
	if authoredHost != "" {
		wireHost = authoredHost
	}
	statuses := map[string]int{}
	sent, batches := 0, 0
	for start := 0; start < count; start += batch {
		if ctx.Err() != nil {
			return nil, seedErr(run, fmt.Sprintf("interrupted after %d of %d events", sent, count), ctx.Err())
		}
		end := start + batch
		if end > count {
			end = count
		}
		var body bytes.Buffer
		for i := start; i < end; i++ {
			raw, _ := json.Marshal(next())
			body.Write(raw)
			body.WriteByte('\n')
		}
		// The URL keeps the service's own host: the dial is the resolver's,
		// and net/http takes the TLS server name from the URL — an https
		// endpoint reached at an address is offered no SNI at all.
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, scheme+"://"+host+path, &body)
		if err != nil {
			return nil, seedErr(run, "building request", err)
		}
		req.Host = wireHost
		req.Header.Set("Content-Type", "application/x-ndjson")
		req.Header.Set("User-Agent", "podaro-seed/"+run.Name)
		req.Header.Set("X-Podaro-Seed", run.SeedValue)
		for _, h := range headers {
			req.Header.Set(h[0], h[1])
		}
		resp, err := r.client().Do(req)
		if err != nil {
			return nil, seedErr(run, fmt.Sprintf("batch %d–%d of %d events to %s%s failed", start+1, end, count, service, path), err)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		statuses[strconv.Itoa(resp.StatusCode)]++
		batches++
		// Only a 2xx is a delivery. This client does not follow
		// redirects (`http.ErrUseLastResponse`), so a 3xx is a batch that
		// went nowhere — and counting it as sent reported a seed as
		// succeeded over events no destination ever received, which is
		// then what an objective is judged against.
		if resp.StatusCode >= 400 {
			return nil, seedErr(run, fmt.Sprintf("%s%s rejected batch %d–%d with %d", service, path, start+1, end, resp.StatusCode), nil)
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, seedErr(run, fmt.Sprintf("%s%s answered batch %d–%d with %d and this client does not follow redirects, so it did not arrive",
				service, path, start+1, end, resp.StatusCode), nil)
		}
		sent = end
	}
	return &Report{
		Sent:    map[string]any{"events": sent, "batches": batches, "statuses": statuses},
		Message: fmt.Sprintf("%d events to %s%s, seeded rng %s", sent, service, path, run.SeedValue),
	}, nil
}

// webLogs delivers count web-server events as newline-delimited JSON
// (Content-Type application/x-ndjson) to params.service/params.path in
// batches of params.batch (default 100).
func (r *Runner) webLogs(ctx context.Context, run Run) (*Report, *pdr.Error) {
	g := newWebLogGen(run.SeedValue, epochOf(run))
	return r.deliver(ctx, run, "/", 500, func() any { return g.next() })
}

// Escape renders a query value for a URL (a helper for callers building
// params).
func Escape(s string) string { return url.QueryEscape(s) }

// SortedKeys is the deterministic order of a params map.
func SortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
