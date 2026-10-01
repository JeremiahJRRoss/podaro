// SPDX-License-Identifier: AGPL-3.0-only

// Package verify is the checkpoint engine (plan S6; spec 0001 §3–§4;
// roadmap §5): the built-in adapters this step ships — http, container,
// attest — and the seam through which exec extensions are judged, with
// the retry, timeout, and result rules every adapter shares. Adapters
// query products through their declared endpoints on the host's loopback
// (threat model B4); they never receive secret values (spec 0001 §2) —
// credentials, where a built-in needs one, are resolved engine-side.
package verify

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeremiahjrross/podaro/internal/lab"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/wire"
	"math"
	"slices"
)

// Defaults of spec 0001 §2.
const (
	DefaultTimeout  = 30 * time.Second
	DefaultAttempts = 3
	DefaultBackoff  = 5 * time.Second
)

// Statuses of spec 0001 §4.
const (
	StatusPass     = "pass"
	StatusFail     = "fail"
	StatusAttested = "attested"
	StatusError    = "error"
)

// Target is how adapters reach the instance.
type Target interface {
	// Resolve returns the loopback address (host:port) a service publishes
	// for one of its container ports; an error names why it cannot be
	// reached (no such service, port not published).
	Resolve(service string, port int) (string, error)
	// Dial connects to that address for one request, verifying — as the
	// gateway's route does — that the recorded container is running,
	// owned and mapping the port before the dial and unchanged after it,
	// so a service that stopped outside a job and whose ephemeral port
	// went to another listener is never judged through the wrong door.
	Dial(ctx context.Context, service string, port int) (net.Conn, error)
	// Container reports a service's container facts for the container
	// adapter, within the attempt's context (an inspect that stalls ends
	// with the checkpoint's timeout, never blocking the run).
	Container(ctx context.Context, service string) (*ContainerFacts, error)
}

// ContainerFacts is what the container adapter judges.
type ContainerFacts struct {
	Exists  bool
	Running bool
	// Healthy is the engine's readiness verdict (the service reached the
	// ladder's healthy rung and has not been found otherwise since).
	Healthy bool
	Labels  map[string]string
	Stage   string
}

// Result is one evaluation (API §8: observed vs expected, the hint on
// fail, the anatomy on error).
type Result struct {
	Status   string
	Observed any
	Expected any
	Message  string
	Error    *pdr.Error
	Duration time.Duration
	Attempts int
	// Capture is what an exec verdict recorded under evidence.capture.
	Capture map[string]any
}

// ExecFunc judges an exec checkpoint (Spec 0002); the engine wires the
// extension runner here. A nil func means exec is unavailable.
type ExecFunc func(ctx context.Context, cp lab.FlatCheckpoint, timeout time.Duration) Result

// Evaluator runs checkpoints against a target.
type Evaluator struct {
	Target Target
	Exec   ExecFunc
	// Client is the HTTP client adapters use; nil builds one that accepts
	// the labs' self-signed certificates and keeps no connections.
	Client *http.Client
	// Sleep waits between attempts (a seam for tests); nil sleeps.
	Sleep func(ctx context.Context, d time.Duration) error
	// Now is the clock (a seam for tests).
	Now func() time.Time

	// clientOnce builds the default client exactly once: one evaluator
	// judges checkpoints concurrently (the engine runs four at a time).
	clientOnce sync.Once
}

// New returns an evaluator over a target.
func New(target Target, exec ExecFunc) *Evaluator {
	return &Evaluator{Target: target, Exec: exec, Client: DefaultClient()}
}

// DefaultClient is the HTTP client the adapters use when none is given:
// it accepts the labs' self-signed certificates, follows no redirects
// (a 3xx is an observation, not a detour), and keeps no connections.
func DefaultClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // lab products present self-signed certificates
			DisableKeepAlives: true,
			DialContext:       dialVia,
		},
	}
}

// dialKey carries a request's connection factory in its context: the
// target's Dial for the service the request addresses.
type dialKey struct{}

// withDialer attaches the connection factory a request must use; the
// default client's transport dials through it (dialVia).
func withDialer(ctx context.Context, d func(context.Context) (net.Conn, error)) context.Context {
	return context.WithValue(ctx, dialKey{}, d)
}

// dialVia is the default transport's dialer: the request's own factory
// when the adapter attached one, a plain loopback dial otherwise.
func dialVia(ctx context.Context, network, addr string) (net.Conn, error) {
	if d, ok := ctx.Value(dialKey{}).(func(context.Context) (net.Conn, error)); ok && d != nil {
		return d(ctx)
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
}

func (ev *Evaluator) client() *http.Client {
	ev.clientOnce.Do(func() {
		if ev.Client == nil {
			ev.Client = DefaultClient()
		}
	})
	return ev.Client
}

func (ev *Evaluator) sleep(ctx context.Context, d time.Duration) error {
	if ev.Sleep != nil {
		return ev.Sleep(ctx, d)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

func (ev *Evaluator) now() time.Time {
	if ev.Now != nil {
		return ev.Now()
	}
	return time.Now()
}

// Budget reads a checkpoint's timeout, attempts, and backoff with the
// spec's defaults applied.
func Budget(cp lab.Checkpoint) (timeout time.Duration, attempts int, backoff time.Duration) {
	timeout, attempts, backoff = DefaultTimeout, DefaultAttempts, DefaultBackoff
	if d, err := time.ParseDuration(cp.Timeout); err == nil && d > 0 {
		timeout = d
	}
	if cp.Retries != nil {
		if cp.Retries.Attempts > 0 {
			attempts = cp.Retries.Attempts
		}
		if d, err := time.ParseDuration(cp.Retries.Backoff); err == nil && d >= 0 {
			backoff = d
		}
	}
	return timeout, attempts, backoff
}

// Evaluate runs one checkpoint with its retries: each attempt is bounded
// by the timeout; a fail or an error is retried after the backoff until
// an attempt passes or the attempts are spent, and the last attempt's
// verdict is the result (eventual consistency is the medium — spec 0001
// §2). Errors that no retry can change (an adapter this release lacks,
// a refused image) end the loop at once.
func (ev *Evaluator) Evaluate(ctx context.Context, cp lab.FlatCheckpoint) Result {
	timeout, attempts, backoff := Budget(cp.Checkpoint)
	start := ev.now()
	var res Result
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			if err := ev.sleep(ctx, backoff); err != nil {
				// A run cut off while waiting to retry has no verdict: the
				// attempts declared were never completed, so the previous
				// attempt's fail or error must not stand as the result — a
				// cancellation or timeout is one, and is recorded as such.
				res = errorResult(pdr.CodeCheckpointTimeout,
					fmt.Sprintf("checkpoint %s: interrupted after %d of %d attempts while waiting to retry (%v)", cp.ID, attempt-1, attempts, err),
					"the run was cancelled or ran out of time between attempts; no attempt's verdict stands, since the retries declared never completed",
					"run the checkpoint again, or raise its timeout")
				res.Duration = ev.now().Sub(start)
				res.Attempts = attempt - 1
				if res.Expected == nil && len(cp.Expect) > 0 {
					res.Expected = cp.Expect
				}
				return res
			}
		}
		actx, cancel := context.WithTimeout(ctx, timeout)
		res = ev.once(actx, cp, timeout)
		cancel()
		res.Attempts = attempt
		if res.Status == StatusPass || res.Status == StatusAttested || final(res) || ctx.Err() != nil {
			break
		}
	}
	res.Duration = ev.now().Sub(start)
	if res.Expected == nil && len(cp.Expect) > 0 {
		res.Expected = cp.Expect
	}
	return res
}

// final reports whether a result's error is structural: retrying cannot
// change it.
func final(r Result) bool {
	if r.Status != StatusError || r.Error == nil {
		return false
	}
	switch r.Error.Code {
	case pdr.CodeAdapterUnavailable, pdr.CodeExecRoot, pdr.CodeExecPull:
		return true
	}
	return false
}

// once is one attempt.
func (ev *Evaluator) once(ctx context.Context, cp lab.FlatCheckpoint, timeout time.Duration) Result {
	switch cp.Adapter {
	case "http":
		return ev.httpAdapter(ctx, cp)
	case "container":
		return ev.containerAdapter(ctx, cp)
	case "attest":
		return attestAdapter(cp)
	case "exec":
		if ev.Exec == nil {
			return errorResult(pdr.CodeAdapterUnavailable, "exec extensions are not available on this engine", "no extension runner is wired", "")
		}
		return ev.Exec(ctx, cp, timeout)
	}
	// A module alias resolves to exec at validate (spec 0003 §10); an
	// engine that sees the alias name unexpanded treats it as exec.
	if ev.Exec != nil {
		return ev.Exec(ctx, cp, timeout)
	}
	return errorResult(pdr.CodeAdapterUnavailable, fmt.Sprintf("adapter %q is not available", cp.Adapter), "neither a built-in of this release nor a runnable extension", "")
}

func errorResult(code, message, cause, next string) Result {
	e := pdr.New(code, "%s", message)
	e.Cause = cause
	e.Next = next
	if next == "" {
		if entry, ok := pdr.Lookup(code); ok {
			e.Next = entry.Next
		}
	}
	return Result{Status: StatusError, Error: e, Message: message}
}

// --- http -------------------------------------------------------------

// httpAdapter: params url (instance-internal: http://<service>:<port>/…),
// method, headers, body; expect status, body_contains, json_path {path,
// op, value}. The service name is resolved to the loopback address its
// port is published at; the Host header keeps the in-lab name.
func (ev *Evaluator) httpAdapter(ctx context.Context, cp lab.FlatCheckpoint) Result {
	// The expectation is read and typed before anything is sent: a
	// misconfigured checkpoint has no side effects — a POST with a
	// malformed expectation must not mutate the product, once per attempt,
	// before the configuration error is reported.
	ex, bad := parseHTTPExpect(cp)
	if bad != nil {
		return *bad
	}
	// The params too: a header block of the wrong shape, a method that
	// is no word, a key the adapter does not read — silently skipped,
	// any of them would send a request the checkpoint did not describe.
	prm, bad := parseHTTPParams(cp)
	if bad != nil {
		return *bad
	}
	rawURL := prm.rawURL
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s: params.url %q is not an http(s) URL naming a service", cp.ID, rawURL), "urls are instance-internal: http://<service>:<port>/path", "")
	}
	port := 0
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	} else if u.Scheme == "https" {
		port = 443
	} else {
		port = 80
	}
	service := u.Hostname()
	// Resolved to report an unreachable service before anything is sent;
	// the address itself is the dialer's business, not the URL's.
	if _, err := ev.Target.Resolve(service, port); err != nil {
		return errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s cannot reach %s", cp.ID, u.Host), err.Error(), "")
	}
	method, body := prm.method, prm.body
	// The URL keeps the service's own host. The connection is the
	// target's to make — the attached dialer ignores the address
	// entirely, so nothing is gained by writing the loopback address
	// here, and something is lost: net/http derives the TLS server name
	// from the URL's host, and would omit SNI altogether for an IP. An
	// https checkpoint against a product that selects a virtual host by
	// SNI would then reach the default one, or fail its handshake, while
	// naming a service that is running.
	// The resolved address is still read above, so a service that cannot
	// be reached is reported before anything is sent.
	ctx = withDialer(ctx, func(c context.Context) (net.Conn, error) { return ev.Target.Dial(c, service, port) })
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return errorResult(pdr.CodeCheckpointError, "http checkpoint "+cp.ID+": "+err.Error(), "", "")
	}
	req.Host = u.Host
	for k, v := range prm.headers {
		// Host is the request's own field on the wire — Go sends it from
		// there, never from the header map — so an authored Host names
		// the virtual host the checkpoint asks for, while the dial stays
		// the target's.
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := ev.client().Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			return errorResult(pdr.CodeCheckpointTimeout, fmt.Sprintf("http checkpoint %s: %s %s did not answer within the timeout", cp.ID, method, rawURL), err.Error(), "")
		}
		return errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s: %s %s failed", cp.ID, method, rawURL), err.Error(), "")
	}
	defer resp.Body.Close()
	// The body is read only for the expectations that judge it: a
	// status-only checkpoint is judged by the status line, so an endpoint
	// that answers and keeps its body open — a stream — passes on the
	// status instead of expiring. One byte
	// past the cap tells a body that fits from one that was cut: a cut
	// body is judged by nothing that reads it — the answer's tail, where
	// a second JSON value or the needle may sit, is unknown (round 30).
	var raw []byte
	oversized := false
	if ex.needle != nil || ex.jsonPath != nil {
		raw, err = io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
				return errorResult(pdr.CodeCheckpointTimeout, fmt.Sprintf("http checkpoint %s: %s %s answered %d but its body did not arrive within the timeout", cp.ID, method, rawURL, resp.StatusCode), err.Error(), "")
			}
			return errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s: reading the answer of %s %s failed", cp.ID, method, rawURL), err.Error(), "")
		}
		oversized = len(raw) > maxBody
	}
	observed := map[string]any{"status": resp.StatusCode}
	var failures []string
	expect := cp.Expect
	if ex.status != nil && resp.StatusCode != *ex.status {
		failures = append(failures, fmt.Sprintf("status %d, expected %d", resp.StatusCode, *ex.status))
	}
	if ex.needle != nil {
		if oversized {
			return errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s: %s %s answered %d with a body larger than %d MiB", cp.ID, method, rawURL, resp.StatusCode, maxBody>>20), "the adapter judges bodies up to that size; a larger one is not judged by its first bytes", "point the checkpoint at a smaller answer")
		}
		has := strings.Contains(string(raw), *ex.needle)
		observed["body_contains"] = has
		if !has {
			failures = append(failures, fmt.Sprintf("body does not contain %q", *ex.needle))
		}
	}
	if ex.jsonPath != nil {
		if oversized {
			return errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s: %s %s answered %d with a body larger than %d MiB", cp.ID, method, rawURL, resp.StatusCode, maxBody>>20), "the adapter judges bodies up to that size; a larger one is not judged by its first bytes", "point the checkpoint at a smaller answer")
		}
		jp, path, op := ex.jsonPath, ex.path, ex.op
		var doc any
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			return errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s: %s %s answered %d but not JSON", cp.ID, method, rawURL, resp.StatusCode), err.Error(), "")
		}
		// Exactly one document: a second value, or stray bytes after the
		// first, means the body is not the JSON answer the checkpoint
		// judges — an error, never a pass on the valid prefix.
		var trailing any
		if err := dec.Decode(&trailing); err != io.EOF {
			return errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s: %s %s answered %d with JSON followed by trailing data", cp.ID, method, rawURL, resp.StatusCode), "the body must be exactly one JSON document", "")
		}
		value, found, err := jsonPathLookup(normalize(doc), path)
		if err != nil {
			return errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s: %s", cp.ID, err.Error()), "fix expect.json_path.path", "")
		}
		if found {
			observed["json_path"] = value
		} else {
			observed["json_path"] = nil
		}
		ok, err := compare(op, value, found, jp["value"])
		if err != nil {
			return errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s: %s", cp.ID, err.Error()), "fix expect.json_path.op", "")
		}
		if !ok {
			if !found {
				failures = append(failures, fmt.Sprintf("json_path %s: no such element", path))
			} else {
				failures = append(failures, fmt.Sprintf("json_path %s is %s, expected %s %s", path, asText(value), opWord(op), asText(jp["value"])))
			}
		}
	}
	if len(failures) > 0 {
		return Result{Status: StatusFail, Observed: observed, Expected: expect, Message: fmt.Sprintf("%s %s → %s", method, rawURL, strings.Join(failures, "; "))}
	}
	return Result{Status: StatusPass, Observed: observed, Expected: expect, Message: fmt.Sprintf("%s %s → %d%s", method, rawURL, resp.StatusCode, passDetail(observed))}
}

func passDetail(observed map[string]any) string {
	if v, ok := observed["json_path"]; ok {
		return " · json_path " + asText(v)
	}
	if v, ok := observed["body_contains"]; ok && v == true {
		return " · body contains the text"
	}
	return ""
}

func opWord(op string) string {
	switch op {
	case "", "eq":
		return "="
	case "ne":
		return "≠"
	case "gt":
		return ">"
	case "gte":
		return "≥"
	case "lt":
		return "<"
	case "lte":
		return "≤"
	case "contains":
		return "to contain"
	}
	return op
}

// normalize keeps an integer json.Number as the exact literal it is — it
// marshals as a number and compares exactly (asInteger) — and turns any
// other json.Number into a float64, so observed values marshal as numbers.
func normalize(v any) any {
	switch t := v.(type) {
	case json.Number:
		if integerLiteral.MatchString(t.String()) {
			return t
		}
		if f, err := t.Float64(); err == nil {
			return f
		}
		return t.String()
	case map[string]any:
		for k, val := range t {
			t[k] = normalize(val)
		}
		return t
	case []any:
		for i, val := range t {
			t[i] = normalize(val)
		}
		return t
	}
	return v
}

// maxBody is the largest http answer the adapter judges (4 MiB); a larger
// one is an error for the expectations that read the body.
const maxBody = 4 << 20

// httpExpectations and containerExpectations name what each adapter
// judges. An expectation key the adapter does not read, or an expect that
// names none, is a configuration error: an http checkpoint declaring only
// `code: 200`, or nothing, would otherwise pass on any reachable endpoint.
var (
	httpExpectations      = []string{"body_contains", "json_path", "status"}
	containerExpectations = []string{"healthy", "label", "state"}
)

// httpExpect is the http adapter's expectation, read and typed before the
// request is sent (round 35): status an integer status code, body_contains
// a string, json_path a map naming its path with a word for its operator.
type httpExpect struct {
	status   *int
	needle   *string
	jsonPath map[string]any
	path, op string
}

// parseHTTPExpect reads and types an http checkpoint's expectation, or
// returns the configuration error that stops the checkpoint before any
// request is made.
func parseHTTPExpect(cp lab.FlatCheckpoint) (httpExpect, *Result) {
	var ex httpExpect
	if res := checkExpectations(cp, "http", httpExpectations); res != nil {
		return ex, res
	}
	bad := func(res Result) (httpExpect, *Result) { return ex, &res }
	expect := cp.Expect
	if want, ok := expect["status"]; ok {
		code, isCode := asStatusCode(want)
		if !isCode {
			return bad(errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s: expect.status must be an integer HTTP status code, not %s", cp.ID, typedText(want)), "the http adapter's status expectation is a number (spec 0001 §3); quoted text is a string and cannot be judged, as a quoted healthy is", "fix expect.status"))
		}
		ex.status = &code
	}
	if want, ok := expect["body_contains"]; ok {
		needle, isString := want.(string)
		if !isString {
			return bad(errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s: expect.body_contains must be a string, not %s", cp.ID, asText(want)), "the http adapter's body_contains expectation is the text the body must contain (spec 0001 §3)", "fix expect.body_contains"))
		}
		// Every body contains the empty string: an empty needle asserts
		// nothing.
		if needle == "" {
			return bad(errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s: expect.body_contains is empty", cp.ID), "the http adapter's body_contains expectation is the text the body must contain (spec 0001 §3); every body contains nothing", "fix expect.body_contains"))
		}
		ex.needle = &needle
	}
	if rawJP, ok := expect["json_path"]; ok {
		// A bare path, or anything but a map, asserts nothing the adapter
		// can judge — a configuration error, never an expectation skipped
		// and so passed on any reachable endpoint.
		jp, isMap := rawJP.(map[string]any)
		if !isMap {
			return bad(errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s: expect.json_path must be a map of path, op and value, not %s", cp.ID, asText(rawJP)), "the http adapter's json_path expectation is a map (spec 0001 §3); a bare path is a string and asserts nothing", "fix expect.json_path"))
		}
		path, op, res := jsonPathTerms("http checkpoint "+cp.ID, jp)
		if res != nil {
			return ex, res
		}
		ex.jsonPath, ex.path, ex.op = jp, path, op
	}
	return ex, nil
}

// jsonPathTerms reads and types a json_path expectation's terms — the
// contract of spec 0001 §3, shared by every adapter that judges one, so
// there is one implementation of it and not one per adapter (plan S8).
// The label names the checkpoint the way its adapter does.
func jsonPathTerms(label string, jp map[string]any) (string, string, *Result) {
	bad := func(res Result) (string, string, *Result) { return "", "", &res }
	// A field the adapter does not read — operator for op, a typo —
	// would be ignored and the assertion judged as if it were absent.
	if k, stray := unknownKey(jp, []string{"op", "path", "value"}); stray {
		return bad(errorResult(pdr.CodeCheckpointError, fmt.Sprintf("%s: expect.json_path.%s is not a field the adapter reads", label, k), "the json_path expectation is a map of path, op and value (spec 0001 §3); a field it does not read would be ignored, and the assertion judged as if it were absent", "fix expect.json_path"))
	}
	path, isString := jp["path"].(string)
	if !isString || strings.TrimSpace(path) == "" {
		return bad(errorResult(pdr.CodeCheckpointError, fmt.Sprintf("%s: expect.json_path.path must be a path of the form $.a.b[0], not %s", label, asText(jp["path"])), "the json_path expectation names the element it judges (spec 0001 §3)", "fix expect.json_path.path"))
	}
	// The operator is a word or absent; a value of another shape, or
	// an empty one, is a configuration error, never the default eq.
	op := ""
	if rawOp, has := jp["op"]; has {
		word, isString := rawOp.(string)
		if !isString || word == "" {
			return bad(errorResult(pdr.CodeCheckpointError, fmt.Sprintf("%s: expect.json_path.op must be one of eq, ne, gt, gte, lt, lte, contains, exists, not %q", label, asText(rawOp)), "the json_path operator is a word (spec 0001 §3); a value of another shape, or an empty one, cannot be judged and is not the default eq", "fix expect.json_path.op"))
		}
		op = word
	}
	if _, err := compare(op, nil, false, nil); err != nil {
		return bad(errorResult(pdr.CodeCheckpointError, fmt.Sprintf("%s: %s", label, err.Error()), "fix expect.json_path.op", ""))
	}
	// Every operator but exists compares against a value the checkpoint
	// names: a missing value is not null — it would compare against
	// nothing and pass on a null element.
	// An explicit null is a value.
	if _, hasValue := jp["value"]; !hasValue && op != "exists" {
		return bad(errorResult(pdr.CodeCheckpointError, fmt.Sprintf("%s: expect.json_path.value is required for op %s", label, opWord(op)), "the json_path expectation names the value it compares against (spec 0001 §3); only exists needs none", "fix expect.json_path.value"))
	}
	// contains names the text it looks for: every element contains the
	// empty string, so an empty needle would judge nothing and pass a
	// gate — a mutating request's included — on any answer, as an empty
	// body_contains would (round 40).
	if op == "contains" && asText(jp["value"]) == "" {
		return bad(errorResult(pdr.CodeCheckpointError, fmt.Sprintf("%s: expect.json_path.value is empty for op contains", label), "the json_path contains operator looks for the text the checkpoint names (spec 0001 §3); every element contains nothing", "fix expect.json_path.value"))
	}
	return path, op, nil
}

// asStatusCode reads an integer HTTP status code from a number — int, a
// float that is whole, a json.Number — never from a string: a quoted
// "204" is text, as a quoted "true" is (round 30), and is not judged.
func asStatusCode(v any) (int, bool) {
	var f float64
	switch t := v.(type) {
	case int:
		f = float64(t)
	case int64:
		f = float64(t)
	case float64:
		f = t
	case json.Number:
		x, err := t.Float64()
		if err != nil {
			return 0, false
		}
		f = x
	default:
		return 0, false
	}
	if f != math.Trunc(f) || f < 100 || f > 599 {
		return 0, false
	}
	return int(f), true
}

// typedText names a value with its kind where the text alone would
// mislead: a quoted "200" reads like a number.
func typedText(v any) string {
	if t, ok := v.(string); ok {
		return fmt.Sprintf("the text %q", t)
	}
	return asText(v)
}

// httpParams is the http adapter's request, read and typed before it is
// sent (round 40): url a string, method a word (GET when absent), headers
// a map of names to text, number or boolean values, body text or JSON.
type httpParams struct {
	rawURL  string
	method  string
	headers map[string]string
	body    io.Reader
}

var httpParamKeys = []string{"body", "headers", "method", "url"}

// parseHTTPParams reads and types an http checkpoint's params, or returns
// the configuration error that stops the checkpoint before any request.
func parseHTTPParams(cp lab.FlatCheckpoint) (httpParams, *Result) {
	var p httpParams
	if res := checkParams(cp, "http", httpParamKeys); res != nil {
		return p, res
	}
	bad := func(res Result) (httpParams, *Result) { return p, &res }
	rawURL, isString := cp.Params["url"].(string)
	if !isString || rawURL == "" {
		return bad(errorResult(pdr.CodeCheckpointError, "http checkpoint "+cp.ID+" has no params.url", "the http adapter needs params.url (spec 0001 §3)", ""))
	}
	p.rawURL = rawURL
	p.method = http.MethodGet
	if m, has := cp.Params["method"]; has {
		word, isString := m.(string)
		if !isString || strings.TrimSpace(word) == "" {
			return bad(errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s: params.method must be an HTTP method word, not %s", cp.ID, typedText(m)), "the http adapter's method is a word such as GET or POST (spec 0001 §3)", "fix params.method"))
		}
		p.method = strings.ToUpper(strings.TrimSpace(word))
	}
	if hs, has := cp.Params["headers"]; has {
		m, isMap := hs.(map[string]any)
		if !isMap {
			return bad(errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s: params.headers must be a map of header names to values, not %s", cp.ID, typedText(hs)), "the http adapter's headers are a map (spec 0001 §3); a block of another shape would be skipped and the request sent without it", "fix params.headers"))
		}
		p.headers = map[string]string{}
		names := make([]string, 0, len(m))
		for k := range m {
			names = append(names, k)
		}
		slices.Sort(names)
		seen := map[string]string{}
		for _, k := range names {
			v := m[k]
			if strings.TrimSpace(k) == "" {
				return bad(errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s: params.headers names an empty header", cp.ID), "a header has a name (spec 0001 §3)", "fix params.headers"))
			}
			// One field per name, whatever its case: HTTP field names are
			// case-insensitive, and http.Header.Set keeps whichever of
			// `Authorization` and `authorization` the map yielded last, so
			// the request could carry either authored value.
			if first, dup := seen[strings.ToLower(k)]; dup {
				return bad(errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s: params.headers names header %q twice (%q and %q)", cp.ID, strings.ToLower(k), first, k), "HTTP field names are case-insensitive: one value per field, whatever its case (spec 0001 §3)", "fix params.headers"))
			}
			seen[strings.ToLower(k)] = k
			// Host names a host: an empty one would make the client fall
			// back to the dial address on the wire (round 44 re-read).
			if strings.EqualFold(k, "Host") && strings.TrimSpace(asText(v)) == "" {
				return bad(errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s: params.headers.Host is empty", cp.ID), "an authored Host names the virtual host the checkpoint asks for (spec 0001 §3); leave it out to send the URL's host", "fix params.headers"))
			}
			// A Host the transport would not send as written — a space, a
			// slash, a control character — is refused here: Go's client
			// zeroes an illegal Host rather than sending it, so the request
			// would reach the product under no host at all.
			// The grammar, not a character set: `grafana:abc`, `[` or `%20`
			// are refused here, never sent.
			if strings.EqualFold(k, "Host") && !wire.ValidHost(asText(v)) {
				return bad(errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s: params.headers.Host is not a legal HTTP host", cp.ID), "a Host is a host name or an IP address with an optional numeric port, 1 to 65535 (RFC 9110 §7.2); the transport would otherwise send none", "fix params.headers"))
			}
			switch v.(type) {
			case string, bool, int, int64, float64, json.Number:
			default:
				return bad(errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s: params.headers.%s must be a text, number or boolean value, not %s", cp.ID, k, asText(v)), "a header's value is one line of text (spec 0001 §3)", "fix params.headers"))
			}
			p.headers[k] = asText(v)
		}
	}
	if b, has := cp.Params["body"]; has {
		// A present null is not the absence it would otherwise read as: a
		// POST would go out with no body and no content type — a different
		// request than authored, judged all the same.
		// The author leaves the key out to send no body.
		if b == nil {
			return bad(errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s: params.body is null", cp.ID), "the http adapter sends params.body as text or JSON (spec 0001 §3); a present null is neither, and the request would go out without a body", "write the body to send, or leave params.body out to send none"))
		}
		switch t := b.(type) {
		case string:
			p.body = strings.NewReader(t)
		default:
			raw, err := json.Marshal(t)
			if err != nil {
				return bad(errorResult(pdr.CodeCheckpointError, fmt.Sprintf("http checkpoint %s: params.body cannot be sent as JSON", cp.ID), err.Error(), "fix params.body"))
			}
			p.body = strings.NewReader(string(raw))
		}
	}
	return p, nil
}

// unknownKey returns the first key of m, in sorted order, that is not
// among known.
func unknownKey(m map[string]any, known []string) (string, bool) {
	keys := make([]string, 0, len(m))
	for k := range m {
		if !slices.Contains(known, k) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return "", false
	}
	sort.Strings(keys)
	return keys[0], true
}

// checkParams refuses a params key the adapter does not read: silently
// skipped, a misspelt block would send a request the checkpoint did not
// describe.
func checkParams(cp lab.FlatCheckpoint, adapter string, known []string) *Result {
	k, stray := unknownKey(cp.Params, known)
	if !stray {
		return nil
	}
	res := errorResult(pdr.CodeCheckpointError, fmt.Sprintf("%s checkpoint %s: params.%s is not a parameter the %s adapter reads", adapter, cp.ID, k, adapter), fmt.Sprintf("the %s adapter reads %s (spec 0001 §3); a parameter it does not read would be skipped", adapter, strings.Join(known, ", ")), fmt.Sprintf("fix params.%s", k))
	return &res
}

// checkExpectations refuses an expect that the adapter would judge by
// nothing: no key at all, or a key it does not read. It returns nil when
// every key is one the adapter judges.
func checkExpectations(cp lab.FlatCheckpoint, adapter string, known []string) *Result {
	if len(cp.Expect) == 0 {
		res := errorResult(pdr.CodeCheckpointError, fmt.Sprintf("%s checkpoint %s: expect names nothing the adapter judges", adapter, cp.ID), fmt.Sprintf("the %s adapter judges %s (spec 0001 §3); an empty expectation would pass by asserting nothing", adapter, strings.Join(known, ", ")), "declare at least one expectation")
		return &res
	}
	keys := make([]string, 0, len(cp.Expect))
	for k := range cp.Expect {
		if !slices.Contains(known, k) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)
	res := errorResult(pdr.CodeCheckpointError, fmt.Sprintf("%s checkpoint %s: expect.%s is not an expectation the %s adapter judges", adapter, cp.ID, keys[0], adapter), fmt.Sprintf("the %s adapter judges %s (spec 0001 §3); an expectation it does not read would pass by being ignored", adapter, strings.Join(known, ", ")), fmt.Sprintf("fix expect.%s", keys[0]))
	return &res
}

// --- container --------------------------------------------------------

// containerAdapter: params service; expect state (running|stopped),
// healthy (bool), label {k, v}.
func (ev *Evaluator) containerAdapter(ctx context.Context, cp lab.FlatCheckpoint) Result {
	if res := checkExpectations(cp, "container", containerExpectations); res != nil {
		return *res
	}
	if res := checkParams(cp, "container", []string{"service"}); res != nil {
		return *res
	}
	service, _ := cp.Params["service"].(string)
	if service == "" {
		return errorResult(pdr.CodeCheckpointError, "container checkpoint "+cp.ID+" has no params.service", "the container adapter needs params.service (spec 0001 §3)", "")
	}
	facts, err := ev.Target.Container(ctx, service)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			return errorResult(pdr.CodeCheckpointTimeout, fmt.Sprintf("container checkpoint %s: inspecting service %s did not finish within the timeout", cp.ID, service), err.Error(), "")
		}
		return errorResult(pdr.CodeCheckpointError, fmt.Sprintf("container checkpoint %s cannot inspect service %s", cp.ID, service), err.Error(), "")
	}
	state := "absent"
	switch {
	case facts.Exists && facts.Running:
		state = "running"
	case facts.Exists:
		state = "stopped"
	}
	observed := map[string]any{"state": state, "healthy": facts.Healthy}
	var failures []string
	// The expectations are typed: the checkpoint schema leaves an
	// adapter's expectations open, so a value of the wrong shape — a
	// quoted "true", a state that is no state, a label that is not a
	// map — is a configuration error, never an expectation read as false
	// or skipped and so passed by accident.
	if want, ok := cp.Expect["state"]; ok {
		s := asText(want)
		if s != "running" && s != "stopped" && s != "absent" {
			return errorResult(pdr.CodeCheckpointError, fmt.Sprintf("container checkpoint %s: expect.state must be running, stopped or absent, not %s", cp.ID, s), "the container adapter's state expectation is one of those words (spec 0001 §3)", "fix expect.state")
		}
		if s != state {
			failures = append(failures, fmt.Sprintf("state %s, expected %s", state, s))
		}
	}
	if want, ok := cp.Expect["healthy"]; ok {
		wantB, isBool := want.(bool)
		if !isBool {
			return errorResult(pdr.CodeCheckpointError, fmt.Sprintf("container checkpoint %s: expect.healthy must be true or false, not %s", cp.ID, asText(want)), "the container adapter's healthy expectation is a boolean (spec 0001 §3); a quoted value is a string and cannot be judged", "fix expect.healthy")
		}
		if wantB != facts.Healthy {
			failures = append(failures, fmt.Sprintf("healthy %v, expected %v", facts.Healthy, wantB))
		}
	}
	if raw, ok := cp.Expect["label"]; ok {
		want, isMap := raw.(map[string]any)
		if !isMap {
			return errorResult(pdr.CodeCheckpointError, fmt.Sprintf("container checkpoint %s: expect.label must be a map of label names to values, not %s", cp.ID, asText(raw)), "the container adapter's label expectation is a map (spec 0001 §3)", "fix expect.label")
		}
		// An empty map asserts nothing and would pass on any container —
		// or none.
		if len(want) == 0 {
			return errorResult(pdr.CodeCheckpointError, fmt.Sprintf("container checkpoint %s: expect.label names no label", cp.ID), "the container adapter's label expectation names at least one label and its value (spec 0001 §3); an empty map would pass by asserting nothing", "fix expect.label")
		}
		labels := map[string]any{}
		keys := make([]string, 0, len(want))
		for k := range want {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			got, has := facts.Labels[k]
			if has {
				labels[k] = got
			} else {
				labels[k] = nil
			}
			if !has || got != asText(want[k]) {
				failures = append(failures, fmt.Sprintf("label %s is %q, expected %q", k, got, asText(want[k])))
			}
		}
		observed["label"] = labels
	}
	if len(failures) > 0 {
		return Result{Status: StatusFail, Observed: observed, Expected: cp.Expect, Message: "container " + service + ": " + strings.Join(failures, "; ")}
	}
	return Result{Status: StatusPass, Observed: observed, Expected: cp.Expect, Message: fmt.Sprintf("container %s is %s", service, state)}
}

// --- attest -----------------------------------------------------------

// AttestPrompt reads an attest checkpoint's definition: params carry
// exactly `prompt`, a non-empty string — the condition the human
// confirms — and expect nothing, since the adapter judges by the
// confirmation alone (spec 0001 §3). A typo (`promt`), a prompt of another
// shape or an expectation is a configuration error, never an empty
// prompt presented as generic self-confirmation that a `POST …/attest`
// could then mark attested without the authored condition ever shown.
// The engine asks the same question
// before it records a confirmation.
func AttestPrompt(cp lab.FlatCheckpoint) (string, *Result) {
	if len(cp.Expect) > 0 {
		k := ""
		for key := range cp.Expect {
			if k == "" || key < k {
				k = key
			}
		}
		res := errorResult(pdr.CodeCheckpointError, fmt.Sprintf("attest checkpoint %s: expect.%s is not an expectation the attest adapter judges", cp.ID, k), "the attest adapter judges by the human's confirmation alone (spec 0001 §3); an expectation would be ignored", "drop expect")
		return "", &res
	}
	if res := checkParams(cp, "attest", []string{"prompt"}); res != nil {
		return "", res
	}
	raw, has := cp.Params["prompt"]
	prompt, isString := raw.(string)
	if !has || !isString || strings.TrimSpace(prompt) == "" {
		res := errorResult(pdr.CodeCheckpointError, fmt.Sprintf("attest checkpoint %s: params.prompt must be a non-empty string naming what the human confirms", cp.ID), "the attest adapter presents params.prompt for confirmation (spec 0001 §3); a missing or empty one would present nothing, and a confirmation of nothing is no confirmation", "set params.prompt")
		return "", &res
	}
	return strings.TrimSpace(prompt), nil
}

// attestAdapter: a machine evaluation of an attest checkpoint records
// that no human has confirmed it (fail, expected red at create); the
// confirmation itself lands through the attest endpoint as `attested`
// and is never upgraded to a machine pass (spec 0001 §3).
func attestAdapter(cp lab.FlatCheckpoint) Result {
	prompt, bad := AttestPrompt(cp)
	if bad != nil {
		return *bad
	}
	return Result{Status: StatusFail, Observed: map[string]any{"attested": false}, Expected: map[string]any{"attested": true}, Message: "awaiting self-confirmation: " + prompt}
}
