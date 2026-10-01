// SPDX-License-Identifier: AGPL-3.0-only

package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/lab"
	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// stubTarget resolves one service to an httptest server and reports
// container facts.
type stubTarget struct {
	service string
	port    int
	addr    string
	facts   *ContainerFacts
}

func (s *stubTarget) Resolve(service string, port int) (string, error) {
	if service != s.service {
		return "", fmt.Errorf("no such service %q (services: %s)", service, s.service)
	}
	if port != s.port {
		return "", fmt.Errorf("service %s publishes no port %d (published: %d)", service, port, s.port)
	}
	return s.addr, nil
}

func (s *stubTarget) Dial(ctx context.Context, service string, port int) (net.Conn, error) {
	addr, err := s.Resolve(service, port)
	if err != nil {
		return nil, err
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
}

func (s *stubTarget) Container(_ context.Context, service string) (*ContainerFacts, error) {
	if service != s.service || s.facts == nil {
		return nil, fmt.Errorf("no such service %q", service)
	}
	return s.facts, nil
}

func cp(id, adapter string, params, expect map[string]any) lab.FlatCheckpoint {
	return lab.FlatCheckpoint{Checkpoint: lab.Checkpoint{ID: id, Adapter: adapter, Params: params, Expect: expect, Retries: &lab.Retries{Attempts: 1}}, ResolvedClass: "baseline"}
}

func newEvaluator(t *testing.T, handler http.HandlerFunc) (*Evaluator, *stubTarget) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	target := &stubTarget{service: "prometheus", port: 9090, addr: strings.TrimPrefix(srv.URL, "http://")}
	ev := New(target, nil)
	ev.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	return ev, target
}

// An attest checkpoint's params are exactly a non-empty prompt, and it
// expects nothing: a typo (`promt`), a prompt of another shape, a key the
// adapter does not read or an expectation is a configuration error —
// never an empty prompt presented as generic self-confirmation.
func TestAttestParamsAreExactlyAPrompt(t *testing.T) {
	ev, _ := newEvaluator(t, func(w http.ResponseWriter, r *http.Request) {})
	ctx := context.Background()
	good := cp("ok", "attest", map[string]any{"prompt": "I looked at the page."}, nil)
	res := ev.Evaluate(ctx, good)
	if res.Status != StatusFail || res.Message != "awaiting self-confirmation: I looked at the page." {
		t.Fatalf("a well-formed attest awaits its confirmation: %+v", res)
	}
	if p, bad := AttestPrompt(good); bad != nil || p != "I looked at the page." {
		t.Fatalf("AttestPrompt: %q %+v", p, bad)
	}
	for _, tc := range []struct {
		name    string
		cp      lab.FlatCheckpoint
		mention string
	}{
		{"typo", cp("a", "attest", map[string]any{"promt": "Review the dashboard"}, nil), "params.promt"},
		{"shape", cp("a", "attest", map[string]any{"prompt": 7}, nil), "params.prompt"},
		{"empty", cp("a", "attest", map[string]any{"prompt": "  "}, nil), "params.prompt"},
		{"missing", cp("a", "attest", map[string]any{}, nil), "params.prompt"},
		{"none", cp("a", "attest", nil, nil), "params.prompt"},
		{"expect", cp("a", "attest", map[string]any{"prompt": "x"}, map[string]any{"attested": true}), "expect.attested"},
	} {
		res := ev.Evaluate(ctx, tc.cp)
		if res.Status != StatusError || res.Error == nil || res.Error.Code != pdr.CodeCheckpointError || !strings.Contains(res.Error.Message, tc.mention) {
			t.Errorf("%s: %+v", tc.name, res)
		}
		if _, bad := AttestPrompt(tc.cp); bad == nil {
			t.Errorf("%s: AttestPrompt accepted it", tc.name)
		}
	}
}

// A present null body is not the absence it would otherwise read as: a
// POST with `body: null` is refused before anything is sent, never a
// bodiless request judged as authored.
func TestHTTPNullBodyIsRefused(t *testing.T) {
	var hits atomic.Int64
	ev, _ := newEvaluator(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1) })
	res := ev.Evaluate(context.Background(), cp("nb", "http", map[string]any{"url": "http://prometheus:9090/-/reload", "method": "POST", "body": nil}, map[string]any{"status": 200}))
	if res.Status != StatusError || res.Error == nil || res.Error.Code != pdr.CodeCheckpointError || !strings.Contains(res.Error.Message, "params.body is null") {
		t.Fatalf("a null body is refused: %+v", res)
	}
	if hits.Load() != 0 {
		t.Fatalf("nothing is sent for a null body: %d requests", hits.Load())
	}
}

func TestHTTPAdapterAssertions(t *testing.T) {
	var host atomic.Value
	ev, _ := newEvaluator(t, func(w http.ResponseWriter, r *http.Request) {
		host.Store(r.Host)
		switch r.URL.Path {
		case "/-/ready":
			w.WriteHeader(200)
			fmt.Fprint(w, "Prometheus Server is Ready.")
		case "/api/v1/query":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1725537600,"312"]}]}}`)
		case "/empty":
			fmt.Fprint(w, `{"status":"success","data":{"result":[]}}`)
		case "/text":
			fmt.Fprint(w, "not json")
		case "/echo":
			w.Header().Set("Content-Type", "application/json")
			body := make([]byte, 64)
			n, _ := r.Body.Read(body)
			fmt.Fprintf(w, `{"method":%q,"body":%q,"header":%q}`, r.Method, string(body[:n]), r.Header.Get("X-Test"))
		default:
			w.WriteHeader(404)
		}
	})
	ctx := context.Background()
	res := ev.Evaluate(ctx, cp("ready", "http", map[string]any{"url": "http://prometheus:9090/-/ready"}, map[string]any{"status": 200}))
	if res.Status != StatusPass || res.Attempts != 1 || !strings.Contains(res.Message, "GET http://prometheus:9090/-/ready → 200") || res.Duration < 0 {
		t.Fatalf("status pass: %+v", res)
	}
	if h, _ := host.Load().(string); h != "prometheus:9090" {
		t.Fatalf("the in-lab Host header must reach the product: %q", h)
	}
	if obs, _ := json.Marshal(res.Observed); string(obs) != `{"status":200}` {
		t.Fatalf("observed: %s", obs)
	}
	res = ev.Evaluate(ctx, cp("ready", "http", map[string]any{"url": "http://prometheus:9090/-/ready"}, map[string]any{"status": 503})) // a number: quoted text is a configuration error since round 36
	if res.Status != StatusFail || !strings.Contains(res.Message, "status 200, expected 503") {
		t.Fatalf("status fail: %+v", res)
	}
	res = ev.Evaluate(ctx, cp("body", "http", map[string]any{"url": "http://prometheus:9090/-/ready"}, map[string]any{"body_contains": "Ready"}))
	if res.Status != StatusPass {
		t.Fatalf("body_contains pass: %+v", res)
	}
	res = ev.Evaluate(ctx, cp("body", "http", map[string]any{"url": "http://prometheus:9090/-/ready"}, map[string]any{"body_contains": "Broken"}))
	if res.Status != StatusFail || !strings.Contains(res.Message, `body does not contain "Broken"`) {
		t.Fatalf("body_contains fail: %+v", res)
	}
	// json_path: numbers compare as numbers whatever their JSON type.
	q := map[string]any{"url": "http://prometheus:9090/api/v1/query?query=sum(prometheus_http_requests_total)"}
	for _, tc := range []struct {
		op    string
		value any
		want  string
	}{
		{"gte", "200", StatusPass}, {"gte", 400, StatusFail}, {"eq", "312", StatusPass}, {"eq", 312, StatusPass}, {"lt", "312", StatusFail}, {"ne", "1", StatusPass}, {"contains", "31", StatusPass}, {"exists", nil, StatusPass},
	} {
		res = ev.Evaluate(ctx, cp("q", "http", q, map[string]any{"json_path": map[string]any{"path": "$.data.result[0].value[1]", "op": tc.op, "value": tc.value}}))
		if res.Status != tc.want {
			t.Errorf("json_path %s %v: %s (%s)", tc.op, tc.value, res.Status, res.Message)
		}
	}
	res = ev.Evaluate(ctx, cp("q", "http", q, map[string]any{"json_path": map[string]any{"path": "$.data.result[0].value[1]", "op": "gte", "value": "200"}}))
	if obs, _ := json.Marshal(res.Observed); string(obs) != `{"json_path":"312","status":200}` || !strings.Contains(res.Message, "json_path 312") {
		t.Fatalf("observed json_path: %s %s", obs, res.Message)
	}
	// A missing element fails (the adapter did evaluate); observed says null.
	res = ev.Evaluate(ctx, cp("q", "http", map[string]any{"url": "http://prometheus:9090/empty"}, map[string]any{"json_path": map[string]any{"path": "$.data.result[0].value[1]", "op": "eq", "value": "1"}}))
	if res.Status != StatusFail || !strings.Contains(res.Message, "no such element") {
		t.Fatalf("missing element: %+v", res)
	}
	if obs, _ := json.Marshal(res.Observed); string(obs) != `{"json_path":null,"status":200}` {
		t.Fatalf("observed missing: %s", obs)
	}
	// Not JSON where json_path is asked is an error, not a fail.
	res = ev.Evaluate(ctx, cp("q", "http", map[string]any{"url": "http://prometheus:9090/text"}, map[string]any{"json_path": map[string]any{"path": "$.x", "op": "eq", "value": "1"}}))
	if res.Status != StatusError || res.Error == nil || res.Error.Code != pdr.CodeCheckpointError || !strings.Contains(res.Error.Message, "not JSON") {
		t.Fatalf("not json: %+v", res)
	}
	// A bad path or op is an error naming the fix.
	res = ev.Evaluate(ctx, cp("q", "http", q, map[string]any{"json_path": map[string]any{"path": "data.x", "op": "eq", "value": "1"}}))
	if res.Status != StatusError || !strings.Contains(res.Error.Message, "must start with $") {
		t.Fatalf("bad path: %+v", res)
	}
	res = ev.Evaluate(ctx, cp("q", "http", q, map[string]any{"json_path": map[string]any{"path": "$.status", "op": "matches", "value": "1"}}))
	if res.Status != StatusError || !strings.Contains(res.Error.Message, "op") {
		t.Fatalf("bad op: %+v", res)
	}
	// Method, headers, and body reach the product; the default is GET.
	res = ev.Evaluate(ctx, cp("echo", "http", map[string]any{"url": "http://prometheus:9090/echo", "method": "post", "headers": map[string]any{"X-Test": "yes"}, "body": map[string]any{"a": 1}},
		map[string]any{"json_path": map[string]any{"path": "$.body", "op": "eq", "value": `{"a":1}`}}))
	if res.Status != StatusPass {
		t.Fatalf("post body: %+v", res)
	}
	res = ev.Evaluate(ctx, cp("echo", "http", map[string]any{"url": "http://prometheus:9090/echo"}, map[string]any{"json_path": map[string]any{"path": "$.method", "op": "eq", "value": "GET"}}))
	if res.Status != StatusPass {
		t.Fatalf("default method: %+v", res)
	}
	// Errors: no url; a url naming a port the service does not publish; an
	// unknown service; not http(s).
	for _, params := range []map[string]any{{}, {"url": "http://prometheus:9091/"}, {"url": "http://nope:9090/"}, {"url": "ftp://prometheus:21/"}} {
		res = ev.Evaluate(ctx, cp("bad", "http", params, map[string]any{"status": 200}))
		if res.Status != StatusError || res.Error == nil || res.Error.Code != pdr.CodeCheckpointError {
			t.Errorf("params %v: %+v", params, res)
		}
	}
	// Expected always carries the authored expectation.
	if exp, _ := json.Marshal(res.Expected); string(exp) != `{"status":200}` {
		t.Fatalf("expected: %s", exp)
	}
}

func TestRetriesTimeoutsAndFinalErrors(t *testing.T) {
	var calls atomic.Int32
	ev, target := newEvaluator(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/flaky":
			if calls.Add(1) < 3 {
				w.WriteHeader(503)
				return
			}
			w.WriteHeader(200)
		case "/slow":
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
			w.WriteHeader(200)
		}
	})
	sleeps := 0
	ev.Sleep = func(ctx context.Context, d time.Duration) error {
		sleeps++
		if d != 7*time.Millisecond {
			t.Errorf("backoff %s", d)
		}
		return nil
	}
	ctx := context.Background()
	flaky := cp("flaky", "http", map[string]any{"url": "http://prometheus:9090/flaky"}, map[string]any{"status": 200})
	flaky.Retries = &lab.Retries{Attempts: 4, Backoff: "7ms"}
	res := ev.Evaluate(ctx, flaky)
	if res.Status != StatusPass || res.Attempts != 3 || sleeps != 2 {
		t.Fatalf("retried to a pass: %+v sleeps=%d", res, sleeps)
	}
	// Attempts spent: the last attempt's verdict stands.
	calls.Store(0)
	flaky.Retries = &lab.Retries{Attempts: 2, Backoff: "7ms"}
	res = ev.Evaluate(ctx, flaky)
	if res.Status != StatusFail || res.Attempts != 2 {
		t.Fatalf("attempts spent: %+v", res)
	}
	// Timeout per attempt: PDR-E401, retried, then final.
	slow := cp("slow", "http", map[string]any{"url": "http://prometheus:9090/slow"}, map[string]any{"status": 200})
	slow.Timeout = "30ms"
	slow.Retries = &lab.Retries{Attempts: 2, Backoff: "7ms"}
	start := time.Now()
	res = ev.Evaluate(ctx, slow)
	if res.Status != StatusError || res.Error == nil || res.Error.Code != pdr.CodeCheckpointTimeout || res.Attempts != 2 || time.Since(start) > time.Second {
		t.Fatalf("timeout: %+v (%s)", res, time.Since(start))
	}
	// Defaults (spec 0001 §2): 30s, 3 attempts, 5s backoff.
	if to, at, bo := Budget(lab.Checkpoint{}); to != 30*time.Second || at != 3 || bo != 5*time.Second {
		t.Fatalf("defaults: %s %d %s", to, at, bo)
	}
	if to, at, bo := Budget(lab.Checkpoint{Timeout: "2s", Retries: &lab.Retries{Attempts: 6, Backoff: "500ms"}}); to != 2*time.Second || at != 6 || bo != 500*time.Millisecond {
		t.Fatalf("declared: %s %d %s", to, at, bo)
	}
	// Adapters this release lacks are one error, not three retries. The
	// golden lab's adapters are no longer among them (plan S8), so the
	// case is a name that is neither a built-in nor a module's alias —
	// which reaches the exec runner, and there is none here.
	sleeps = 0
	unavailable := cp("k", "kafka-lag", map[string]any{"topic": "orders"}, map[string]any{"count": ">=0"})
	unavailable.Retries = &lab.Retries{Attempts: 3, Backoff: "1ms"}
	res = ev.Evaluate(ctx, unavailable)
	if res.Status != StatusError || res.Error.Code != pdr.CodeAdapterUnavailable || res.Attempts != 1 || sleeps != 0 {
		t.Fatalf("unavailable adapter: %+v", res)
	}
	// exec without a runner: unavailable; with one: called with the timeout.
	res = ev.Evaluate(ctx, cp("x", "exec", map[string]any{"image": "i@sha256:x"}, nil))
	if res.Status != StatusError || res.Error.Code != pdr.CodeAdapterUnavailable {
		t.Fatalf("exec without runner: %+v", res)
	}
	var gotTimeout time.Duration
	ev.Exec = func(ctx context.Context, c lab.FlatCheckpoint, timeout time.Duration) Result {
		gotTimeout = timeout
		return Result{Status: StatusPass, Observed: map[string]any{"lag": 0}, Message: "judged"}
	}
	ex := cp("x", "exec", map[string]any{"image": "i@sha256:x"}, map[string]any{"lag": 0})
	ex.Timeout = "9s"
	res = ev.Evaluate(ctx, ex)
	if res.Status != StatusPass || gotTimeout != 9*time.Second || res.Message != "judged" {
		t.Fatalf("exec hook: %+v %s", res, gotTimeout)
	}
	// A module alias name the engine sees unexpanded runs as exec too.
	res = ev.Evaluate(ctx, cp("k", "kafka-lag", map[string]any{"image": "i@sha256:x"}, nil))
	if res.Status != StatusPass {
		t.Fatalf("alias runs through exec: %+v", res)
	}
	// A cancelled context stops the loop without a verdict being invented.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	res = ev.Evaluate(cctx, flaky)
	if res.Status == StatusPass {
		t.Fatalf("a cancelled evaluation must not pass: %+v", res)
	}
	_ = target
}

func TestContainerAndAttestAdapters(t *testing.T) {
	ev, target := newEvaluator(t, func(w http.ResponseWriter, r *http.Request) {})
	ctx := context.Background()
	target.facts = &ContainerFacts{Exists: true, Running: true, Healthy: true, Labels: map[string]string{"dev.podaro/service": "prometheus"}, Stage: "healthy"}
	res := ev.Evaluate(ctx, cp("c", "container", map[string]any{"service": "prometheus"}, map[string]any{"state": "running", "healthy": true, "label": map[string]any{"dev.podaro/service": "prometheus"}}))
	if res.Status != StatusPass || !strings.Contains(res.Message, "prometheus is running") {
		t.Fatalf("container pass: %+v", res)
	}
	if obs, _ := json.Marshal(res.Observed); string(obs) != `{"healthy":true,"label":{"dev.podaro/service":"prometheus"},"state":"running"}` {
		t.Fatalf("observed: %s", obs)
	}
	target.facts.Running = false
	target.facts.Healthy = false
	res = ev.Evaluate(ctx, cp("c", "container", map[string]any{"service": "prometheus"}, map[string]any{"state": "running", "healthy": true, "label": map[string]any{"missing": "x"}}))
	if res.Status != StatusFail || !strings.Contains(res.Message, "state stopped, expected running") || !strings.Contains(res.Message, "healthy false, expected true") || !strings.Contains(res.Message, `label missing is "", expected "x"`) {
		t.Fatalf("container fail: %+v", res)
	}
	target.facts.Exists = false
	res = ev.Evaluate(ctx, cp("c", "container", map[string]any{"service": "prometheus"}, map[string]any{"state": "absent"}))
	if res.Status != StatusPass {
		t.Fatalf("absent: %+v", res)
	}
	res = ev.Evaluate(ctx, cp("c", "container", map[string]any{"service": "nope"}, map[string]any{"state": "running"}))
	if res.Status != StatusError || res.Error.Code != pdr.CodeCheckpointError {
		t.Fatalf("unknown service: %+v", res)
	}
	res = ev.Evaluate(ctx, cp("c", "container", map[string]any{}, map[string]any{"state": "running"}))
	if res.Status != StatusError {
		t.Fatalf("no service: %+v", res)
	}
	// attest: a machine evaluation records the missing confirmation.
	res = ev.Evaluate(ctx, cp("a", "attest", map[string]any{"prompt": "I found the route."}, nil))
	if res.Status != StatusFail || res.Message != "awaiting self-confirmation: I found the route." {
		t.Fatalf("attest: %+v", res)
	}
	if obs, _ := json.Marshal(res.Observed); string(obs) != `{"attested":false}` {
		t.Fatalf("attest observed: %s", obs)
	}
}

func TestJSONPathLookupAndCompare(t *testing.T) {
	var doc any
	_ = json.Unmarshal([]byte(`{"data":{"result":[{"value":[1,"312"]},{"value":[2,"7"]}]},"list":[{"title":"Lab Overview"}],"n":5,"ok":true,"s":"x"}`), &doc)
	for _, tc := range []struct {
		path  string
		want  string
		found bool
	}{
		{"$.data.result[0].value[1]", `"312"`, true},
		{"$.data.result[1].value[0]", `2`, true},
		{"$[0]", "", false},
		{"$.list[0].title", `"Lab Overview"`, true},
		{"$.list[0]['title']", `"Lab Overview"`, true},
		{"$.list[1].title", "", false},
		{"$.n", `5`, true},
		{"$.ok", `true`, true},
		{"$.missing.deeper", "", false},
		{"$", `{"data":{"result":[{"value":[1,"312"]},{"value":[2,"7"]}]},"list":[{"title":"Lab Overview"}],"n":5,"ok":true,"s":"x"}`, true},
	} {
		v, found, err := jsonPathLookup(doc, tc.path)
		if err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}
		if found != tc.found {
			t.Errorf("%s: found %v", tc.path, found)
			continue
		}
		if found {
			if got, _ := json.Marshal(v); string(got) != tc.want {
				t.Errorf("%s = %s, want %s", tc.path, got, tc.want)
			}
		}
	}
	for _, bad := range []string{"data.x", "$.", "$[0", "$x"} {
		if _, _, err := jsonPathLookup(doc, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, tc := range []struct {
		op   string
		obs  any
		val  any
		want bool
	}{
		{"eq", "312", 312.0, true}, {"eq", "Lab Overview", "Lab Overview", true}, {"eq", "1", "1.0", true},
		{"ne", "1", "2", true}, {"gt", "312", "200", true}, {"gte", 200.0, "200", true}, {"lt", "5", 4, false}, {"lte", "b", "a", false},
		{"contains", "Lab Overview", "Over", true}, {"", true, "true", true}, {"eq", nil, "null", true},
	} {
		got, err := compare(tc.op, tc.obs, true, tc.val)
		if err != nil || got != tc.want {
			t.Errorf("compare %s %v %v = %v (%v), want %v", tc.op, tc.obs, tc.val, got, err, tc.want)
		}
	}
	if ok, _ := compare("exists", nil, false, nil); ok {
		t.Error("exists on a missing element")
	}
	if ok, _ := compare("ne", nil, false, "x"); !ok {
		t.Error("ne on a missing element holds")
	}
	if _, err := compare("matches", "a", true, "a"); err == nil {
		t.Error("unknown op accepted")
	}
}

// blockingTarget is a target whose inspect never answers on its own: it
// returns only when the attempt's context ends.
type blockingTarget struct{ stubTarget }

func (b *blockingTarget) Container(ctx context.Context, service string) (*ContainerFacts, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// A container checkpoint whose inspect stalls ends with the checkpoint's
// own timeout — PDR-E401 — instead of holding the run: the attempt's
// context reaches the target (lab.go:159).
func TestContainerAdapterHonorsTheAttemptDeadline(t *testing.T) {
	ev := New(&blockingTarget{}, nil)
	ev.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	stuck := lab.FlatCheckpoint{Checkpoint: lab.Checkpoint{ID: "stuck", Adapter: "container", Params: map[string]any{"service": "web"}, Expect: map[string]any{"state": "running"}, Timeout: "100ms", Retries: &lab.Retries{Attempts: 1}}, ResolvedClass: "baseline"}
	done := make(chan Result, 1)
	go func() { done <- ev.Evaluate(context.Background(), stuck) }()
	select {
	case res := <-done:
		if res.Status != StatusError || res.Error == nil || res.Error.Code != pdr.CodeCheckpointTimeout {
			t.Fatalf("a stalled inspect must be the checkpoint's timeout: %+v", res)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the evaluation hung on a stalled inspect: the attempt's deadline never reached the target")
	}
}

// json_path compares integers exactly, whatever their size: two integer
// literals that differ only beyond a double's 53 bits are different numbers
// — and the observed value is recorded as the literal, not a rounded double
// (verify.go:440).
func TestJSONPathComparesIntegersExactly(t *testing.T) {
	ev, _ := newEvaluator(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"n":9007199254740993,"m":12345678901234567890,"f":1.5}`)
	})
	ctx := context.Background()
	q := map[string]any{"url": "http://prometheus:9090/big"}
	for _, tc := range []struct {
		path  string
		op    string
		value any
		want  string
	}{
		{"$.n", "eq", 9007199254740992, StatusFail},
		{"$.n", "eq", 9007199254740993, StatusPass},
		{"$.n", "eq", "9007199254740993", StatusPass},
		{"$.n", "gt", 9007199254740992, StatusPass},
		{"$.n", "lte", 9007199254740992, StatusFail},
		{"$.m", "eq", "12345678901234567890", StatusPass},
		{"$.m", "ne", "12345678901234567891", StatusPass},
		{"$.m", "eq", "12345678901234567891", StatusFail},
		{"$.f", "eq", 1.5, StatusPass},
		{"$.f", "gt", 1, StatusPass},
	} {
		res := ev.Evaluate(ctx, cp("big", "http", q, map[string]any{"json_path": map[string]any{"path": tc.path, "op": tc.op, "value": tc.value}}))
		if res.Status != tc.want {
			t.Errorf("json_path %s %s %v: %s (%s)", tc.path, tc.op, tc.value, res.Status, res.Message)
		}
	}
	res := ev.Evaluate(ctx, cp("big", "http", q, map[string]any{"json_path": map[string]any{"path": "$.n", "op": "eq", "value": 9007199254740993}}))
	if obs, _ := json.Marshal(res.Observed); string(obs) != `{"json_path":9007199254740993,"status":200}` {
		t.Fatalf("the observed integer is recorded exactly: %s", obs)
	}
}

// json_path judges exactly one JSON document: a body with a second value,
// or stray bytes after the first, is an error — never a pass on the valid
// prefix — while trailing whitespace is still one document (verify.go:374).
func TestJSONPathRejectsTrailingData(t *testing.T) {
	ev, _ := newEvaluator(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/two":
			fmt.Fprint(w, `{"n":1} {"n":2}`)
		case "/garbage":
			fmt.Fprint(w, `{"n":1}garbage`)
		case "/ws":
			fmt.Fprint(w, "{\"n\":1}\n  \n")
		default:
			w.WriteHeader(404)
		}
	})
	ctx := context.Background()
	for _, path := range []string{"/two", "/garbage"} {
		res := ev.Evaluate(ctx, cp("trail", "http", map[string]any{"url": "http://prometheus:9090" + path}, map[string]any{"json_path": map[string]any{"path": "$.n", "op": "eq", "value": 1}}))
		if res.Status != StatusError || res.Error == nil || !strings.Contains(res.Error.Message, "trailing data") {
			t.Errorf("%s: a body that is not one JSON document is an error, not a judged answer: %s (%s)", path, res.Status, res.Message)
		}
	}
	res := ev.Evaluate(ctx, cp("trail", "http", map[string]any{"url": "http://prometheus:9090/ws"}, map[string]any{"json_path": map[string]any{"path": "$.n", "op": "eq", "value": 1}}))
	if res.Status != StatusPass {
		t.Fatalf("trailing whitespace is still one document: %s (%s)", res.Status, res.Message)
	}
}

// A container expectation of the wrong shape is a configuration error,
// never a value read as false or skipped and so passed by accident (verify.go:500).
func TestContainerAdapterRejectsMalformedExpectations(t *testing.T) {
	ev, target := newEvaluator(t, func(w http.ResponseWriter, r *http.Request) {})
	ctx := context.Background()
	target.facts = &ContainerFacts{Exists: true, Running: true, Healthy: false, Labels: map[string]string{"dev.podaro/service": "prometheus"}, Stage: "connected"}
	params := map[string]any{"service": "prometheus"}
	for name, expect := range map[string]map[string]any{
		"quoted healthy":  {"healthy": "true"},
		"numeric healthy": {"healthy": 1},
		"unknown state":   {"state": "flying"},
		"string label":    {"label": "a=b"},
		"empty label":     {"label": map[string]any{}},
	} {
		res := ev.Evaluate(ctx, cp("c", "container", params, expect))
		if res.Status != StatusError || res.Error == nil || res.Error.Code != pdr.CodeCheckpointError {
			t.Errorf("%s: want a configuration error, got %s (%s)", name, res.Status, res.Message)
		}
	}
	// The well-typed expectations still judge the facts.
	if res := ev.Evaluate(ctx, cp("c", "container", params, map[string]any{"healthy": false})); res.Status != StatusPass {
		t.Fatalf("healthy false against an unhealthy container: %s (%s)", res.Status, res.Message)
	}
	if res := ev.Evaluate(ctx, cp("c", "container", params, map[string]any{"healthy": true})); res.Status != StatusFail || !strings.Contains(res.Message, "healthy false, expected true") {
		t.Fatalf("healthy true against an unhealthy container: %s (%s)", res.Status, res.Message)
	}
}

// A body larger than the adapter judges is an error for the expectations
// that read it: the tail — a second document, the needle — is unknown, so
// the first bytes never pass for the whole (verify.go:347).
func TestHTTPAdapterRefusesAnOversizedBody(t *testing.T) {
	filler := strings.Repeat(" ", 4<<20)
	ev, _ := newEvaluator(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/big":
			fmt.Fprint(w, `{"n":1}`+filler+`{"n":2}`)
		case "/needle":
			fmt.Fprint(w, filler+"needle")
		default:
			w.WriteHeader(404)
		}
	})
	ctx := context.Background()
	res := ev.Evaluate(ctx, cp("big", "http", map[string]any{"url": "http://prometheus:9090/big"}, map[string]any{"json_path": map[string]any{"path": "$.n", "op": "eq", "value": 1}}))
	if res.Status != StatusError || res.Error == nil || !strings.Contains(res.Error.Message, "larger than 4 MiB") {
		t.Fatalf("json_path on an oversized body: %s (%s)", res.Status, res.Message)
	}
	res = ev.Evaluate(ctx, cp("big", "http", map[string]any{"url": "http://prometheus:9090/needle"}, map[string]any{"body_contains": "needle"}))
	if res.Status != StatusError || res.Error == nil || !strings.Contains(res.Error.Message, "larger than 4 MiB") {
		t.Fatalf("body_contains on an oversized body: %s (%s)", res.Status, res.Message)
	}
	// An expectation that reads nothing of the body still judges the answer.
	res = ev.Evaluate(ctx, cp("big", "http", map[string]any{"url": "http://prometheus:9090/big"}, map[string]any{"status": 200}))
	if res.Status != StatusPass {
		t.Fatalf("status alone on an oversized body: %s (%s)", res.Status, res.Message)
	}
}

// An http expectation of the wrong shape, one the adapter does not judge,
// or none at all is a configuration error: an expectation skipped or
// ignored would pass on any reachable endpoint (verify.go:376).
func TestHTTPAdapterRejectsMalformedExpectations(t *testing.T) {
	ev, _ := newEvaluator(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})
	ctx := context.Background()
	params := map[string]any{"url": "http://prometheus:9090/"}
	for name, expect := range map[string]map[string]any{
		"bare json_path":          {"json_path": "$.ok"},
		"json_path sans path":     {"json_path": map[string]any{"op": "exists"}},
		"status word":             {"status": "ok"},
		"status fraction":         {"status": 200.5},
		"status out of range":     {"status": 2000},
		"status quoted":           {"status": "200"},
		"empty needle":            {"body_contains": ""},
		"json_path stray field":   {"json_path": map[string]any{"path": "$.ok", "value": true, "operator": "ne"}},
		"needle map":              {"body_contains": map[string]any{"a": 1}},
		"unknown key":             {"code": 200},
		"typo beside a valid key": {"status": 200, "json_paths": map[string]any{"path": "$.ok", "op": "exists"}},
		"nothing":                 {},
	} {
		res := ev.Evaluate(ctx, cp("h", "http", params, expect))
		if res.Status != StatusError || res.Error == nil || res.Error.Code != pdr.CodeCheckpointError {
			t.Errorf("%s: want a configuration error, got %s (%s)", name, res.Status, res.Message)
		}
	}
	if res := ev.Evaluate(ctx, cp("h", "http", params, nil)); res.Status != StatusError {
		t.Errorf("no expect at all: want a configuration error, got %s (%s)", res.Status, res.Message)
	}
	// The well-typed expectations still judge the answer; a quoted status is text, not a code (round 36).
	for name, expect := range map[string]map[string]any{
		"status":    {"status": 200},
		"json_path": {"json_path": map[string]any{"path": "$.ok", "op": "exists"}},
		"needle":    {"body_contains": `"ok"`},
	} {
		if res := ev.Evaluate(ctx, cp("h", "http", params, expect)); res.Status != StatusPass {
			t.Errorf("%s: %s (%s)", name, res.Status, res.Message)
		}
	}
}

// A container expectation the adapter does not judge, or none at all, is a
// configuration error too.
func TestContainerAdapterRejectsUnknownOrEmptyExpectations(t *testing.T) {
	ev, target := newEvaluator(t, func(w http.ResponseWriter, r *http.Request) {})
	ctx := context.Background()
	target.facts = &ContainerFacts{Exists: true, Running: true, Healthy: true, Stage: "healthy"}
	params := map[string]any{"service": "prometheus"}
	for name, expect := range map[string]map[string]any{
		"typo":    {"healty": true},
		"nothing": {},
	} {
		res := ev.Evaluate(ctx, cp("c", "container", params, expect))
		if res.Status != StatusError || res.Error == nil || res.Error.Code != pdr.CodeCheckpointError {
			t.Errorf("%s: want a configuration error, got %s (%s)", name, res.Status, res.Message)
		}
	}
	if res := ev.Evaluate(ctx, cp("c", "container", params, nil)); res.Status != StatusError {
		t.Errorf("no expect at all: want a configuration error, got %s (%s)", res.Status, res.Message)
	}
	if res := ev.Evaluate(ctx, cp("c", "container", params, map[string]any{"state": "running", "healthy": true})); res.Status != StatusPass {
		t.Fatalf("well-typed expectations still judge: %s (%s)", res.Status, res.Message)
	}
}

// A json_path operator given as anything but a word is a configuration
// error, never the default eq (verify.go:403).
func TestJSONPathRejectsANonStringOperator(t *testing.T) {
	ev, _ := newEvaluator(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true,"n":1}`)
	})
	ctx := context.Background()
	params := map[string]any{"url": "http://prometheus:9090/"}
	for name, op := range map[string]any{"bool": true, "number": 1, "map": map[string]any{"eq": true}, "empty": ""} {
		res := ev.Evaluate(ctx, cp("h", "http", params, map[string]any{"json_path": map[string]any{"path": "$.ok", "op": op, "value": true}}))
		if res.Status != StatusError || res.Error == nil || res.Error.Code != pdr.CodeCheckpointError {
			t.Errorf("op %s: want a configuration error, got %s (%s)", name, res.Status, res.Message)
		}
	}
	// An omitted operator is still eq; a misspelt one is still an error.
	if res := ev.Evaluate(ctx, cp("h", "http", params, map[string]any{"json_path": map[string]any{"path": "$.n", "value": 1}})); res.Status != StatusPass {
		t.Fatalf("omitted op: %s (%s)", res.Status, res.Message)
	}
	if res := ev.Evaluate(ctx, cp("h", "http", params, map[string]any{"json_path": map[string]any{"path": "$.n", "op": "equals", "value": 1}})); res.Status != StatusError {
		t.Fatalf("misspelt op: %s (%s)", res.Status, res.Message)
	}
}

// The http expectation is read and typed before the request is sent: a
// misconfigured checkpoint has no side effects — a POST with a malformed
// expectation must not reach the product before the configuration error
// is reported (verify.go:344).
func TestHTTPAdapterValidatesExpectationsBeforeTheRequest(t *testing.T) {
	var hits atomic.Int32
	ev, _ := newEvaluator(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})
	ctx := context.Background()
	params := map[string]any{"url": "http://prometheus:9090/mutate", "method": "POST", "body": map[string]any{"drop": "everything"}}
	for name, expect := range map[string]map[string]any{
		"needle bool":     {"body_contains": true},
		"bare json_path":  {"json_path": "$.ok"},
		"status word":     {"status": "ok"},
		"status quoted":   {"status": "204"},
		"empty needle":    {"body_contains": ""},
		"stray field":     {"json_path": map[string]any{"path": "$.ok", "value": true, "operator": "ne"}},
		"op number":       {"json_path": map[string]any{"path": "$.ok", "op": 7}},
		"op misspelt":     {"json_path": map[string]any{"path": "$.ok", "op": "equals", "value": true}},
		"sans value":      {"json_path": map[string]any{"path": "$.ok"}},
		"unknown key":     {"code": 200},
		"nothing at all":  {},
		"typo beside key": {"status": 200, "json_paths": map[string]any{"path": "$.ok"}},
	} {
		res := ev.Evaluate(ctx, cp("m", "http", params, expect))
		if res.Status != StatusError || res.Error == nil || res.Error.Code != pdr.CodeCheckpointError {
			t.Errorf("%s: want a configuration error, got %s (%s)", name, res.Status, res.Message)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("a misconfigured checkpoint reached the product %d time(s) before its error", n)
	}
	// A well-formed expectation still sends the request and judges it.
	if res := ev.Evaluate(ctx, cp("m", "http", params, map[string]any{"status": 200, "json_path": map[string]any{"path": "$.ok", "op": "eq", "value": true}})); res.Status != StatusPass || hits.Load() != 1 {
		t.Fatalf("well-formed: %s (%s), %d request(s)", res.Status, res.Message, hits.Load())
	}
}

// A json_path comparison names the value it compares against: a missing
// value is not null — it would compare against nothing and pass on a null
// element — while an explicit null is a value and exists needs none
// (verify.go:562).
func TestJSONPathRequiresAValueToCompare(t *testing.T) {
	ev, _ := newEvaluator(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"x":null}`)
	})
	ctx := context.Background()
	params := map[string]any{"url": "http://prometheus:9090/"}
	res := ev.Evaluate(ctx, cp("n", "http", params, map[string]any{"json_path": map[string]any{"path": "$.x"}}))
	if res.Status != StatusError || res.Error == nil || res.Error.Code != pdr.CodeCheckpointError {
		t.Fatalf("a comparison without a value is a configuration error, not a pass on null: %s (%s)", res.Status, res.Message)
	}
	if res := ev.Evaluate(ctx, cp("n", "http", params, map[string]any{"json_path": map[string]any{"path": "$.x", "value": nil}})); res.Status != StatusPass {
		t.Fatalf("an explicit null is a value: %s (%s)", res.Status, res.Message)
	}
	if res := ev.Evaluate(ctx, cp("n", "http", params, map[string]any{"json_path": map[string]any{"path": "$.x", "op": "exists"}})); res.Status != StatusPass {
		t.Fatalf("exists needs no value: %s (%s)", res.Status, res.Message)
	}
}

// A status-only checkpoint reads no body: an endpoint that answers its
// status and keeps its body open — a stream — is judged by the status, and
// a body that an expectation needs but that never arrives is a timeout,
// not a read error (verify.go:364).
func TestStatusOnlyCheckpointsReadNoBody(t *testing.T) {
	ev, _ := newEvaluator(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done() // the body stays open until the client gives up
	})
	ctx := context.Background()
	params := map[string]any{"url": "http://prometheus:9090/stream"}
	start := time.Now()
	c := cp("s", "http", params, map[string]any{"status": 200})
	c.Timeout = "400ms"
	res := ev.Evaluate(ctx, c)
	if res.Status != StatusPass || time.Since(start) > 3*time.Second {
		t.Fatalf("status alone is judged without reading the body: %s (%s) after %s", res.Status, res.Message, time.Since(start).Round(time.Millisecond))
	}
	c = cp("b", "http", params, map[string]any{"body_contains": "x"})
	c.Timeout = "400ms"
	res = ev.Evaluate(ctx, c)
	if res.Status != StatusError || res.Error == nil || res.Error.Code != pdr.CodeCheckpointTimeout {
		t.Fatalf("a body that never arrives is a timeout: %s (%s)", res.Status, res.Message)
	}
}

// The http params are read and typed before anything is sent: a header
// block of the wrong shape, a method that is no word, a key the adapter
// does not read — silently skipped, any of them would send a request the
// checkpoint did not describe (verify.go:346).
func TestHTTPAdapterRejectsMalformedParams(t *testing.T) {
	var hits atomic.Int32
	var seen atomic.Value
	ev, _ := newEvaluator(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		seen.Store(r.Header.Get("X-Token") + "|" + r.Header.Get("X-Count"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})
	ctx := context.Background()
	base := map[string]any{"url": "http://prometheus:9090/mutate", "method": "POST", "body": map[string]any{"drop": "everything"}}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for kk, vv := range base {
			m[kk] = vv
		}
		m[k] = v
		return m
	}
	for name, params := range map[string]map[string]any{
		"headers text":    with("headers", "X-Token: t"),
		"header map":      with("headers", map[string]any{"X-Token": map[string]any{"a": 1}}),
		"header nameless": with("headers", map[string]any{"": "v"}),
		"header twice":    with("headers", map[string]any{"Authorization": "a", "authorization": "b"}),
		"host empty":      with("headers", map[string]any{"Host": ""}),
		"host space":      with("headers", map[string]any{"Host": "grafana local"}),
		"host slash":      with("headers", map[string]any{"Host": "grafana.local/admin"}),
		"host control":    with("headers", map[string]any{"host": "grafana.local\r\nX-Injected: yes"}),
		// the grammar, not a character set
		"host colon-word": with("headers", map[string]any{"Host": "grafana.local:abc"}),
		"host bracket":    with("headers", map[string]any{"Host": "["}),
		"host percent":    with("headers", map[string]any{"Host": "grafana%20local"}),
		"host port zero":  with("headers", map[string]any{"Host": "grafana.local:0"}),
		"method number":   with("method", 7),
		"method empty":    with("method", ""),
		"unknown key":     with("header", map[string]any{"X-Token": "t"}),
		"url number":      with("url", 5),
	} {
		res := ev.Evaluate(ctx, cp("m", "http", params, map[string]any{"status": 200}))
		if res.Status != StatusError || res.Error == nil || res.Error.Code != pdr.CodeCheckpointError {
			t.Errorf("%s: want a configuration error, got %s (%s)", name, res.Status, res.Message)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("a misconfigured checkpoint reached the product %d time(s) before its error", n)
	}
	// Well-formed headers travel: text, numbers and booleans as their text.
	res := ev.Evaluate(ctx, cp("m", "http", with("headers", map[string]any{"X-Token": "t", "X-Count": 3}), map[string]any{"status": 200}))
	if res.Status != StatusPass || hits.Load() != 1 || seen.Load() != "t|3" {
		t.Fatalf("well-formed headers: %s (%s), %d request(s), saw %v", res.Status, res.Message, hits.Load(), seen.Load())
	}
}

// A container param the adapter does not read is an error too; the service
// is a name.
func TestContainerAdapterRejectsUnknownParams(t *testing.T) {
	ev, target := newEvaluator(t, func(w http.ResponseWriter, r *http.Request) {})
	ctx := context.Background()
	target.facts = &ContainerFacts{Exists: true, Running: true, Healthy: true, Stage: "healthy"}
	for name, params := range map[string]map[string]any{
		"stray key":      {"service": "prometheus", "container": "x"},
		"service number": {"service": 7},
	} {
		res := ev.Evaluate(ctx, cp("c", "container", params, map[string]any{"state": "running"}))
		if res.Status != StatusError || res.Error == nil || res.Error.Code != pdr.CodeCheckpointError {
			t.Errorf("%s: want a configuration error, got %s (%s)", name, res.Status, res.Message)
		}
	}
}

// `Host` in params.headers is the request's own field on the wire — Go
// sends it from there, never from the header map — so an authored Host
// names the virtual host the checkpoint asks for while the dial stays the
// target's; without one the URL's host is sent (verify.go:335).
func TestHTTPAdapterHonoursAnAuthoredHostHeader(t *testing.T) {
	var seen atomic.Value
	ev, _ := newEvaluator(t, func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.Host)
		w.WriteHeader(200)
	})
	ctx := context.Background()
	res := ev.Evaluate(ctx, cp("h", "http", map[string]any{"url": "http://prometheus:9090/-/ready", "headers": map[string]any{"host": "grafana.local"}}, map[string]any{"status": 200}))
	if res.Status != StatusPass || seen.Load() != "grafana.local" {
		t.Fatalf("an authored Host must reach the wire: %s (%s), server saw Host %v", res.Status, res.Message, seen.Load())
	}
	res = ev.Evaluate(ctx, cp("h", "http", map[string]any{"url": "http://prometheus:9090/-/ready"}, map[string]any{"status": 200}))
	if res.Status != StatusPass || seen.Load() != "prometheus:9090" {
		t.Fatalf("without one the URL's host is sent: %s (%s), server saw Host %v", res.Status, res.Message, seen.Load())
	}
}

// The contains operator names the text it looks for: every element contains
// the empty string, so `contains ""` would judge nothing — and, schema-valid,
// pass a mutating request's gate on any answer. It is refused at
// pre-flight, before anything is sent, as an empty body_contains is
// (verify.go:588).
func TestJSONPathContainsNamesTheTextItLooksFor(t *testing.T) {
	var hits atomic.Int32
	ev, _ := newEvaluator(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"x":"anything at all","n":42}`)
	})
	ctx := context.Background()
	params := map[string]any{"url": "http://prometheus:9090/api/v1/mutate", "method": "POST"}
	res := ev.Evaluate(ctx, cp("c", "http", params, map[string]any{"json_path": map[string]any{"path": "$.x", "op": "contains", "value": ""}}))
	if res.Status != StatusError || res.Error == nil || res.Error.Code != pdr.CodeCheckpointError || !strings.Contains(res.Error.Message, "expect.json_path.value is empty for op contains") {
		t.Fatalf("an empty needle is a configuration error, never a pass: %s (%s)", res.Status, res.Message)
	}
	if hits.Load() != 0 {
		t.Fatalf("the request went out before its expectation was judged sound: %d hit(s)", hits.Load())
	}
	for _, tc := range []struct {
		value any
		want  string
	}{
		{"thing", StatusPass},
		{"nothing", StatusFail},
		{4, StatusPass},   // a number is text to contains: "42" contains "4"
		{nil, StatusFail}, // null is the text "null", a needle like any other
	} {
		res := ev.Evaluate(ctx, cp("c", "http", map[string]any{"url": "http://prometheus:9090/"}, map[string]any{"json_path": map[string]any{"path": "$.x", "op": "contains", "value": tc.value}}))
		if tc.value == 4 || tc.value == nil {
			res = ev.Evaluate(ctx, cp("c", "http", map[string]any{"url": "http://prometheus:9090/"}, map[string]any{"json_path": map[string]any{"path": "$.n", "op": "contains", "value": tc.value}}))
		}
		if res.Status != tc.want {
			t.Errorf("contains %v: %s (%s), want %s", tc.value, res.Status, res.Message, tc.want)
		}
	}
}

// A run cancelled while waiting between retries has no verdict: it used
// to return the previous attempt's fail as if the retries had completed,
// and the engine recorded that as the latest result (verify.go:214).
// It is a PDR-E401 error result naming how many
// of the declared attempts ran.
func TestAnInterruptedBackoffIsATimeout(t *testing.T) {
	var hits atomic.Int32
	ev, _ := newEvaluator(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(503)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ev.Sleep = func(ctx context.Context, d time.Duration) error {
		cancel() // the run is cancelled while it waits to retry
		return ctx.Err()
	}
	cp := cp("m", "http", map[string]any{"url": "http://prometheus:9090/-/ready"}, map[string]any{"status": 200})
	cp.Checkpoint.Retries = &lab.Retries{Attempts: 3, Backoff: "1s"}
	res := ev.Evaluate(ctx, cp)
	if res.Status != StatusError || res.Error == nil || res.Error.Code != pdr.CodeCheckpointTimeout {
		t.Fatalf("an interrupted backoff is a timeout error, not the last attempt's verdict: %s %+v", res.Status, res.Error)
	}
	if res.Attempts != 1 || hits.Load() != 1 || !strings.Contains(res.Error.Message, "1 of 3 attempts") {
		t.Fatalf("one attempt ran and the message says so: attempts %d, hits %d, %s", res.Attempts, hits.Load(), res.Error.Message)
	}
}
