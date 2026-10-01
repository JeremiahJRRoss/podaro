// SPDX-License-Identifier: AGPL-3.0-only

package seed

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

type stubResolver struct {
	addr string
	port int
}

func (s *stubResolver) Resolve(service string, port int) (string, error) {
	if service != "prometheus" && service != "collector" {
		return "", fmt.Errorf("no such service %q", service)
	}
	if port != s.port {
		return "", fmt.Errorf("service %s publishes no port %d", service, port)
	}
	return s.addr, nil
}

func (s *stubResolver) Dial(ctx context.Context, service string, port int) (net.Conn, error) {
	addr, err := s.Resolve(service, port)
	if err != nil {
		return nil, err
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
}

func (s *stubResolver) Endpoint(service, purpose string) (int, string, bool) {
	if purpose == "" || purpose == "api" || purpose == "http-in" {
		return s.port, "http", true
	}
	return 0, "", false
}

func TestSeedValueAndDeterminism(t *testing.T) {
	a := SeedValue("salt-1", "query-load")
	if len(a) != 16 || a != SeedValue("salt-1", "query-load") || a == SeedValue("salt-1", "web-logs") || a == SeedValue("salt-2", "query-load") {
		t.Fatalf("seed value: %s", a)
	}
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	x := GenerateWebLogs(a, 50, now)
	y := GenerateWebLogs(a, 50, now.Add(time.Hour))
	z := GenerateWebLogs(SeedValue("salt-2", "query-load"), 50, now)
	if len(x) != 50 || len(y) != 50 {
		t.Fatal("count")
	}
	same, differ := 0, 0
	for i := range x {
		if x[i].Path == y[i].Path && x[i].ClientIP == y[i].ClientIP && x[i].Status == y[i].Status && x[i].Bytes == y[i].Bytes && x[i].UserAgent == y[i].UserAgent && x[i].Sequence == i {
			same++
		}
		if x[i].Path != z[i].Path || x[i].ClientIP != z[i].ClientIP || x[i].Bytes != z[i].Bytes {
			differ++
		}
	}
	if same != 50 {
		t.Fatalf("one seed value, one payload identity: %d of 50 identical", same)
	}
	if differ < 40 {
		t.Fatalf("another seed value, another payload: only %d of 50 differ", differ)
	}
	if x[0].Timestamp == y[0].Timestamp || !strings.HasPrefix(x[0].Source, "podaro-seed/") {
		t.Fatalf("timestamps follow the clock; source names the seed: %+v %+v", x[0], y[0])
	}
	if reg, impl := BuiltIn("http-requests"); !reg || !impl {
		t.Fatal("http-requests")
	}
	if reg, impl := BuiltIn("web-logs"); !reg || !impl {
		t.Fatal("web-logs")
	}
	if reg, _ := BuiltIn("kafka-orders"); reg {
		t.Fatal("aliases are not built-ins")
	}
}

func TestHTTPRequestsDeterministicMarkers(t *testing.T) {
	var mu sync.Mutex
	var markers []string
	var hosts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		markers = append(markers, r.Header.Get("X-Podaro-Seed"))
		hosts = append(hosts, r.Host+r.URL.RequestURI())
		mu.Unlock()
		if strings.HasSuffix(r.URL.RawQuery, "fail") {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	r := &Runner{Resolver: &stubResolver{addr: strings.TrimPrefix(srv.URL, "http://"), port: 9090}}
	ctx := context.Background()
	run := Run{Instance: "lab", Name: "query-load", Generator: "http-requests", Count: 5, Params: map[string]any{"service": "prometheus", "path": "/api/v1/query?query=up"}, SeedValue: "9f2c66d1a4e07b53"}
	rep, perr := r.Run(ctx, run)
	if perr != nil || rep.Sent["requests"] != 5 || !strings.Contains(rep.Message, "5 GET requests to prometheus/api/v1/query?query=up, seeded rng 9f2c66d1a4e07b53") {
		t.Fatalf("report: %+v %v", rep, perr)
	}
	if hosts[0] != "prometheus:9090/api/v1/query?query=up" {
		t.Fatalf("host and path: %s", hosts[0])
	}
	first := append([]string(nil), markers...)
	markers = nil
	if _, perr := r.Run(ctx, run); perr != nil {
		t.Fatal(perr)
	}
	if strings.Join(first, ",") != strings.Join(markers, ",") || !strings.HasPrefix(first[0], "9f2c66d1a4e07b53-0000-") {
		t.Fatalf("re-pressing a seed sends the same identities: %v vs %v", first, markers)
	}
	run.SeedValue = "0000000000000000"
	markers = nil
	_, _ = r.Run(ctx, run)
	if strings.Join(first, ",") == strings.Join(markers, ",") {
		t.Fatal("another seed value, other identities")
	}
	// Non-2xx answers still count as sent (the product observed them).
	run.Params["path"] = "/api/v1/query?query=fail"
	rep, perr = r.Run(ctx, run)
	if perr != nil || rep.Sent["requests"] != 5 || rep.Sent["statuses"].(map[string]int)["500"] != 5 {
		t.Fatalf("statuses: %+v %v", rep, perr)
	}
	// No service: the seed has no delivery target (E404 names the fix).
	rep, perr = r.Run(ctx, Run{Name: "orphan", Generator: "http-requests", Count: 1, SeedValue: "x"})
	if rep != nil || perr == nil || perr.Code != pdr.CodeSeedFailed || !strings.Contains(perr.Message, "no delivery target") {
		t.Fatalf("no target: %+v %v", rep, perr)
	}
	// An unreachable service is a seed failure with the cause.
	srv.Close()
	rep, perr = r.Run(ctx, run)
	if rep != nil || perr == nil || perr.Code != pdr.CodeSeedFailed || perr.Cause == "" {
		t.Fatalf("unreachable: %+v %v", rep, perr)
	}
	// A built-in with no delivery target is a seed failure naming what it
	// needs; a name that is no built-in is an unavailable generator.
	if _, perr := r.Run(ctx, Run{Name: "events", Generator: "web-logs", SeedValue: "x"}); perr == nil || perr.Code != pdr.CodeSeedFailed {
		t.Fatalf("web-logs without a target: %v", perr)
	}
	if _, perr := r.Run(ctx, Run{Name: "k", Generator: "kafka-orders", SeedValue: "x"}); perr == nil || perr.Code != pdr.CodeAdapterUnavailable {
		t.Fatalf("unknown: %v", perr)
	}
}

func TestWebLogsDeliverNDJSONBatches(t *testing.T) {
	var mu sync.Mutex
	var lines []WebLog
	batches := 0
	reject := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if reject {
			w.WriteHeader(503)
			return
		}
		if r.Header.Get("Content-Type") != "application/x-ndjson" || r.Header.Get("X-Podaro-Seed") == "" || r.Method != http.MethodPost || r.Host != "collector:8088" {
			w.WriteHeader(400)
			return
		}
		batches++
		sc := bufio.NewScanner(r.Body)
		for sc.Scan() {
			var ev WebLog
			if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
				w.WriteHeader(400)
				return
			}
			lines = append(lines, ev)
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	r := &Runner{Resolver: &stubResolver{addr: strings.TrimPrefix(srv.URL, "http://"), port: 8088}}
	ctx := context.Background()
	run := Run{Instance: "lab", Name: "web-logs", Generator: "web-logs", Count: 250, Params: map[string]any{"service": "collector", "path": "/services/collector/raw", "purpose": "http-in"}, SeedValue: SeedValue("s", "web-logs")}
	rep, perr := r.Run(ctx, run)
	if perr != nil || rep.Sent["events"] != 250 || batches != 3 || rep.Sent["batches"] != 3 || len(lines) != 250 || !strings.Contains(rep.Message, "250 events to collector/services/collector/raw") {
		t.Fatalf("delivery: %+v %v batches=%d lines=%d", rep, perr, batches, len(lines))
	}
	if lines[0].Sequence != 0 || lines[249].Sequence != 249 || lines[0].Source != "podaro-seed/"+run.SeedValue {
		t.Fatalf("events: %+v", lines[0])
	}
	reject = true
	if _, perr := r.Run(ctx, run); perr == nil || perr.Code != pdr.CodeSeedFailed || !strings.Contains(perr.Message, "rejected batch 1–100 with 503") {
		t.Fatalf("rejection: %v", perr)
	}
	if _, perr := r.Run(ctx, Run{Name: "web-logs", Generator: "web-logs", Count: 5, SeedValue: "x"}); perr == nil || !strings.Contains(perr.Message, "no delivery target") {
		t.Fatalf("no target: %v", perr)
	}
}

// The same seed sends the very same events every time (Spec 0002 §5): the
// timestamps are anchored at the run's Epoch — the instance's creation
// instant — and, without one, at an anchor derived from the seed value;
// never at the clock (seed.go:300).
func TestWebLogsReplayTheSameEventsOnRerun(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()
	r := &Runner{Resolver: &stubResolver{addr: strings.TrimPrefix(srv.URL, "http://"), port: 8088}}
	ctx := context.Background()
	collect := func(run Run) string {
		mu.Lock()
		bodies = nil
		mu.Unlock()
		if _, perr := r.Run(ctx, run); perr != nil {
			t.Fatalf("run: %+v", perr)
		}
		mu.Lock()
		defer mu.Unlock()
		return strings.Join(bodies, "")
	}
	epoch := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	run := Run{Instance: "lab", Name: "web-logs", Generator: "web-logs", Count: 50, Params: map[string]any{"service": "collector", "path": "/ingest"}, SeedValue: "0123456789abcdef", Epoch: epoch}
	first := collect(run)
	time.Sleep(1100 * time.Millisecond) // a clock-anchored run would shift every RFC 3339 timestamp by now
	second := collect(run)
	if first != second {
		t.Fatalf("a re-run must replay the same events:\n%s\n---\n%s", first, second)
	}
	if !strings.Contains(first, `"2026-09-05T`) {
		t.Fatalf("the events are anchored at the epoch: %s", first[:200])
	}
	run.Epoch = time.Time{}
	third := collect(run)
	time.Sleep(1100 * time.Millisecond)
	fourth := collect(run)
	if third != fourth {
		t.Fatalf("without an epoch the anchor derives from the seed value, not the clock:\n%s\n---\n%s", third, fourth)
	}
	if strings.Contains(third, time.Now().UTC().Format("2006-01-02T15")) {
		t.Fatalf("the seed-derived anchor must not be the clock: %s", third[:200])
	}
}

// web-logs renders and sends one batch at a time: a delivery cut short by
// the receiver has rendered only the batches it sent, never the whole
// count (seed.go:315).
func TestWebLogsRenderOneBatchAtATime(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mu.Lock()
		requests++
		n := requests
		mu.Unlock()
		if n == 2 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	rendered := 0
	onWebLog = func(int) { rendered++ }
	defer func() { onWebLog = nil }()
	r := &Runner{Resolver: &stubResolver{addr: strings.TrimPrefix(srv.URL, "http://"), port: 8088}}
	run := Run{Instance: "lab", Name: "web-logs", Generator: "web-logs", Count: 300, Params: map[string]any{"service": "collector", "path": "/ingest", "batch": 100}, SeedValue: "0123456789abcdef", Epoch: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)}
	if _, perr := r.Run(context.Background(), run); perr == nil {
		t.Fatal("the rejected second batch ends the run")
	}
	if rendered != 200 {
		t.Fatalf("a run cut short after two batches renders 200 events, not the whole count: rendered %d", rendered)
	}
	if got := GenerateWebLogs(run.SeedValue, 3, run.Epoch); got[2].Sequence != 2 || got[0].Source != "podaro-seed/"+run.SeedValue {
		t.Fatalf("the generator keeps the events' identity: %+v", got)
	}
}

// A built-in seed's requests and its whole run are bounded: a target that
// accepts a connection and never answers fails the run within the budget
// instead of holding the job forever (seed.go:99).
func TestSeedRequestsAreBounded(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never answers while the client waits; released only when the
		// test ends, so the server can close whatever the client did.
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)
	r := &Runner{Resolver: &stubResolver{addr: strings.TrimPrefix(srv.URL, "http://"), port: 8088}, RequestTimeout: 200 * time.Millisecond, RunBudget: 2 * time.Second}
	run := Run{Instance: "lab", Name: "probe", Generator: "http-requests", Count: 1, Params: map[string]any{"service": "collector", "path": "/"}, SeedValue: "0123456789abcdef"}
	done := make(chan *pdr.Error, 1)
	go func() {
		_, perr := r.Run(context.Background(), run)
		done <- perr
	}()
	select {
	case perr := <-done:
		if perr == nil {
			t.Fatal("a target that never answers must fail the run")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the run must end within its bounds; it hung on a target that never answers")
	}
}

// params.batch is capped: a web-logs delivery never renders more than the
// cap in one batch, whatever the seed asks (seed.go:367).
func TestWebLogBatchesAreCapped(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mu.Lock()
		requests++
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()
	r := &Runner{Resolver: &stubResolver{addr: strings.TrimPrefix(srv.URL, "http://"), port: 8088}}
	run := Run{Instance: "lab", Name: "web-logs", Generator: "web-logs", Count: 2500, Params: map[string]any{"service": "collector", "path": "/ingest", "batch": 1000000}, SeedValue: "0123456789abcdef", Epoch: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)}
	rep, perr := r.Run(context.Background(), run)
	if perr != nil {
		t.Fatalf("run: %+v", perr)
	}
	mu.Lock()
	n := requests
	mu.Unlock()
	if n != 3 {
		t.Fatalf("2500 events at a capped batch of 1000 go in 3 requests, not %d (batch asked: 1000000)", n)
	}
	if rep.Sent["events"] != 2500 || rep.Sent["batches"] != 3 {
		t.Fatalf("the report counts every event and the capped batches: %+v", rep.Sent)
	}
}

// A built-in generator's params are typed before anything is sent: a
// present path, scheme, purpose, method or service of another shape — a
// present null included — or a port that is no port, is a configuration
// error (PDR-E404) with no request issued — never a silently substituted
// default that delivers the payload elsewhere and calls it sent (seed.go:244 and :320).
func TestSeedParamsAreTypedBeforeDelivery(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	r := &Runner{Resolver: &stubResolver{addr: strings.TrimPrefix(srv.URL, "http://"), port: 9090}}
	ctx := context.Background()
	for _, tc := range []struct {
		key   string
		value any
	}{
		{"path", 7}, {"path", map[string]any{"x": 1}}, {"scheme", true}, {"purpose", 3}, {"method", 1}, {"service", []any{"prometheus"}},
		{"port", "abc"}, {"port", 70000}, {"port", 0}, {"port", true}, {"port", 9090.5},
		// a string of digits is digits only (round 57)
		{"port", "+9090"}, {"port", " 9090"}, {"port", "9090 "}, {"port", "-9090"},
		// A present null is not absence (round 54): the schema admits it,
		// and it names no path, scheme, purpose, method, service or port.
		{"path", nil}, {"scheme", nil}, {"purpose", nil}, {"method", nil}, {"service", nil}, {"port", nil},
	} {
		params := map[string]any{"service": "prometheus", "path": "/api/v1/query?query=up", tc.key: tc.value}
		run := Run{Instance: "lab", Name: "query-load", Generator: "http-requests", Count: 3, Params: params, SeedValue: "9f2c66d1a4e07b53"}
		_, perr := r.Run(ctx, run)
		if perr == nil || perr.Code != pdr.CodeSeedFailed || !strings.Contains(perr.Message, "params."+tc.key) {
			t.Fatalf("%s=%v: want PDR-E404 naming the param, got %v", tc.key, tc.value, perr)
		}
		if n := hits.Load(); n != 0 {
			t.Fatalf("%s=%v: %d request(s) went out before the params were judged", tc.key, tc.value, n)
		}
	}
	// Well-typed params still deliver; a port written as a string of
	// digits is a port.
	run := Run{Instance: "lab", Name: "query-load", Generator: "http-requests", Count: 2, Params: map[string]any{"service": "prometheus", "path": "/", "port": "9090", "method": "get"}, SeedValue: "9f2c66d1a4e07b53"}
	if rep, perr := r.Run(ctx, run); perr != nil || rep.Sent["requests"] != 2 || hits.Load() != 2 {
		t.Fatalf("well-typed params deliver: %+v %v (hits %d)", rep, perr, hits.Load())
	}
}

// web-logs' params.headers is judged before the first batch: one field
// per name whatever its case — `Authorization` beside `authorization`
// would have sent whichever spelling the map's walk set last, so either
// credential on any given run (seed.go:523)
// — string values, legal names, no control characters; a
// refusal names the field, never a value. Well-formed headers arrive.
// A built-in generator's params are the ones it reads: a key it does not
// read — a typo such as `methd` — is PDR-E404 before anything is
// resolved or sent, never defaulted past and recorded as sent.
func TestSeedParamsAreTheGeneratorsOwn(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	r := &Runner{Resolver: &stubResolver{addr: strings.TrimPrefix(srv.URL, "http://"), port: 9090}}
	ctx := context.Background()
	for _, tc := range []struct {
		generator string
		params    map[string]any
		key       string
	}{
		{"http-requests", map[string]any{"service": "prometheus", "methd": "POST"}, "methd"},
		{"web-logs", map[string]any{"service": "collector", "batches": 10}, "batches"},
		{"web-logs", map[string]any{"service": "collector", "with_pii": 40}, "with_pii"},
	} {
		rep, perr := r.Run(ctx, Run{Name: "typo", Generator: tc.generator, Count: 3, Params: tc.params, SeedValue: "x"})
		if rep != nil || perr == nil || perr.Code != pdr.CodeSeedFailed || !strings.Contains(perr.Message, "params."+tc.key+" is not a parameter the "+tc.generator+" generator reads") {
			t.Fatalf("%s %s: %+v %v", tc.generator, tc.key, rep, perr)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("a seed with a parameter its generator does not read sends nothing: %d requests", hits.Load())
	}
	// The lists are the registry's: every built-in has one.
	for _, name := range []string{"http-requests", "web-logs"} {
		if len(GeneratorParams[name]) == 0 {
			t.Fatalf("%s reads no params?", name)
		}
	}
}

func TestWebLogHeadersAreOneFieldEach(t *testing.T) {
	var hits atomic.Int32
	var mu sync.Mutex
	var seen http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		mu.Lock()
		seen = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()
	r := &Runner{Resolver: &stubResolver{addr: strings.TrimPrefix(srv.URL, "http://"), port: 8088}}
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		headers any
		names   []string // what the refusal names
		never   string   // what it never prints
	}{
		{"case variants", map[string]any{"Authorization": "Bearer one", "authorization": "Bearer two"}, []string{"params.headers", `"Authorization"`, `"authorization"`}, "Bearer"},
		{"a null value", map[string]any{"X-Team": nil}, []string{"params.headers.X-Team", "null"}, ""},
		{"a number value", map[string]any{"X-Team": 7}, []string{"params.headers.X-Team"}, ""},
		{"not a map", "X-Team: blue", []string{"params.headers", "string"}, "blue"},
		{"a list", []any{"X-Team: blue"}, []string{"params.headers"}, "blue"},
		{"an empty name", map[string]any{"": "blue"}, []string{"params.headers"}, "blue"},
		{"a space in the name", map[string]any{"X Team": "blue"}, []string{"params.headers", `"X Team"`}, "blue"},
		{"a control character in the value", map[string]any{"X-Team": "blue\r\nInjected: yes"}, []string{"params.headers.X-Team", "control character"}, "Injected"},
	} {
		run := Run{Instance: "lab", Name: "access", Generator: "web-logs", Count: 3, Params: map[string]any{"service": "collector", "port": 8088, "path": "/services/collector", "headers": tc.headers}, SeedValue: "9f2c66d1a4e07b53"}
		_, perr := r.Run(ctx, run)
		if perr == nil || perr.Code != pdr.CodeSeedFailed {
			t.Fatalf("%s: want PDR-E404, got %v", tc.name, perr)
		}
		for _, want := range tc.names {
			if !strings.Contains(perr.Message, want) {
				t.Fatalf("%s: the refusal names %s: %s", tc.name, want, perr.Message)
			}
		}
		if tc.never != "" && strings.Contains(perr.Error(), tc.never) {
			t.Fatalf("%s: the refusal printed a value: %s", tc.name, perr.Error())
		}
		if n := hits.Load(); n != 0 {
			t.Fatalf("%s: %d batch(es) went out before the headers were judged", tc.name, n)
		}
	}
	run := Run{Instance: "lab", Name: "access", Generator: "web-logs", Count: 3, Params: map[string]any{"service": "collector", "port": 8088, "path": "/services/collector", "headers": map[string]any{"X-Team": "blue", "content-type": "application/json"}}, SeedValue: "9f2c66d1a4e07b53"}
	if rep, perr := r.Run(ctx, run); perr != nil || rep.Sent["events"] != 3 || hits.Load() != 1 {
		t.Fatalf("well-formed headers deliver: %+v %v (hits %d)", rep, perr, hits.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if seen.Get("X-Team") != "blue" || seen.Get("Content-Type") != "application/json" || seen.Get("X-Podaro-Seed") == "" {
		t.Fatalf("the declared fields arrive, the declared type wins, the marker stays: %v", seen)
	}
}

// web-logs' params.batch is judged before the first batch: a present
// value that is no batch size — zero, a negative, a null, a map, a word,
// a fraction — is PDR-E404 with no request issued, where before the
// default of 100 was kept silently and the events went out grouped
// otherwise than declared (seed.go:553).
// A whole number, as an integer or a string of digits, is the batch.
func TestWebLogBatchIsJudgedBeforeDelivery(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		hits.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	r := &Runner{Resolver: &stubResolver{addr: strings.TrimPrefix(srv.URL, "http://"), port: 8088}}
	ctx := context.Background()
	// a string of digits is digits only: a sign or a space is not one (round 57)
	for _, bad := range []any{0, -1, nil, map[string]any{"size": 2}, "abc", 9.5, true, "", []any{2}, "+1", "-1", " 1", "1 ", "0", "1.0"} {
		run := Run{Instance: "lab", Name: "access", Generator: "web-logs", Count: 5, Params: map[string]any{"service": "collector", "port": 8088, "path": "/ingest", "batch": bad}, SeedValue: "9f2c66d1a4e07b53"}
		_, perr := r.Run(ctx, run)
		if perr == nil || perr.Code != pdr.CodeSeedFailed || !strings.Contains(perr.Message, "params.batch") {
			t.Fatalf("batch=%v: want PDR-E404 naming params.batch, got %v", bad, perr)
		}
		if n := hits.Load(); n != 0 {
			t.Fatalf("batch=%v: %d request(s) went out before the batch was judged", bad, n)
		}
	}
	for _, good := range []any{2, "2", 2.0, int64(2)} {
		hits.Store(0)
		run := Run{Instance: "lab", Name: "access", Generator: "web-logs", Count: 5, Params: map[string]any{"service": "collector", "port": 8088, "path": "/ingest", "batch": good}, SeedValue: "9f2c66d1a4e07b53"}
		rep, perr := r.Run(ctx, run)
		if perr != nil || rep.Sent["batches"] != 3 || hits.Load() != 3 {
			t.Fatalf("batch=%v (%T): five events in batches of two are three requests: %+v %v (hits %d)", good, good, rep, perr, hits.Load())
		}
	}
}

// A Host among web-logs' params.headers is the wire Host: Go sends the
// Host from the request's own field, never from the header map, so the
// authored value used to be lost and a collector keyed by virtual host
// saw the service's name (seed.go:591).
// It is validated as a legal host; the dial stays the service's.
func TestWebLogAuthoredHostIsTheWireHost(t *testing.T) {
	var hits atomic.Int32
	var mu sync.Mutex
	var seenHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		hits.Add(1)
		mu.Lock()
		seenHost = r.Host
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()
	r := &Runner{Resolver: &stubResolver{addr: strings.TrimPrefix(srv.URL, "http://"), port: 8088}}
	ctx := context.Background()
	// the Host grammar, not a character set (round 57): a word for a port, a lone
	// bracket, a percent, a port out of range, a label that is none
	for _, bad := range []string{"", "tenant-a.collector.test/ingest", "tenant a", "tenant-a.collector.test?x=1", "a\tb", "tenant:abc", "[", "%", "tenant%20a", "tenant-a.collector.test:0", "tenant-a.collector.test:65536", "-tenant.collector.test", "a..b", "[::1", "tenant:8088:1"} {
		run := Run{Instance: "lab", Name: "access", Generator: "web-logs", Count: 2, Params: map[string]any{"service": "collector", "port": 8088, "path": "/ingest", "headers": map[string]any{"host": bad}}, SeedValue: "9f2c66d1a4e07b53"}
		_, perr := r.Run(ctx, run)
		if perr == nil || perr.Code != pdr.CodeSeedFailed || !strings.Contains(perr.Message, "params.headers.host") {
			t.Fatalf("host=%q: want PDR-E404 naming the field, got %v", bad, perr)
		}
		if n := hits.Load(); n != 0 {
			t.Fatalf("host=%q: %d request(s) went out", bad, n)
		}
	}
	run := Run{Instance: "lab", Name: "access", Generator: "web-logs", Count: 2, Params: map[string]any{"service": "collector", "port": 8088, "path": "/ingest", "headers": map[string]any{"Host": "tenant-a.collector.test:8088", "X-Team": "blue"}}, SeedValue: "9f2c66d1a4e07b53"}
	if rep, perr := r.Run(ctx, run); perr != nil || rep.Sent["events"] != 2 || hits.Load() != 1 {
		t.Fatalf("an authored Host delivers: %+v %v (hits %d)", rep, perr, hits.Load())
	}
	wire := func() string { mu.Lock(); defer mu.Unlock(); return seenHost }
	if got := wire(); got != "tenant-a.collector.test:8088" {
		t.Fatalf("the wire Host is the authored one, got %q", got)
	}
	// Without one, the wire Host is the service's, as before.
	run.Params["headers"] = map[string]any{"X-Team": "blue"}
	if _, perr := r.Run(ctx, run); perr != nil {
		t.Fatal(perr)
	}
	if got := wire(); got != "collector:8088" {
		t.Fatalf("the default wire Host is the service's, got %q", got)
	}
}
