// SPDX-License-Identifier: AGPL-3.0-only

package observe

// Plan S9, threat model B10: the export path's promises, each proven
// against a destination this test holds — nothing configured means no
// client at all; everything that leaves is filtered; a full queue drops
// the oldest and counts it; a filter that cannot be built withholds the
// record; `test` reports what the destination actually answered; traces
// are OTLP-only past the config as well as at it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/config"
)

// capture is a destination: it records every body it is posted.
type capture struct {
	mu     sync.Mutex
	bodies []string
	paths  []string
	auth   []string
	status int
	srv    *httptest.Server
}

func newCapture(t *testing.T) *capture {
	t.Helper()
	c := &capture{status: http.StatusOK}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.bodies = append(c.bodies, string(body))
		c.paths = append(c.paths, r.URL.Path)
		c.auth = append(c.auth, r.Header.Get("Authorization"))
		status := c.status
		c.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *capture) all() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.bodies, "\n")
}

func (c *capture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.bodies)
}

func identity() (func(string) string, error) {
	return func(s string) string { return s }, nil
}

// TestNothingConfiguredExportsNothing: the default posture. No config,
// no exporter, no client, no connection — the promise the Manual makes
// in its first sentence about export.
func TestNothingConfiguredExportsNothing(t *testing.T) {
	e, err := New(Options{Filter: identity})
	if err != nil || e != nil {
		t.Fatalf("no config: exporter %v, err %v — want nil, nil", e, err)
	}
	// An empty block is the same: every signal nil.
	e, err = New(Options{Config: &config.Observability{}, Filter: identity})
	if err != nil || e != nil {
		t.Fatalf("empty block: exporter %v, err %v — want nil, nil", e, err)
	}
	// And the nil exporter answers the posture honestly rather than
	// panicking: every signal off.
	p := e.Posture()
	if p.Logs.Exporter != "off" || p.Metrics.Exporter != "off" || p.Traces.Exporter != "off" {
		t.Fatalf("nil exporter posture = %+v — want every signal off", p)
	}
	if got := e.Test(context.Background()); got != nil {
		t.Fatalf("nil exporter test = %v — want nil", got)
	}
}

// TestFilterRequired: an exporter built without the engine's filter is
// refused, not defaulted to the identity.
func TestFilterRequired(t *testing.T) {
	c := newCapture(t)
	_, err := New(Options{Config: &config.Observability{
		Logs: &config.Signal{Exporter: "http", Endpoint: c.srv.URL},
	}})
	if err == nil || !strings.Contains(err.Error(), "refusing to export unfiltered") {
		t.Fatalf("New without a filter: %v — want a refusal", err)
	}
}

// TestEverythingExportedIsFiltered: the B10 promise. A secret in a log
// body, a metric attribute and a span name never reaches the wire.
func TestEverythingExportedIsFiltered(t *testing.T) {
	c := newCapture(t)
	const secret = "s3cr3t-admin-password"
	filter := func() (func(string) string, error) {
		return func(s string) string { return strings.ReplaceAll(s, secret, "[redacted]") }, nil
	}
	e, err := New(Options{Config: &config.Observability{
		Logs:    &config.Signal{Exporter: "http", Endpoint: c.srv.URL},
		Metrics: &config.Signal{Exporter: "http", Endpoint: c.srv.URL},
		Traces:  &config.Signal{Exporter: "otlp", Endpoint: c.srv.URL},
	}, Filter: filter})
	if err != nil {
		t.Fatal(err)
	}
	e.Log("info", "a product answered with "+secret, map[string]string{"password": secret})
	e.Metric("podaro.test", 1, map[string]string{"token": secret})
	e.Trace(Span{TraceID: "aa", SpanID: "bb", Name: "create " + secret, Start: time.Now(), End: time.Now(),
		Attrs: map[string]string{"k": secret}})
	e.Flush(context.Background())
	body := c.all()
	if strings.Contains(body, secret) {
		t.Fatalf("a secret reached the wire")
	}
	if !strings.Contains(body, "[redacted]") {
		// The captured bodies are not printed: this branch is reached
		// exactly when the filter did not run, so they are the most
		// likely thing in the suite to be carrying the secret.
		t.Fatalf("nothing was filtered (%d bytes captured)", len(body))
	}
	if n := strings.Count(body, "[redacted]"); n != 5 {
		t.Fatalf("%d values filtered — want exactly five: the log body and its attribute, the metric's attribute, the span name and its attribute", n)
	}
}

// TestWithheldWhenFilterFails: a filter that cannot be built (an
// unreadable secret store, PDR-E412) withholds the record rather than
// exporting text it never saw — and says how many it withheld.
func TestWithheldWhenFilterFails(t *testing.T) {
	c := newCapture(t)
	e, err := New(Options{Config: &config.Observability{
		Logs: &config.Signal{Exporter: "http", Endpoint: c.srv.URL},
	}, Filter: func() (func(string) string, error) {
		return nil, errors.New("PDR-E412 the secret store cannot be read")
	}})
	if err != nil {
		t.Fatal(err)
	}
	e.Log("info", "a line that must not leave", nil)
	e.Flush(context.Background())
	if n := c.count(); n != 0 {
		t.Fatalf("%d bodies reached the destination — want none", n)
	}
	p := e.Posture()
	if p.Withheld != 1 {
		t.Fatalf("withheld = %d — want 1", p.Withheld)
	}
	if !strings.Contains(p.LastErr, "PDR-E412") {
		t.Fatalf("last error = %q — want the filter's own refusal", p.LastErr)
	}
}

// TestQueueDropsOldestAndCounts: a full queue never blocks the engine,
// and the drop is not silent.
func TestQueueDropsOldestAndCounts(t *testing.T) {
	c := newCapture(t)
	e, err := New(Options{Config: &config.Observability{
		Logs: &config.Signal{Exporter: "http", Endpoint: c.srv.URL},
	}, Filter: identity})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < QueueDepth+10; i++ {
		e.Log("info", fmt.Sprintf("line %d", i), nil)
	}
	if p := e.Posture(); p.Dropped != 10 {
		t.Fatalf("dropped = %d — want 10", p.Dropped)
	}
	e.Flush(context.Background())
	body := c.all()
	if strings.Contains(body, `"line 5"`) {
		t.Fatalf("the oldest line survived a full queue")
	}
	if !strings.Contains(body, fmt.Sprintf(`"line %d"`, QueueDepth+9)) {
		t.Fatalf("the newest line was dropped instead of the oldest")
	}
}

// TestTestReportsWhatTheDestinationAnswered: `observe test` never
// invents a success.
func TestTestReportsWhatTheDestinationAnswered(t *testing.T) {
	c := newCapture(t)
	e, err := New(Options{Config: &config.Observability{
		Logs: &config.Signal{Exporter: "http", Endpoint: c.srv.URL},
	}, Filter: identity})
	if err != nil {
		t.Fatal(err)
	}
	probes := e.Test(context.Background())
	if len(probes) != 1 || !probes[0].OK {
		t.Fatalf("probes = %+v — want one that landed", probes)
	}
	c.mu.Lock()
	c.status = http.StatusForbidden
	c.mu.Unlock()
	probes = e.Test(context.Background())
	if len(probes) != 1 || probes[0].OK {
		t.Fatalf("probes = %+v — want one that did not land", probes)
	}
	if !strings.Contains(probes[0].Error, "403") {
		t.Fatalf("probe error = %q — want the status the destination answered", probes[0].Error)
	}
}

// TestTracesAreOTLPOnlyPastTheConfig: the second wall. The config
// refuses the combination; the sinks refuse it too, because a wall that
// exists only in validation is one edit from being gone.
func TestTracesAreOTLPOnlyPastTheConfig(t *testing.T) {
	c := newCapture(t)
	for _, kind := range []string{"http", "hec"} {
		var sink Sink
		switch kind {
		case "http":
			sink = &httpSink{endpoint: c.srv.URL, client: c.srv.Client()}
		case "hec":
			sink = &hecSink{endpoint: c.srv.URL, client: c.srv.Client()}
		}
		err := sink.Traces(context.Background(), []Span{{Name: "x"}}, nil)
		if err == nil || !strings.Contains(err.Error(), "OTLP-only") {
			t.Fatalf("%s traces: %v — want a refusal", kind, err)
		}
	}
	if n := c.count(); n != 0 {
		t.Fatalf("%d bodies posted — a refused signal must not reach the wire", n)
	}
}

// TestWireShapes: each exporter posts what its destination expects —
// OTLP's paths and envelope, HEC's collector path and Splunk scheme,
// JSON lines one record per line.
func TestWireShapes(t *testing.T) {
	c := newCapture(t)
	token := filepath.Join(t.TempDir(), "hec.token")
	if err := os.WriteFile(token, []byte("abc-123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := New(Options{Config: &config.Observability{
		Logs:       &config.Signal{Exporter: "hec", Endpoint: c.srv.URL, TokenFile: token},
		Metrics:    &config.Signal{Exporter: "otlp", Endpoint: c.srv.URL},
		Traces:     &config.Signal{Exporter: "otlp", Endpoint: c.srv.URL},
		Attributes: map[string]string{"host": "lab-01"},
	}, Filter: identity})
	if err != nil {
		t.Fatal(err)
	}
	e.Log("warn", "one", nil)
	e.Log("warn", "two", nil)
	e.Metric("podaro.jobs.finished", 2, nil)
	e.Trace(Span{TraceID: "0af7", SpanID: "b7ad", Name: "podaro.create", Start: time.Now(), End: time.Now(), Status: "ok"})
	e.Flush(context.Background())

	c.mu.Lock()
	defer c.mu.Unlock()
	seen := map[string]string{}
	for i, p := range c.paths {
		seen[p] = c.bodies[i]
		if p == "/services/collector/event" && c.auth[i] != "Splunk abc-123" {
			t.Fatalf("HEC authorization = %q — want Splunk's own scheme with the trimmed token", c.auth[i])
		}
	}
	for _, want := range []string{"/services/collector/event", "/v1/metrics", "/v1/traces"} {
		if _, ok := seen[want]; !ok {
			t.Fatalf("nothing posted to %s; paths seen: %v", want, c.paths)
		}
	}
	// HEC: two events, one JSON object per line, no enclosing array.
	hec := strings.TrimSpace(seen["/services/collector/event"])
	lines := strings.Split(hec, "\n")
	if len(lines) != 2 {
		t.Fatalf("HEC body has %d lines — want one object per event:\n%s", len(lines), hec)
	}
	var ev struct {
		Time  float64 `json:"time"`
		Event struct {
			Severity   string            `json:"severity"`
			Message    string            `json:"message"`
			Attributes map[string]string `json:"attributes"`
		} `json:"event"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatalf("HEC line is not one object: %v", err)
	}
	if ev.Event.Message != "one" || ev.Event.Severity != "warn" || ev.Event.Attributes["host"] != "lab-01" {
		t.Fatalf("HEC event = %+v — want the line, its severity and the configured attributes", ev.Event)
	}
	// OTLP: the resource envelope, and a timestamp as a string.
	var otlp struct {
		ResourceMetrics []struct {
			ScopeMetrics []struct {
				Metrics []struct {
					Name  string `json:"name"`
					Gauge struct {
						DataPoints []struct {
							TimeUnixNano string  `json:"timeUnixNano"`
							AsDouble     float64 `json:"asDouble"`
						} `json:"dataPoints"`
					} `json:"gauge"`
				} `json:"metrics"`
			} `json:"scopeMetrics"`
		} `json:"resourceMetrics"`
	}
	if err := json.Unmarshal([]byte(seen["/v1/metrics"]), &otlp); err != nil {
		t.Fatalf("OTLP metrics body: %v", err)
	}
	if len(otlp.ResourceMetrics) != 1 || len(otlp.ResourceMetrics[0].ScopeMetrics) != 1 {
		t.Fatalf("OTLP envelope = %+v", otlp)
	}
	m := otlp.ResourceMetrics[0].ScopeMetrics[0].Metrics
	if len(m) != 1 || m[0].Name != "podaro.jobs.finished" || m[0].Gauge.DataPoints[0].AsDouble != 2 {
		t.Fatalf("OTLP metric = %+v", m)
	}
	if m[0].Gauge.DataPoints[0].TimeUnixNano == "" {
		t.Fatalf("OTLP timestamp must be a string of nanoseconds")
	}
	if !strings.Contains(seen["/v1/metrics"], `"host"`) || !strings.Contains(seen["/v1/metrics"], `"lab-01"`) {
		t.Fatalf("configured attributes missing from the OTLP resource")
	}
}

// TestEndpointWithAPathIsLeftAlone: a collector behind a reverse proxy
// keeps the path the operator wrote.
func TestEndpointWithAPathIsLeftAlone(t *testing.T) {
	s := &otlpSink{endpoint: "https://otel.corp/collector/v1/logs"}
	if got := s.path("logs"); got != "https://otel.corp/collector/v1/logs" {
		t.Fatalf("path = %s — want the endpoint unchanged", got)
	}
	if got := (&otlpSink{endpoint: "https://otel.corp:4318"}).path("traces"); got != "https://otel.corp:4318/v1/traces" {
		t.Fatalf("path = %s — want OTLP's own path appended to a base URL", got)
	}
	if got := (&hecSink{endpoint: "https://splunk.corp:8088"}).path(); got != "https://splunk.corp:8088/services/collector/event" {
		t.Fatalf("path = %s", got)
	}
}

// TestTokenFileMustHaveAToken: a destination credential that is an
// empty file is a misconfiguration, not an anonymous export.
func TestTokenFileMustHaveAToken(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "hec.token")
	if err := os.WriteFile(empty, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(Options{Config: &config.Observability{
		Logs: &config.Signal{Exporter: "hec", Endpoint: "https://splunk.corp:8088", TokenFile: empty},
	}, Filter: identity})
	if err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("empty token_file: %v — want a refusal", err)
	}
}
