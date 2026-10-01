// SPDX-License-Identifier: AGPL-3.0-only

package observe

// The three wire shapes the Manual names: `otlp` (OTLP/HTTP), `http`
// (JSON lines to any endpoint), `hec` (the HTTP Event Collector protocol,
// which Splunk defined — logs and metrics).
//
// Each is written by hand against the destination's published shape
// rather than pulled in as a dependency: the payloads are small, the
// engine exports its own operational signals and nothing else, and a
// vendor SDK is a lot of surface — and a lot of its own background
// connections — to accept for three POSTs. What leaves is exactly what
// these files build.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	podaro "github.com/jeremiahjrross/podaro"
	"github.com/jeremiahjrross/podaro/internal/config"
)

// --- OTLP/HTTP --------------------------------------------------------

// otlpSink speaks OTLP/HTTP with a JSON body (the JSON mapping of the
// protobuf, which every OTLP receiver accepts on the same paths).
type otlpSink struct {
	endpoint string
	token    string
	client   *http.Client
}

func (s *otlpSink) Kind() string { return "otlp" }

// Endpoint is what an operator is *shown* — the posture, `observe test`
// and the start-up line all come through here — so it never carries a
// credential, whatever the exporter was built with.
// The requests use s.endpoint; only this is filtered.
func (s *otlpSink) Endpoint() string { return config.WithoutUserinfo(s.endpoint) }

// path appends OTLP's signal path when the operator gave a base URL, and
// leaves a URL that already names a path alone — a collector behind a
// reverse proxy may live anywhere, and the Manual's example endpoint
// (`https://otel.corp:4318`) is the base.
func (s *otlpSink) path(signal string) string {
	u, err := url.Parse(s.endpoint)
	if err != nil {
		return s.endpoint
	}
	if p := strings.Trim(u.Path, "/"); p != "" {
		return s.endpoint
	}
	u.Path = "/v1/" + signal
	return u.String()
}

// otlpRejected reads an OTLP answer for what the receiver would not
// keep. A collector that accepts only part of a batch answers 200 with a
// `partialSuccess` naming the rejected records, points or spans — so a
// 2xx is not on its own an export, and counting one was the same lie as
// a silent drop.
//
// Only the counts are read. `errorMessage` may echo the request, and the
// request is what the redaction filter was for (D161), so it never
// reaches a counter, the posture or the operator's journal. The counts
// are strings in OTLP's JSON mapping, as every int64 is.
func otlpRejected(raw []byte) error {
	if len(raw) == 0 {
		return nil
	}
	if len(raw) > MaxAnswer {
		// Past the bound the answer is unread, and an unread answer is
		// not an acceptance: a receiver that rejects records can put a
		// message of any length before its counts, and treating that as
		// success would be a fail-open path the destination decides to
		// take.
		return fmt.Errorf("the receiver's answer is longer than %d bytes and was not read for what it rejected", MaxAnswer)
	}
	var answer struct {
		Partial struct {
			Logs   json.Number `json:"rejectedLogRecords"`
			Points json.Number `json:"rejectedDataPoints"`
			Spans  json.Number `json:"rejectedSpans"`
		} `json:"partialSuccess"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		// A 2xx whose body is not OTLP's is the receiver's business,
		// not a loss: nothing here says any record was refused.
		return nil
	}
	// In a fixed order, so the same answer always reports the same way.
	for _, k := range []struct {
		kind string
		n    json.Number
	}{
		{"log record", answer.Partial.Logs},
		{"data point", answer.Partial.Points},
		{"span", answer.Partial.Spans},
	} {
		count, err := k.n.Int64()
		if err != nil || count <= 0 {
			continue
		}
		return &rejectedError{n: count, kind: k.kind}
	}
	return nil
}

func (s *otlpSink) send(ctx context.Context, signal string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	h := http.Header{}
	if s.token != "" {
		h.Set("Authorization", "Bearer "+s.token)
	}
	return post(ctx, s.client, s.path(signal), "application/json", h, raw, otlpRejected)
}

func (s *otlpSink) Logs(ctx context.Context, recs []LogRecord, base map[string]string) error {
	out := make([]any, 0, len(recs))
	for _, r := range recs {
		num, text := severity(r.Severity)
		out = append(out, map[string]any{
			"timeUnixNano":   nanos(r.At),
			"severityNumber": num,
			"severityText":   text,
			"body":           map[string]any{"stringValue": r.Body},
			"attributes":     otlpAttrs(r.Attrs),
		})
	}
	return s.send(ctx, "logs", map[string]any{"resourceLogs": []any{map[string]any{
		"resource":  otlpResource(base),
		"scopeLogs": []any{map[string]any{"scope": otlpScope(), "logRecords": out}},
	}}})
}

func (s *otlpSink) Metrics(ctx context.Context, pts []MetricPoint, base map[string]string) error {
	// One metric per point keeps the mapping obvious; the engine's points
	// are few and named, not a scrape of a whole process.
	out := make([]any, 0, len(pts))
	for _, p := range pts {
		out = append(out, map[string]any{
			"name": p.Name,
			"gauge": map[string]any{"dataPoints": []any{map[string]any{
				"timeUnixNano": nanos(p.At),
				"asDouble":     p.Value,
				"attributes":   otlpAttrs(p.Attrs),
			}}},
		})
	}
	return s.send(ctx, "metrics", map[string]any{"resourceMetrics": []any{map[string]any{
		"resource":     otlpResource(base),
		"scopeMetrics": []any{map[string]any{"scope": otlpScope(), "metrics": out}},
	}}})
}

func (s *otlpSink) Traces(ctx context.Context, spans []Span, base map[string]string) error {
	out := make([]any, 0, len(spans))
	for _, sp := range spans {
		code := 1 // OK
		if sp.Status != "" && sp.Status != "ok" {
			code = 2 // ERROR
		}
		out = append(out, map[string]any{
			"traceId":           sp.TraceID,
			"spanId":            sp.SpanID,
			"name":              sp.Name,
			"kind":              1, // INTERNAL: the engine's own work
			"startTimeUnixNano": nanos(sp.Start),
			"endTimeUnixNano":   nanos(sp.End),
			"status":            map[string]any{"code": code},
			"attributes":        otlpAttrs(sp.Attrs),
		})
	}
	return s.send(ctx, "traces", map[string]any{"resourceSpans": []any{map[string]any{
		"resource":   otlpResource(base),
		"scopeSpans": []any{map[string]any{"scope": otlpScope(), "spans": out}},
	}}})
}

func otlpScope() map[string]any {
	return map[string]any{"name": "podaro", "version": podaro.Version()}
}

func otlpResource(base map[string]string) map[string]any {
	attrs := map[string]string{"service.name": "podaro"}
	for k, v := range base {
		attrs[k] = v
	}
	return map[string]any{"attributes": otlpAttrs(attrs)}
}

// otlpAttrs renders a map as OTLP key/value pairs, sorted so a captured
// body is comparable between runs (the acceptance diffs one).
func otlpAttrs(m map[string]string) []any {
	out := make([]any, 0, len(m))
	for _, k := range sortedAttrs(m) {
		out = append(out, map[string]any{"key": k, "value": map[string]any{"stringValue": m[k]}})
	}
	return out
}

// nanos is OTLP's timestamp: nanoseconds since the epoch, as a string
// because the value exceeds what JSON numbers carry safely.
func nanos(t time.Time) string { return strconv.FormatInt(t.UTC().UnixNano(), 10) }

// severity maps the engine's words onto OTLP's numbers and canonical
// text. An unknown word is INFO rather than a refusal: a log line is not
// worth dropping over its label.
func severity(s string) (int, string) {
	switch strings.ToLower(s) {
	case "debug":
		return 5, "DEBUG"
	case "warn", "warning":
		return 13, "WARN"
	case "error":
		return 17, "ERROR"
	default:
		return 9, "INFO"
	}
}

// --- JSON lines -------------------------------------------------------

// httpSink posts newline-delimited JSON: one record per line, in
// Podaro's own shape, for the endpoint an operator already has.
type httpSink struct {
	endpoint string
	token    string
	client   *http.Client
}

func (s *httpSink) Kind() string     { return "http" }
func (s *httpSink) Endpoint() string { return config.WithoutUserinfo(s.endpoint) }

func (s *httpSink) send(ctx context.Context, lines []any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf) // Encode writes the newline itself
	for _, l := range lines {
		if err := enc.Encode(l); err != nil {
			return err
		}
	}
	h := http.Header{}
	if s.token != "" {
		h.Set("Authorization", "Bearer "+s.token)
	}
	return post(ctx, s.client, s.endpoint, "application/x-ndjson", h, buf.Bytes(), nil)
}

func (s *httpSink) Logs(ctx context.Context, recs []LogRecord, base map[string]string) error {
	lines := make([]any, 0, len(recs))
	for _, r := range recs {
		lines = append(lines, map[string]any{
			"time":       r.At.UTC().Format(time.RFC3339Nano),
			"signal":     "log",
			"severity":   strings.ToLower(r.Severity),
			"body":       r.Body,
			"attributes": merged(r.Attrs, base),
		})
	}
	return s.send(ctx, lines)
}

func (s *httpSink) Metrics(ctx context.Context, pts []MetricPoint, base map[string]string) error {
	lines := make([]any, 0, len(pts))
	for _, p := range pts {
		lines = append(lines, map[string]any{
			"time":       p.At.UTC().Format(time.RFC3339Nano),
			"signal":     "metric",
			"name":       p.Name,
			"value":      p.Value,
			"attributes": merged(p.Attrs, base),
		})
	}
	return s.send(ctx, lines)
}

// Traces refuses rather than inventing a shape: traces are OTLP-only in
// this release (Manual §4), and the config refuses the combination
// before it reaches here — this is the second wall, not the first.
func (s *httpSink) Traces(context.Context, []Span, map[string]string) error {
	return errTracesOTLPOnly("http")
}

// --- Splunk HEC -------------------------------------------------------

// hecSink posts to Splunk's HTTP Event Collector: events for logs,
// metric events for metrics.
type hecSink struct {
	endpoint string
	token    string
	client   *http.Client
}

func (s *hecSink) Kind() string     { return "hec" }
func (s *hecSink) Endpoint() string { return config.WithoutUserinfo(s.endpoint) }

// path appends HEC's collector path when the operator gave a base URL
// (the Manual's example is `https://collector.example.com:8088`).
func (s *hecSink) path() string {
	u, err := url.Parse(s.endpoint)
	if err != nil {
		return s.endpoint
	}
	if p := strings.Trim(u.Path, "/"); p != "" {
		return s.endpoint
	}
	u.Path = "/services/collector/event"
	return u.String()
}

// send writes HEC's body: JSON objects one after another, no separator
// and no enclosing array.
func (s *hecSink) send(ctx context.Context, events []any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	h := http.Header{}
	// HEC's own scheme, not Bearer: a token sent as Bearer is refused
	// with a 401 that says nothing about why.
	h.Set("Authorization", "Splunk "+s.token)
	return post(ctx, s.client, s.path(), "application/json", h, buf.Bytes(), nil)
}

func (s *hecSink) Logs(ctx context.Context, recs []LogRecord, base map[string]string) error {
	events := make([]any, 0, len(recs))
	for _, r := range recs {
		events = append(events, map[string]any{
			"time":       hecTime(r.At),
			"source":     "podaro",
			"sourcetype": "podaro:log",
			"event": map[string]any{
				"severity":   strings.ToLower(r.Severity),
				"message":    r.Body,
				"attributes": merged(r.Attrs, base),
			},
		})
	}
	return s.send(ctx, events)
}

func (s *hecSink) Metrics(ctx context.Context, pts []MetricPoint, base map[string]string) error {
	events := make([]any, 0, len(pts))
	for _, p := range pts {
		fields := map[string]any{"metric_name:" + p.Name: p.Value}
		for k, v := range merged(p.Attrs, base) {
			fields[k] = v
		}
		events = append(events, map[string]any{
			"time":       hecTime(p.At),
			"source":     "podaro",
			"sourcetype": "podaro:metric",
			"event":      "metric",
			"fields":     fields,
		})
	}
	return s.send(ctx, events)
}

// Traces refuses: HEC carries events, and traces are OTLP-only in this
// release (Manual §4).
func (s *hecSink) Traces(context.Context, []Span, map[string]string) error {
	return errTracesOTLPOnly("hec")
}

// hecTime is HEC's epoch-seconds-with-fraction.
func hecTime(t time.Time) float64 {
	return float64(t.UTC().UnixNano()) / float64(time.Second)
}

func errTracesOTLPOnly(kind string) error {
	return fmt.Errorf("traces are OTLP-only in this release; the %s exporter carries logs and metrics", kind)
}
