// SPDX-License-Identifier: AGPL-3.0-only

// Package observe is the observability export (Manual §4, roadmap v0.13,
// threat model B10): Podaro's *own* logs, metrics and traces, sent to
// destinations the operator configured.
//
// Two meanings are never blurred here. **Vendor telemetry is zero,
// ever** — nothing goes to the project or to anyone, not even opt-in, and
// this package initiates no connection the operator did not ask for: with
// no `observability` block in the config, it does nothing at all and holds
// no client. **Observability export** is this: the engine's operational
// signals, off by default, to an endpoint the operator names.
//
// Three rules shape the code:
//
//   - Everything that leaves passes the same redaction filter as local
//     output. A secret value leaving by export is the same reportable
//     bug as one in a log line, at wire speed (B10). The filter is built
//     per record, from the engine, so a value generated a moment ago is
//     filtered too; a filter that cannot be built withholds the record
//     rather than exporting text it never saw, exactly as the local
//     paths do (PDR-E412).
//   - The export path never holds the engine. Records queue; a queue
//     that fills drops the oldest and counts what it dropped, and the
//     count is exported and shown by `observe status`, because a silent
//     drop is a lie about what happened.
//   - Nothing is invented. `observe test` reports what the destination
//     answered — the status, the latency, the error — and never a
//     cheerful summary of a request that failed.
package observe

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jeremiahjrross/podaro/internal/config"
)

// Bounds the export path takes on itself: a queue that cannot grow
// without limit, a request that cannot hang, and a batch that cannot
// arrive at a destination as one enormous body.
const (
	QueueDepth     = 2048
	FlushInterval  = 5 * time.Second
	MaxBatch       = 256
	RequestTimeout = 10 * time.Second
)

// LogRecord is one engine log line.
type LogRecord struct {
	At       time.Time
	Severity string
	Body     string
	Attrs    map[string]string
}

// MetricPoint is one gauge reading.
type MetricPoint struct {
	At    time.Time
	Name  string
	Value float64
	Attrs map[string]string
}

// Span is one job, start to finish.
type Span struct {
	TraceID, SpanID string
	Name            string
	Start, End      time.Time
	Status          string
	Attrs           map[string]string
}

// Sink is one destination for one signal.
type Sink interface {
	Kind() string
	Endpoint() string
	Logs(ctx context.Context, recs []LogRecord, attrs map[string]string) error
	Metrics(ctx context.Context, pts []MetricPoint, attrs map[string]string) error
	Traces(ctx context.Context, spans []Span, attrs map[string]string) error
}

// Exporter holds the configured sinks and the queue behind them.
type Exporter struct {
	logs, metrics, traces Sink
	insecure              map[string]bool
	attrs                 map[string]string
	filter                func() (func(string) string, error)
	client                *http.Client
	now                   func() time.Time

	mu       sync.Mutex
	logQ     []LogRecord
	metricQ  []MetricPoint
	traceQ   []Span
	dropped  int64
	withheld int64
	exported int64
	failures int64
	lastErr  string

	stop chan struct{}
	done chan struct{}

	// The flusher's own lifetime. Every flush is sent with a context
	// descended from ctx, so Close can end one that is already running
	// — an interval flush sent with context.Background() could not be
	// reached by the shutdown's deadline at all.
	// started says whether there is a Run to wait for.
	ctx      context.Context
	cancel   context.CancelFunc
	started  bool
	interval time.Duration
	shutdown time.Duration
}

// Options build an exporter.
type Options struct {
	Config *config.Observability
	// Filter returns the engine's redaction filter as it stands now. It
	// is called once per record — the values it covers change as
	// instances come and go, and a filter cached across those is a
	// filter that misses one. A nil Filter is refused rather than
	// defaulted to the identity: exporting unfiltered is the one thing
	// this package must never do by accident, and an error from it
	// withholds the record.
	Filter func() (func(string) string, error)
	Client *http.Client
	Now    func() time.Time
}

// New builds the exporter the config describes, or nil when nothing is
// configured — the default, and the case in which no client exists and
// no connection is ever made.
func New(o Options) (*Exporter, error) {
	if o.Config == nil {
		return nil, nil
	}
	if o.Filter == nil {
		return nil, errors.New("observability export needs the redaction filter; refusing to export unfiltered")
	}
	client := o.Client
	if client == nil {
		client = &http.Client{Timeout: RequestTimeout}
	}
	// The export follows no redirect. Go's client turns a 301, 302 or
	// 303 into a bodyless GET, so a collector that redirects — to add a
	// trailing slash, say — got nothing while the batch was counted
	// exported; and following one at all would send a lab's telemetry to
	// a destination the operator did not configure, which is the one
	// thing this package promises never to do.
	// Copied rather than set on the caller's client: the client belongs
	// to whoever passed it.
	noFollow := *client
	noFollow.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return fmt.Errorf("the destination redirected to %s; configure that endpoint directly", req.URL.Redacted())
	}
	client = &noFollow
	now := o.Now
	if now == nil {
		now = time.Now
	}
	e := &Exporter{
		attrs:    o.Config.Attributes,
		filter:   o.Filter,
		client:   client,
		now:      now,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
		interval: FlushInterval,
		shutdown: ShutdownFlush,
	}
	// Fields rather than the constants themselves so a test can run a
	// whole shutdown in milliseconds; nothing outside this package sets
	// them, and New is the only place they are given a value.
	e.ctx, e.cancel = context.WithCancel(context.Background())
	// A signal the operator marked `insecure` gets its own client: the
	// escape hatch is per destination, and the verifying client stays
	// verifying for every other one. It is the *same* transport with
	// verification turned off, not a fresh one — a fresh one carries
	// none of what the host's environment configures, `HTTPS_PROXY`
	// above all, so the one signal the operator marked insecure became
	// the one that could not reach its destination at all.
	var lax *http.Client
	clientFor := func(insecure bool) (*http.Client, error) {
		if !insecure {
			return client, nil
		}
		if lax == nil {
			tr, err := insecureTransport(client.Transport)
			if err != nil {
				return nil, err
			}
			c := *client
			c.Transport = tr
			lax = &c
		}
		return lax, nil
	}
	var err error
	if e.logs, err = sinkFor(o.Config.Logs, clientFor); err != nil {
		return nil, fmt.Errorf("observability.logs: %w", err)
	}
	if e.metrics, err = sinkFor(o.Config.Metrics, clientFor); err != nil {
		return nil, fmt.Errorf("observability.metrics: %w", err)
	}
	if e.traces, err = sinkFor(o.Config.Traces, clientFor); err != nil {
		return nil, fmt.Errorf("observability.traces: %w", err)
	}
	e.insecure = map[string]bool{}
	for name, sig := range map[string]*config.Signal{"logs": o.Config.Logs, "metrics": o.Config.Metrics, "traces": o.Config.Traces} {
		if sig != nil && sig.Insecure {
			e.insecure[name] = true
		}
	}
	if e.logs == nil && e.metrics == nil && e.traces == nil {
		return nil, nil
	}
	return e, nil
}

// insecureTransport is the effective transport with certificate
// verification turned off and nothing else touched. It clones, so the
// caller's transport keeps verifying and keeps its own TLS settings.
//
// A transport this package cannot clone is refused rather than replaced.
// An escape hatch that silently drops whatever the caller configured is
// how the proxy went missing in the first place, and a refusal at start
// is the house style for an export the operator asked for and would not
// have got.
func insecureTransport(base http.RoundTripper) (http.RoundTripper, error) {
	if base == nil {
		base = http.DefaultTransport
	}
	t, ok := base.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("insecure: true needs an *http.Transport to copy; this client carries %T", base)
	}
	t = t.Clone()
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	t.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec // B10: the documented, warned escape hatch
	return t, nil
}

func sinkFor(s *config.Signal, clientFor func(bool) (*http.Client, error)) (Sink, error) {
	if s == nil {
		return nil, nil
	}
	token := ""
	if s.TokenFile != "" {
		raw, err := os.ReadFile(s.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("token_file %s: %w", s.TokenFile, err)
		}
		token = strings.TrimSpace(string(raw))
		if token == "" {
			return nil, fmt.Errorf("token_file %s is empty", s.TokenFile)
		}
	}
	client, err := clientFor(s.Insecure)
	if err != nil {
		return nil, err
	}
	switch s.Exporter {
	case "otlp":
		return &otlpSink{endpoint: s.Endpoint, token: token, client: client}, nil
	case "http":
		return &httpSink{endpoint: s.Endpoint, token: token, client: client}, nil
	case "hec":
		return &hecSink{endpoint: s.Endpoint, token: token, client: client}, nil
	}
	return nil, fmt.Errorf("exporter %q is not one of otlp · http · hec", s.Exporter)
}

// ShutdownFlush bounds the last flush. Every batch of every configured
// signal goes out sequentially, each with its own request timeout, so
// the whole of it can take far longer than one request — and the flush
// has already taken the records off the queues by then, so a caller
// that stopped waiting would be dropping them silently.
const ShutdownFlush = 30 * time.Second

// Run flushes on an interval until stopped. An exporter that is never
// run still queues and never blocks; Close flushes what is waiting.
func (e *Exporter) Run() {
	defer close(e.done)
	e.mu.Lock()
	e.started = true
	e.mu.Unlock()
	t := time.NewTicker(e.interval)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			// The last flush is bounded here rather than abandoned by
			// the caller: a deadline the sinks are given stops the
			// requests, where a caller that walks away leaves them
			// running against records nothing will retry.
			ctx, cancel := context.WithTimeout(e.ctx, e.shutdown)
			e.Flush(ctx)
			cancel()
			return
		case <-t.C:
			// The lifecycle context, not a fresh Background: an
			// interval flush still running when Close arrives is one
			// Close can end, so the wait there is one Run cannot
			// outlive.
			e.Flush(e.ctx)
		}
	}
}

// Close stops the flusher and waits for the last flush to finish. The
// wait is longer than the flush's own bound, so it is the deadline the
// sinks were given that ends the shutdown — not a timer racing it.
func (e *Exporter) Close() {
	if e == nil {
		return
	}
	defer e.cancel()
	select {
	case <-e.stop:
	default:
		close(e.stop)
	}
	e.mu.Lock()
	started := e.started
	e.mu.Unlock()
	if !started {
		// Nothing is going to flush what is queued, so Close does it
		// itself rather than wait out the whole shutdown for a
		// goroutine that does not exist — which is what Run's contract
		// has always said and what Close did not do.
		ctx, cancel := context.WithTimeout(e.ctx, e.shutdown)
		e.Flush(ctx)
		cancel()
		return
	}
	// An interval flush already running when Close arrives gets the same
	// budget as the last one, and then the sinks are told to stop. That
	// is what makes the wait below one the flusher cannot outlive: an
	// unbounded interval flush with more than a handful of slow batches
	// kept Run running past it, and the records it had already taken off
	// the queues went nowhere and were never counted.
	late := time.AfterFunc(e.shutdown, e.cancel)
	defer late.Stop()
	select {
	case <-e.done:
	case <-time.After(e.shutdown + RequestTimeout):
	}
}

// Log queues one line. It never blocks and never fails: a queue that is
// full drops its oldest record and counts the drop, and a filter that
// cannot be built withholds the line and counts that.
func (e *Exporter) Log(severity, body string, attrs map[string]string) {
	if e == nil || e.logs == nil {
		return
	}
	red, ok := e.redactor()
	if !ok {
		return
	}
	rec := LogRecord{At: e.now().UTC(), Severity: severity, Body: red(body), Attrs: redactAttrs(red, attrs)}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.logQ) >= QueueDepth {
		e.logQ = e.logQ[1:]
		e.dropped++
	}
	e.logQ = append(e.logQ, rec)
}

// Metric queues one gauge reading.
func (e *Exporter) Metric(name string, value float64, attrs map[string]string) {
	if e == nil || e.metrics == nil {
		return
	}
	red, ok := e.redactor()
	if !ok {
		return
	}
	p := MetricPoint{At: e.now().UTC(), Name: red(name), Value: value, Attrs: redactAttrs(red, attrs)}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.metricQ) >= QueueDepth {
		e.metricQ = e.metricQ[1:]
		e.dropped++
	}
	e.metricQ = append(e.metricQ, p)
}

// Trace queues one span.
func (e *Exporter) Trace(s Span) {
	if e == nil || e.traces == nil {
		return
	}
	red, ok := e.redactor()
	if !ok {
		return
	}
	s.Name = red(s.Name)
	s.Attrs = redactAttrs(red, s.Attrs)
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.traceQ) >= QueueDepth {
		e.traceQ = e.traceQ[1:]
		e.dropped++
	}
	e.traceQ = append(e.traceQ, s)
}

// filterNow builds the filter of the moment and counts nothing. The
// count belongs to the caller, which is the only one that knows how many
// records a failure covers — one, a queued batch, or none at all.
func (e *Exporter) filterNow() (func(string) string, error) {
	red, err := e.filter()
	if err != nil {
		return nil, err
	}
	if red == nil {
		return nil, errors.New("the redaction filter could not be built")
	}
	return red, nil
}

// withhold records that n records did not leave because the filter could
// not be built, and why. A silent withholding is as much a lie as a
// silent drop, so `observe status` reports both — and reports them as
// what they are: n is a number of records, never a number of attempts.
func (e *Exporter) withhold(n int, err error) {
	e.mu.Lock()
	e.withheld += int64(n)
	e.lastErr = "record withheld: " + err.Error()
	e.mu.Unlock()
}

// redactor builds the filter for one record. A filter that cannot be
// built withholds the record — nothing this package holds is worth
// exporting text the filter never saw.
func (e *Exporter) redactor() (func(string) string, bool) {
	red, err := e.filterNow()
	if err != nil {
		e.withhold(1, err)
		return nil, false
	}
	return red, true
}

func redactAttrs(red func(string) string, in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[red(k)] = red(v)
	}
	return out
}

// globalAttrs is `observability.attributes` through the filter of the
// moment. Not ok means the filter could not be built, and then nothing
// goes out at all: the same fail-closed rule a record gets.
func (e *Exporter) globalAttrs() (map[string]string, error) {
	if len(e.attrs) == 0 {
		return nil, nil
	}
	red, err := e.filterNow()
	if err != nil {
		return nil, err
	}
	return redactAttrs(red, e.attrs), nil
}

// MaxAnswer bounds what a destination's answer may be read as: enough
// for an OTLP partial success carrying a long message, and a limit an
// answer that exceeds is refused at rather than guessed about.
const MaxAnswer = 1 << 20

// rejectedError is a destination's own count of records it would not
// keep, inside an answer that was otherwise a success. It carries the
// number so the caller can account for the part that landed; the
// destination's own message is never in it (D161).
type rejectedError struct {
	n    int64
	kind string
}

func (r *rejectedError) Error() string {
	return fmt.Sprintf("the receiver rejected %d %s(s) of the batch", r.n, r.kind)
}

// Journal returns the logger every component writes through: the
// operator's own journal first, and the same line exported. The local
// write happens first — a destination that is slow or gone never delays
// what the operator can already read — and there is no second,
// export-only log to drift from it.
//
// It is applied once, where the components are wired, rather than inside
// one of them. Wrapping inside the engine's constructor reached the
// engine's own copy alone, so the gateway's bind and renewal failures,
// the authentication sweeper's errors and `engine serve`'s own start-up
// lines went to the journal and never to a configured destination —
// against the documented promise that the export carries the engine's
// operational lines.
func Journal(local func(string, ...any), e *Exporter) func(string, ...any) {
	if e == nil {
		return local
	}
	return func(format string, args ...any) {
		local(format, args...)
		e.Log("info", fmt.Sprintf(format, args...), nil)
	}
}

// Flush sends what is queued, in batches. Failures are counted and the
// last one kept for `observe status`; records that failed are not
// retried — a destination that is down must not grow an unbounded
// backlog inside a lab host, and the drop is visible.
func (e *Exporter) Flush(ctx context.Context) {
	if e == nil {
		return
	}
	e.mu.Lock()
	logs, metrics, traces := e.logQ, e.metricQ, e.traceQ
	e.logQ, e.metricQ, e.traceQ = nil, nil, nil
	e.mu.Unlock()
	if len(logs)+len(metrics)+len(traces) == 0 {
		// Nothing queued, so nothing to filter. Building the global
		// attributes here counted one withheld record per idle tick —
		// the loop runs every FlushInterval whether or not anything was
		// queued — and `observe status` grew a loss that never happened
		// on a deployment that had exported nothing.
		return
	}

	// `observability.attributes` are the operator's, sent beside every
	// record, and they were passed to the sinks as configured. A
	// credential written into one — which is exactly the sort of thing a
	// resource attribute collects — left unfiltered, past the filter this
	// package refuses to export without. They are redacted
	// here rather than at construction because the filter changes as
	// instances come and go, which is why every other value is filtered
	// on the way out and not on the way in.
	attrs, aerr := e.globalAttrs()
	if aerr != nil {
		// Every queued record is withheld, and each one counts: they were
		// held back because the filter could not be built, which is what
		// `withheld` reports — not lost by a destination, which is what
		// `dropped` reports. Counting the batch as N dropped plus one
		// withheld put a single record in both columns.
		e.withhold(len(logs)+len(metrics)+len(traces), aerr)
		return
	}

	send := func(n int, f func() error) {
		if n == 0 {
			return
		}
		if err := f(); err != nil {
			// A destination that named what it would not keep told us
			// about *those* records; the rest of the batch landed. A
			// rejection counted as the whole batch overstated the loss by
			// the batch's width, which is as wrong as the silent success
			// it replaced.
			lost := int64(n)
			var rej *rejectedError
			if errors.As(err, &rej) && rej.n > 0 && rej.n < int64(n) {
				lost = rej.n
			}
			e.mu.Lock()
			e.failures++
			e.lastErr = err.Error()
			e.dropped += lost
			e.exported += int64(n) - lost
			e.mu.Unlock()
			return
		}
		e.mu.Lock()
		e.exported += int64(n)
		e.mu.Unlock()
	}
	for _, batch := range batches(logs, MaxBatch) {
		send(len(batch), func() error { return e.logs.Logs(ctx, batch, attrs) })
	}
	for _, batch := range batches(metrics, MaxBatch) {
		send(len(batch), func() error { return e.metrics.Metrics(ctx, batch, attrs) })
	}
	for _, batch := range batches(traces, MaxBatch) {
		send(len(batch), func() error { return e.traces.Traces(ctx, batch, attrs) })
	}
}

func batches[T any](in []T, size int) [][]T {
	var out [][]T
	for start := 0; start < len(in); start += size {
		end := start + size
		if end > len(in) {
			end = len(in)
		}
		out = append(out, in[start:end])
	}
	return out
}

// Posture is what `observe status`, `doctor` and `GET /system` report.
type Posture struct {
	Logs     SignalPosture `json:"logs"`
	Metrics  SignalPosture `json:"metrics"`
	Traces   SignalPosture `json:"traces"`
	Exported int64         `json:"exported"`
	Dropped  int64         `json:"dropped"`
	Withheld int64         `json:"withheld"`
	Failures int64         `json:"failures"`
	LastErr  string        `json:"last_error,omitempty"`
}

// SignalPosture is one signal's configuration as it stands. Insecure is
// carried because a destination whose certificate is not verified is a
// posture fact, not a footnote (B10).
type SignalPosture struct {
	Exporter string `json:"exporter"`
	Endpoint string `json:"endpoint"`
	Insecure bool   `json:"insecure,omitempty"`
}

// Posture reports what is configured and what has happened. An exporter
// that is nil — nothing configured — reports every signal off, which is
// the default posture and the one the Manual promises.
func (e *Exporter) Posture() Posture {
	p := Posture{
		Logs:    SignalPosture{Exporter: "off"},
		Metrics: SignalPosture{Exporter: "off"},
		Traces:  SignalPosture{Exporter: "off"},
	}
	if e == nil {
		return p
	}
	for _, pair := range []struct {
		name string
		sink Sink
		into *SignalPosture
	}{{"logs", e.logs, &p.Logs}, {"metrics", e.metrics, &p.Metrics}, {"traces", e.traces, &p.Traces}} {
		if pair.sink != nil {
			*pair.into = SignalPosture{Exporter: pair.sink.Kind(), Endpoint: pair.sink.Endpoint(), Insecure: e.insecure[pair.name]}
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	p.Exported, p.Dropped, p.Withheld, p.Failures, p.LastErr = e.exported, e.dropped, e.withheld, e.failures, e.lastErr
	return p
}

// Probe is one signal's answer to `observe test`.
type Probe struct {
	Signal   string        `json:"signal"`
	Exporter string        `json:"exporter"`
	Endpoint string        `json:"endpoint"`
	Insecure bool          `json:"insecure,omitempty"`
	OK       bool          `json:"ok"`
	Took     time.Duration `json:"-"`
	TookMS   int64         `json:"took_ms"`
	Error    string        `json:"error,omitempty"`
}

// Test sends one probe through each configured signal and reports what
// the destination answered. Nothing is inferred from a signal not being
// configured: it is simply absent from the results.
func (e *Exporter) Test(ctx context.Context) []Probe {
	if e == nil {
		return nil
	}
	at := e.now().UTC()
	attrs := map[string]string{"probe": "observe-test"}
	var out []Probe
	run := func(signal string, sink Sink, f func() error) {
		if sink == nil {
			return
		}
		start := e.now()
		err := f()
		p := Probe{Signal: signal, Exporter: sink.Kind(), Endpoint: sink.Endpoint(), Insecure: e.insecure[signal], OK: err == nil, Took: e.now().Sub(start)}
		p.TookMS = p.Took.Milliseconds()
		if err != nil {
			// A destination's refusal is reported as it came, through the
			// same filter — and withheld outright if the filter cannot be
			// built, because a probe's error can carry the URL it was
			// sent to and everything in it.
			// Filtered without counting: `observe test` carries no
			// records, and a diagnostic that moved the number an
			// operator reads for records lost would be its own small
			// lie (self-found beside).
			if red, ferr := e.filterNow(); ferr == nil {
				p.Error = red(err.Error())
			} else {
				p.Error = "withheld: the redaction filter could not be built"
			}
		}
		out = append(out, p)
	}
	// A probe carries the configured attributes too, so it is filtered
	// the same way; a filter that cannot be built sends no probe at all.
	global, gerr := e.globalAttrs()
	if gerr != nil {
		// One failure per *configured* signal. A signal with no exporter
		// is absent from this answer, filter or no filter — §5 says an
		// unconfigured signal is omitted, and three rows with empty
		// exporter and endpoint would say the opposite.
		for _, s := range []struct {
			name string
			sink Sink
		}{{"logs", e.logs}, {"metrics", e.metrics}, {"traces", e.traces}} {
			if s.sink == nil {
				continue
			}
			out = append(out, Probe{Signal: s.name, Exporter: s.sink.Kind(), Endpoint: s.sink.Endpoint(),
				Insecure: e.insecure[s.name], OK: false,
				Error: "withheld: the redaction filter could not be built"})
		}
		return out
	}
	run("logs", e.logs, func() error {
		return e.logs.Logs(ctx, []LogRecord{{At: at, Severity: "info", Body: "podaro observe test", Attrs: attrs}}, global)
	})
	run("metrics", e.metrics, func() error {
		return e.metrics.Metrics(ctx, []MetricPoint{{At: at, Name: "podaro.observe.test", Value: 1, Attrs: attrs}}, global)
	})
	run("traces", e.traces, func() error {
		return e.traces.Traces(ctx, []Span{{
			TraceID: "0af7651916cd43dd8448eb211c80319c", SpanID: "b7ad6b7169203331",
			Name: "podaro observe test", Start: at, End: at.Add(time.Millisecond), Status: "ok", Attrs: attrs,
		}}, global)
	})
	return out
}

// --- the wire shapes --------------------------------------------------

func merged(attrs, base map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range attrs {
		out[k] = v
	}
	return out
}

func sortedAttrs(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// post sends one body and reads the answer's status. A non-2xx is an
// error naming the status and the endpoint; the answer's body is never
// quoted — a destination that refuses may echo the request, and the
// request is what the redaction filter was for (D161).
func post(ctx context.Context, client *http.Client, endpoint, contentType string, hdr http.Header, body []byte, answer func([]byte) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	// The body is read to exhaustion so the connection is reusable. It
	// is *examined* only where a destination's protocol answers a 2xx
	// that is not a full acceptance — OTLP's partial success — and even
	// there only for its counts: a destination that refuses may echo the
	// request, and the request is what the redaction filter was for
	// (D161).
	defer resp.Body.Close()
	var (
		raw     []byte
		readErr error
	)
	if answer != nil {
		// Bounded, but wide enough for a real one: OTLP puts no order on
		// its fields, so a receiver whose `errorMessage` comes before its
		// counts — and a message about rejected records echoes the
		// request — pushed the counts past a 4 KiB cut, and an answer
		// that could not be parsed was read as full acceptance.
		// One byte over the
		// limit is read too, so being truncated is a fact the reader can
		// see rather than guess at.
		raw, readErr = io.ReadAll(io.LimitReader(resp.Body, MaxAnswer+1))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	// A 2xx is only an export if this body is what earned it. A client
	// that followed a redirect — one the exporter's own client refuses,
	// but `Options.Client` is the caller's — repeated the request as a
	// GET with nothing in it.
	if resp.Request != nil && resp.Request.Method != http.MethodPost {
		return fmt.Errorf("%s redirected the export to a %s carrying no records", endpoint, resp.Request.Method)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s answered %s", endpoint, resp.Status)
	}
	if answer != nil {
		// A body that stopped part-way — a reset, a length that does not
		// match — leaves bytes that are not this protocol's answer, and
		// "not this protocol's answer" is the branch that means nothing
		// said a record was refused. An acceptance nobody could read is
		// not an acceptance. Only the sinks whose
		// protocol answers a 2xx that is not a full acceptance ask for
		// the body at all; for the others the status is the answer and a
		// short read changes nothing.
		if readErr != nil {
			return fmt.Errorf("%s answered %s and its body could not be read to the end: %v", endpoint, resp.Status, readErr)
		}
		return answer(raw)
	}
	return nil
}
