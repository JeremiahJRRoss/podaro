// SPDX-License-Identifier: AGPL-3.0-only

package observe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/config"
)

// hangingSink is a destination that never answers. It returns when the
// context it was given is done — the only way out — or after a wait
// longer than any this test allows, so a test that has already failed
// does not sit here.
type hangingSink struct {
	mu      sync.Mutex
	entered chan struct{}
	reached bool
}

func (s *hangingSink) Kind() string     { return "http" }
func (s *hangingSink) Endpoint() string { return "http://127.0.0.1:0/records" }

func (s *hangingSink) hang(ctx context.Context) error {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	select {
	case <-ctx.Done():
		s.mu.Lock()
		s.reached = true
		s.mu.Unlock()
		return ctx.Err()
	case <-time.After(25 * time.Second):
		return nil
	}
}

func (s *hangingSink) Logs(ctx context.Context, _ []LogRecord, _ map[string]string) error {
	return s.hang(ctx)
}
func (s *hangingSink) Metrics(ctx context.Context, _ []MetricPoint, _ map[string]string) error {
	return s.hang(ctx)
}
func (s *hangingSink) Traces(ctx context.Context, _ []Span, _ map[string]string) error {
	return s.hang(ctx)
}

func exporterForShutdown(t *testing.T) *Exporter {
	t.Helper()
	e, err := New(Options{Config: &config.Observability{
		Logs: &config.Signal{Exporter: "http", Endpoint: httptest.NewServer(http.NotFoundHandler()).URL},
	}, Filter: identity})
	if err != nil {
		t.Fatal(err)
	}
	// The whole shutdown, in milliseconds: the real budget is thirty
	// seconds and the real interval five, which is a minute of waiting
	// to watch a handover that takes no time at all.
	e.interval = 5 * time.Millisecond
	e.shutdown = 100 * time.Millisecond
	return e
}

// Round 6 bounded the last flush and made Close wait longer than that
// bound. The interval flush was still sent with context.Background(),
// so the deadline Close relies on could not reach one that was already
// running: a flush with more than a handful of slow batches kept Run
// going past the wait, and Close returned while records that had
// already been taken off the queues were still in the air — neither
// sent nor counted.
//
// Every flush is sent with the exporter's own lifecycle context now.
// The one in flight gets the same budget as the last flush, and then
// the sinks are told to stop.
func TestAnIntervalFlushCannotOutliveTheShutdown(t *testing.T) {
	sink := &hangingSink{entered: make(chan struct{}, 1)}
	e := exporterForShutdown(t)
	e.logs = sink
	e.Log("info", "a line the operator is owed", nil)
	go e.Run()

	select {
	case <-sink.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no interval flush ever started")
	}

	closed := make(chan struct{})
	go func() { e.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not return: the interval flush it cannot reach holds the shutdown open")
	}

	select {
	case <-e.done:
	default:
		t.Error("Close returned while the flusher was still running: the records it took off the queues go nowhere")
	}
	sink.mu.Lock()
	reached := sink.reached
	sink.mu.Unlock()
	if !reached {
		t.Error("the shutdown never reached the sink: the flush ended on its own, not on the budget")
	}
	// Whatever could not go out is counted. The one thing the shutdown
	// must never do is lose records quietly.
	if p := e.Posture(); p.Exported+p.Dropped == 0 {
		t.Errorf("the queued record was neither sent nor counted: %+v", p)
	}
}

// Mine, not the review's, found while rewriting Close. Run's contract
// says an exporter that is never run still queues and that Close
// flushes what is waiting. Close instead waited out the whole shutdown
// — forty seconds — for a goroutine that did not exist, and flushed
// nothing. In this tree only serve.go builds an exporter and it always
// starts Run first, so this was a trap for the next caller rather than
// a live fault; the contract said otherwise either way.
func TestCloseFlushesWhatIsWaitingWhenRunNeverStarted(t *testing.T) {
	sink := &deadlineSink{}
	e := exporterForShutdown(t)
	e.logs = sink
	e.Log("info", "a line queued before anything was started", nil)

	start := time.Now()
	e.Close()
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Close waited %s for a flusher that was never started", d.Round(time.Millisecond))
	}
	if p := e.Posture(); p.Exported == 0 {
		t.Errorf("Close flushed nothing: what was queued before Run went nowhere: %+v", p)
	}
}
