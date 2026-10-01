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

// deadlineSink records what the flush gave it: whether the context it
// was sent with carries a deadline at all.
type deadlineSink struct {
	mu       sync.Mutex
	calls    int
	deadline bool
	slow     time.Duration
}

func (s *deadlineSink) Kind() string     { return "http" }
func (s *deadlineSink) Endpoint() string { return "http://127.0.0.1:0/records" }

func (s *deadlineSink) note(ctx context.Context) error {
	_, has := ctx.Deadline()
	s.mu.Lock()
	s.calls++
	s.deadline = has
	slow := s.slow
	s.mu.Unlock()
	time.Sleep(slow)
	return nil
}

func (s *deadlineSink) Logs(ctx context.Context, _ []LogRecord, _ map[string]string) error {
	return s.note(ctx)
}
func (s *deadlineSink) Metrics(ctx context.Context, _ []MetricPoint, _ map[string]string) error {
	return s.note(ctx)
}
func (s *deadlineSink) Traces(ctx context.Context, _ []Span, _ map[string]string) error {
	return s.note(ctx)
}

// Close waited a fixed 20 seconds for the last flush, and that flush
// sends every batch of every configured signal in turn, each with its
// own request timeout — so it can take longer than the wait. `Flush` has
// already taken the records off the queues by then, so a caller that
// walked away was dropping them silently, which is the opposite of what
// the shutdown flush promises.
//
// The last flush carries a deadline now, and Close waits longer than it:
// what ends the shutdown is the bound the sinks were given, not a timer
// racing them.
func TestTheShutdownFlushIsBoundedAndWaitedFor(t *testing.T) {
	sink := &deadlineSink{slow: 120 * time.Millisecond}
	e, err := New(Options{Config: &config.Observability{
		Logs: &config.Signal{Exporter: "http", Endpoint: httptest.NewServer(http.NotFoundHandler()).URL},
	}, Filter: identity})
	if err != nil {
		t.Fatal(err)
	}
	e.logs = sink
	go e.Run()
	e.Log("info", "a line the operator is owed", nil)

	done := make(chan struct{})
	go func() { e.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Close never returned")
	}

	sink.mu.Lock()
	calls, deadline := sink.calls, sink.deadline
	sink.mu.Unlock()
	if calls == 0 {
		t.Fatal("the shutdown flush sent nothing")
	}
	if !deadline {
		t.Errorf("the last flush was sent with no deadline: a caller that stops waiting leaves it running")
	}
	// Close returned after the flush finished, so the records it took
	// off the queue really went out — nothing was counted dropped.
	if p := e.Posture(); p.Exported == 0 || p.Dropped != 0 {
		t.Errorf("the shutdown lost what it promised to flush: %+v", p)
	}
}
