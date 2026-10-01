// SPDX-License-Identifier: AGPL-3.0-only

package observe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/config"
)

// An OTLP collector that accepts only part of a batch answers `200` with
// a `partialSuccess` body naming what it rejected. The answer's body was
// read to exhaustion and discarded, so a 2xx was an export: the records
// the collector said it would not keep were counted `exported`, and
// `observe test` said the probe landed. A count that says a record left
// when the destination refused it is the same lie as a silent drop —
// which is the thing this package's counters exist to prevent.
func TestAPartialSuccessIsNotAFullExport(t *testing.T) {
	var mu sync.Mutex
	var seen int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		// OTLP's own shape: the count is a string-encoded int64, and the
		// message may echo the request, so nothing but the count is ever
		// read from it.
		_, _ = w.Write([]byte(`{"partialSuccess":{"rejectedLogRecords":"2","errorMessage":"2 records rejected"}}`))
	}))
	defer srv.Close()

	e, err := New(Options{Config: &config.Observability{
		Logs: &config.Signal{Exporter: "otlp", Endpoint: srv.URL},
	}, Filter: identity})
	if err != nil {
		t.Fatal(err)
	}
	e.Log("info", "one", nil)
	e.Log("info", "two", nil)
	e.Flush(context.Background())

	p := e.Posture()
	if p.Exported != 0 {
		t.Errorf("exported = %d after the collector said it rejected the records", p.Exported)
	}
	if p.Dropped != 2 || p.Failures != 1 {
		t.Errorf("dropped = %d, failures = %d — want the rejected records counted lost, once", p.Dropped, p.Failures)
	}
	if !strings.Contains(p.LastErr, "2") {
		t.Errorf("the last error does not say how many were rejected: %q", p.LastErr)
	}
	// The destination's own message is never quoted back: it can echo
	// the request, and the request is what the filter was for (D161).
	if strings.Contains(p.LastErr, "records rejected") {
		t.Errorf("the destination's message was quoted into the posture: %q", p.LastErr)
	}

	// A collector that keeps everything still counts as an export: an
	// empty partialSuccess is the shape a healthy receiver may answer.
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"partialSuccess":{}}`))
	}))
	defer ok.Close()
	e2, err := New(Options{Config: &config.Observability{
		Logs: &config.Signal{Exporter: "otlp", Endpoint: ok.URL},
	}, Filter: identity})
	if err != nil {
		t.Fatal(err)
	}
	e2.Log("info", "three", nil)
	e2.Flush(context.Background())
	if p := e2.Posture(); p.Exported != 1 || p.Dropped != 0 {
		t.Errorf("a receiver that rejected nothing: exported = %d, dropped = %d", p.Exported, p.Dropped)
	}
}
