// SPDX-License-Identifier: AGPL-3.0-only

package observe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/config"
)

// A destination that answers 301, 302 or 303 — a collector adding a
// trailing slash is the ordinary case — makes Go's client repeat the
// request as a bodyless GET. The redirect target answers 200 to that,
// `post` sees a 2xx, and the batch is counted `exported` although the
// records were never submitted anywhere.
//
// Following it at all is the deeper problem: the only network call this
// package makes is one the operator configured, and a redirect is a
// destination they did not.
func TestARedirectIsNotAnExport(t *testing.T) {
	var mu sync.Mutex
	var reached []string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reached = append(reached, r.Method)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/collect/", http.StatusFound)
	}))
	defer front.Close()

	e, err := New(Options{Config: &config.Observability{
		Logs: &config.Signal{Exporter: "http", Endpoint: front.URL},
	}, Filter: identity})
	if err != nil {
		t.Fatal(err)
	}
	e.Log("info", "a line that must reach the configured destination or none", nil)
	e.Flush(context.Background())

	p := e.Posture()
	if p.Exported != 0 {
		t.Errorf("exported = %d after a redirect that carried no body — the record was never submitted", p.Exported)
	}
	if p.Dropped != 1 || p.Failures != 1 {
		t.Errorf("dropped = %d, failures = %d — want the record counted lost, once", p.Dropped, p.Failures)
	}
	if p.LastErr == "" {
		t.Errorf("nothing was reported for a redirect the export refused")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(reached) != 0 {
		t.Errorf("the export followed a redirect to a destination the operator did not configure: %v", reached)
	}
}

// Records queued while the filter worked, flushed after it broke, were
// counted as N *dropped* plus one *withheld* — the one being the filter
// call itself. They were withheld, every one of them, for the reason
// `withheld` exists to report; and a filter invocation is not a record.
func TestWithheldCountsRecordsAndNotFilterCalls(t *testing.T) {
	c := newCapture(t)
	var mu sync.Mutex
	broken := false
	e, err := New(Options{Config: &config.Observability{
		Attributes: map[string]string{"deployment.region": "eu-west-1"},
		Logs:       &config.Signal{Exporter: "http", Endpoint: c.srv.URL},
	}, Filter: func() (func(string) string, error) {
		mu.Lock()
		defer mu.Unlock()
		if broken {
			return nil, errors.New("PDR-E412 the secret store cannot be read")
		}
		return func(s string) string { return s }, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		e.Log("info", "a line queued while the filter worked", nil)
	}
	mu.Lock()
	broken = true
	mu.Unlock()
	e.Flush(context.Background())

	p := e.Posture()
	if p.Withheld != 3 {
		t.Errorf("withheld = %d — want 3, one per record the filter could not clear", p.Withheld)
	}
	if p.Dropped != 0 {
		t.Errorf("dropped = %d — a record withheld for the filter's sake is not a record a destination lost", p.Dropped)
	}
	if !strings.Contains(p.LastErr, "PDR-E412") {
		t.Errorf("last error = %q — want the filter's own refusal", p.LastErr)
	}
	if n := c.count(); n != 0 {
		t.Errorf("%d bodies reached the destination — want none", n)
	}
}

// Self-found beside the third finding: `observe test` is a diagnostic,
// and a probe is not a record. With the filter unavailable it counted
// one withheld record for the global attributes and one more for every
// probe whose error it could not filter — so running the command moved
// the number an operator reads for records lost.
func TestATestProbeIsNotAWithheldRecord(t *testing.T) {
	c := newCapture(t)
	e, err := New(Options{Config: &config.Observability{
		Attributes: map[string]string{"deployment.region": "eu-west-1"},
		Logs:       &config.Signal{Exporter: "http", Endpoint: c.srv.URL},
	}, Filter: func() (func(string) string, error) {
		return nil, errors.New("PDR-E412 the secret store cannot be read")
	}})
	if err != nil {
		t.Fatal(err)
	}
	probes := e.Test(context.Background())
	if len(probes) != 1 || probes[0].OK {
		t.Fatalf("the probe rows changed shape: %+v", probes)
	}
	if p := e.Posture(); p.Withheld != 0 {
		t.Errorf("withheld = %d after a diagnostic that carried no records", p.Withheld)
	}
}
