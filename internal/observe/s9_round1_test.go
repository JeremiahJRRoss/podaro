// SPDX-License-Identifier: AGPL-3.0-only

package observe

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/config"
)

// `observability.attributes` are the operator's own, sent beside every
// record and every probe. Each record's body and attributes went through
// the redaction filter; these were passed to the sinks exactly as
// configured — so a credential written into a resource attribute, which
// is precisely the sort of thing resource attributes collect, left the
// host unfiltered. B10's promise is that the export path carries the
// same filter as everything else, without exception.
func TestTheConfiguredAttributesAreFilteredToo(t *testing.T) {
	c := newCapture(t)
	const secret = "s3cr3t-admin-password"
	filter := func() (func(string) string, error) {
		return func(s string) string { return strings.ReplaceAll(s, secret, "[redacted]") }, nil
	}
	e, err := New(Options{Config: &config.Observability{
		Attributes: map[string]string{"deployment.token": secret},
		Logs:       &config.Signal{Exporter: "http", Endpoint: c.srv.URL},
		Metrics:    &config.Signal{Exporter: "http", Endpoint: c.srv.URL},
		Traces:     &config.Signal{Exporter: "otlp", Endpoint: c.srv.URL},
	}, Filter: filter})
	if err != nil {
		t.Fatal(err)
	}
	e.Log("info", "nothing secret in this line", nil)
	e.Metric("podaro.test", 1, nil)
	e.Trace(Span{TraceID: "aa", SpanID: "bb", Name: "create", Start: time.Now(), End: time.Now()})
	e.Flush(context.Background())

	body := c.all()
	// The premise: the attribute really was sent — a filter that works by
	// dropping the attribute altogether would prove nothing.
	// The body is never printed on a failure: it is the thing under
	// suspicion of carrying a secret.
	if !strings.Contains(body, "deployment.token") {
		t.Fatalf("the configured attribute never reached the wire (%d bytes captured)", len(body))
	}
	if strings.Contains(body, secret) {
		t.Errorf("a configured attribute carried a secret to the wire")
	}
	if n := strings.Count(body, "[redacted]"); n != 3 {
		t.Errorf("%d values filtered — want three, one per signal", n)
	}
}

// And a probe carries them as well: `observe test` is the command an
// operator runs to see the path working, so it must not be the one call
// that skips the filter.
func TestAProbeCarriesTheAttributesFiltered(t *testing.T) {
	c := newCapture(t)
	const secret = "s3cr3t-admin-password"
	e, err := New(Options{Config: &config.Observability{
		Attributes: map[string]string{"deployment.token": secret},
		Logs:       &config.Signal{Exporter: "http", Endpoint: c.srv.URL},
	}, Filter: func() (func(string) string, error) {
		return func(s string) string { return strings.ReplaceAll(s, secret, "[redacted]") }, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	probes := e.Test(context.Background())
	if len(probes) == 0 {
		t.Fatal("no probe was sent")
	}
	body := c.all()
	if !strings.Contains(body, "deployment.token") {
		t.Fatalf("the probe carried no configured attribute (%d bytes captured)", len(body))
	}
	if strings.Contains(body, secret) {
		t.Errorf("the probe carried a secret to the wire")
	}
}
