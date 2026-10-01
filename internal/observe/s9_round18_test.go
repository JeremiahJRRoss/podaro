// SPDX-License-Identifier: AGPL-3.0-only

package observe

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/config"
)

// The flush loop runs every five seconds whether or not anything was
// queued. With `observability.attributes` configured and the filter
// unavailable, each of those idle ticks built the global attributes,
// failed, and counted one withheld record — so `observe status` reported
// a growing loss on a deployment that had exported nothing and lost
// nothing. A count that climbs on its own is worse than no count: it is
// the number an operator would act on.
func TestAnIdleFlushWithholdsNothing(t *testing.T) {
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
	for range 3 {
		e.Flush(context.Background())
	}
	if p := e.Posture(); p.Withheld != 0 {
		t.Errorf("withheld = %d after three idle flushes — an operator reads that as records lost", p.Withheld)
	}
	if p := e.Posture(); p.LastErr != "" {
		t.Errorf("an idle flush left a last error: %q", p.LastErr)
	}

	// A record that really is withheld still counts, exactly once, and
	// still does not reach the destination.
	e.Log("info", "a line that must not leave", nil)
	e.Flush(context.Background())
	if p := e.Posture(); p.Withheld != 1 {
		t.Errorf("withheld = %d after one record was withheld — want 1", p.Withheld)
	}
	if n := c.count(); n != 0 {
		t.Errorf("%d bodies reached the destination — want none", n)
	}
}
