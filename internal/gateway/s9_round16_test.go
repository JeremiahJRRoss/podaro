// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/engine"
)

// countingRT stands in for the pooled transport: it never dials, which
// is the whole point — a reused keep-alive connection reaches the
// upstream without the dialer being asked anything.
type countingRT struct{ n int }

func (c *countingRT) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n++
	return httptest.NewRecorder().Result(), nil
}

// Round 15 put the generation check in the dial. `http.Transport` reuses
// an idle connection without dialling, so a request authenticated before
// a destroy could ride a connection a current-generation request had
// already opened, and the dial guard would never see that round trip.
//
// The check belongs where every round trip passes — `routeGuard`, which
// already exists to catch exactly this shape for withdrawn routes.
func TestAPooledConnectionIsRefusedForAnotherGeneration(t *testing.T) {
	r := newRig(t)
	r.up("t1")
	inst, err := r.st.GetInstance("t1")
	if err != nil {
		t.Fatal(err)
	}
	stale := inst.AuditFrom - 1
	mine := inst.AuditFrom

	rt := &countingRT{}
	guard := routeGuard{rt: rt, eng: r.eng}

	req := httptest.NewRequest(http.MethodGet, "http://web.t1.upstream.invalid/", nil)
	req.URL.Host = upstreamHost("t1", "web")

	// A bearer of the generation that is gone never reaches the upstream,
	// even though nothing is dialled on this path.
	stalereq := req.Clone(withGeneration(req.Context(), &stale))
	if _, err := guard.RoundTrip(stalereq); err == nil {
		t.Error("a stale bearer rode a pooled connection into the lab that took its name")
	}
	if rt.n != 0 {
		t.Errorf("the round trip reached the upstream %d time(s)", rt.n)
	}

	// The current generation still goes through, so the guard is not
	// simply refusing everyone.
	ownreq := req.Clone(withGeneration(req.Context(), &mine))
	if _, err := guard.RoundTrip(ownreq); err != nil {
		t.Errorf("a bearer of the current generation was refused: %v", err)
	}
	if rt.n != 1 {
		t.Errorf("the current generation's round trip did not reach the upstream (%d)", rt.n)
	}

	// And the operator, carrying no generation at all, is unaffected.
	if _, err := guard.RoundTrip(req.Clone(req.Context())); err != nil {
		t.Errorf("a request carrying no generation was refused: %v", err)
	}
	_ = engine.ErrNoRoute
}
