// SPDX-License-Identifier: AGPL-3.0-only

package api

// The observability export's own surface (API §5, plan S9): what is
// configured and what has happened to it, and a probe through each
// configured signal.
//
// Neither endpoint can turn export on: that is a configuration file the
// operator edits and the engine re-reads (`podaro setup` / restart). An
// API that could redirect the engine's logs to an endpoint of the
// caller's choosing would be a far better exfiltration primitive than
// anything else on this door.

import (
	"context"
	"net/http"
	"time"

	"github.com/jeremiahjrross/podaro/internal/auth"
	"github.com/jeremiahjrross/podaro/internal/observe"
)

// observeRoutes registers the two endpoints.
func (s *Server) observeRoutes() {
	s.handle("GET /system/observe", auth.ScopeRead, s.getObserve)
	// A probe sends real traffic to a configured destination and reports
	// whether its credential worked: an administrative act, at the scope
	// that manages credentials.
	s.handle("POST /system/observe/test", auth.ScopeAdmin, s.testObserve)
}

// ObserveTestTimeout bounds a whole probe run: three signals, each with
// the exporter's own per-request timeout.
const ObserveTestTimeout = 45 * time.Second

func (s *Server) getObserve(w http.ResponseWriter, r *http.Request) {
	s.respond(w, r, http.StatusOK, s.o.Observe.Posture(), "", nil)
}

func (s *Server) testObserve(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), ObserveTestTimeout)
	defer cancel()
	probes := s.o.Observe.Test(ctx)
	if probes == nil {
		// Not an error: export is off, which is the default and the
		// documented posture. Saying so beats an empty list.
		probes = []observe.Probe{}
	}
	s.respond(w, r, http.StatusOK, map[string]any{"probes": probes}, "", nil)
}
