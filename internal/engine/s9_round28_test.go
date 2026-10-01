// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/state"
)

// Review round 28 — the field beside the one I bound
// to the run last round.
//
// Round 27 recorded the image with the run. The module on the same row
// is refreshed by `publishPlanned` exactly as the image was, so a retry
// after an edited module paired the *old* run's image with the *new*
// module: a combination that never existed, in a table whose whole
// subject is what did.
//
// Every column of that table has to be a fact of the run or a fact that
// cannot move. `Name` cannot — a renamed service is a different row —
// and the image is now bound; the module was the last one loose.
func TestTheReportPairsTheModuleWithTheRunThatUsedIt(t *testing.T) {
	h := newHarness(t)
	job, err := h.eng.Create(context.Background(), CreateRequest{Path: labDir(t, "modretry"), Name: "modretry"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	services, err := h.store.ListServices("modretry")
	if err != nil || len(services) != 1 {
		t.Fatalf("the premise: one service ran (%v %v)", services, err)
	}
	svc := services[0]
	// The fixture's service has no module; give the run one so the row
	// carries a module that belongs to it.
	svc.Module, svc.RanModule = "web-1.0.0", "web-1.0.0"
	if err := h.store.PutService(svc); err != nil {
		t.Fatal(err)
	}

	// What a retry after an edited module leaves: the plan's new module
	// on the row, the run's facts untouched beside it.
	svc.Module = "web-2.0.0"
	if err := h.store.PutService(svc); err != nil {
		t.Fatal(err)
	}

	html, err := h.eng.Report("modretry", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(html), "web-2.0.0") {
		t.Errorf("the report pairs the run's image with a module that never ran with it")
	}
	if !strings.Contains(string(html), "web-1.0.0") {
		t.Errorf("the report lost the module the run actually used")
	}
}
