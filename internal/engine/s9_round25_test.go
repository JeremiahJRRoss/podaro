// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/state"
)

// Review round 25, first finding — a hole in round
// 24's own fix.
//
// Round 24 moved "What ran" off the reloaded plan and onto the service
// rows, because those are written when the containers are made. Half of
// that is true: `publishPlanned` writes a row for every *planned*
// service before the job is launched, with no container id and stage
// none. So a report taken while a create is still queued, or after one
// that failed before it made anything, presented every planned service
// as having run — the same claim about an experiment that did not
// happen, arrived at from the other side.
//
// A row proves a container existed when it carries that container's id.
func TestTheReportOmitsAServiceThatNeverRan(t *testing.T) {
	h := newHarness(t)
	job, err := h.eng.Create(context.Background(), CreateRequest{Path: labDir(t, "ranonly"), Name: "ranonly"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	services, err := h.store.ListServices("ranonly")
	if err != nil || len(services) != 1 {
		t.Fatalf("the premise: one service ran (%v %v)", services, err)
	}
	if services[0].ContainerID == "" {
		t.Fatalf("the premise: the row of a service that ran carries its container id")
	}

	// The row `publishPlanned` writes before anything is created: the
	// plan's facts, no container, stage none.
	planned := state.Service{
		Instance: "ranonly", Name: "never", Container: "pdr-ranonly-never", Stage: state.StageNone,
		Module: "m", Image: "docker.io/library/never@sha256:2222222222222222222222222222222222222222222222222222222222222222",
	}
	if err := h.store.PutService(planned); err != nil {
		t.Fatal(err)
	}

	html, err := h.eng.Report("ranonly", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(html), "sha256:222222222222") {
		t.Errorf("the report presents a service no container was ever made for as having run")
	}
	if strings.Contains(string(html), ">never<") {
		t.Errorf("the report names a service that never ran")
	}
	// And the one that did run is still there.
	if want := strings.SplitN(services[0].Image, "@", 2)[1][:19]; !strings.Contains(string(html), want) {
		t.Errorf("the report lost the service that ran: %q", want)
	}
}
