// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/state"
)

// Review round 26 — one finer cut on the same table.
//
// Round 25 asked the row for a container id, because that is written
// when the container is made. `bringUp` writes it immediately after
// `rt.Create` and before `rt.Start`, so a container that was created and
// never ran carried one too: an image and a service in "What ran" that
// executed nothing. The fact that proves a run is the start — `StartedAt`
// is written only past the branches that refuse a container which did
// not come up running.
func TestTheReportOmitsAContainerThatNeverStarted(t *testing.T) {
	h := newHarness(t)
	job, err := h.eng.Create(context.Background(), CreateRequest{Path: labDir(t, "startonly"), Name: "startonly"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	ran, err := h.store.ListServices("startonly")
	if err != nil || len(ran) != 1 || ran[0].StartedAt == nil {
		t.Fatalf("the premise: a service that ran records when it started (%v %v)", ran, err)
	}

	// The row as it stands between `rt.Create` and a start that fails:
	// the container's id is known, and nothing has run.
	made := state.Service{
		Instance: "startonly", Name: "stillborn", Container: "pdr-startonly-stillborn",
		ContainerID: "c0ffee1234", Stage: state.StageNone, Module: "m",
		Image: "docker.io/library/stillborn@sha256:3333333333333333333333333333333333333333333333333333333333333333",
	}
	if err := h.store.PutService(made); err != nil {
		t.Fatal(err)
	}

	html, err := h.eng.Report("startonly", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(html), "sha256:333333333333") {
		t.Errorf("the report presents a container that was created and never started as having run")
	}
	if strings.Contains(string(html), ">stillborn<") {
		t.Errorf("the report names a service that never executed")
	}
	if want := strings.SplitN(ran[0].Image, "@", 2)[1][:19]; !strings.Contains(string(html), want) {
		t.Errorf("the report lost the service that did run: %q", want)
	}
}
