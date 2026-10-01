// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/state"
)

// Review round 27 — the same table, one step further
// back.
//
// Round 26 asked the row for `StartedAt`, which is written only when a
// container is seen running. But `StartedAt` belongs to the *service*,
// not to the image on the row beside it. An authoring instance can be
// retried after the author changes an image: `publishPlanned` refreshes
// `Image` and keeps the old start time, `bringUp` records the
// replacement's container id before attempting to start it, and a
// replacement that fails to start leaves a row reading "image B, and it
// started" — when only image A ever ran.
//
// The row's image is the plan's; what ran is a fact of the run and has
// to be written when the run is seen. This test drives the state that
// retry leaves rather than the retry itself, because the state is the
// thing the report reads.
func TestTheReportNamesTheImageThatRanNotTheOneRetried(t *testing.T) {
	h := newHarness(t)
	job, err := h.eng.Create(context.Background(), CreateRequest{Path: labDir(t, "retried"), Name: "retried"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	services, err := h.store.ListServices("retried")
	if err != nil || len(services) != 1 {
		t.Fatalf("the premise: one service ran (%v %v)", services, err)
	}
	svc := services[0]
	ranDigest := strings.SplitN(svc.Image, "@", 2)[1]

	// What a retry after an edited image leaves behind: the plan's new
	// image on the row, the replacement's container id, and the start
	// time of the run that actually happened — the old one's.
	const replacement = "docker.io/library/replaced@sha256:4444444444444444444444444444444444444444444444444444444444444444"
	svc.Image = replacement
	svc.ContainerID = "c0ffeereplaced"
	if err := h.store.PutService(svc); err != nil {
		t.Fatal(err)
	}

	html, err := h.eng.Report("retried", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(html), "sha256:444444444444") {
		t.Errorf("the report names an image that was planned and never ran")
	}
	if !strings.Contains(string(html), ranDigest[:19]) {
		t.Errorf("the report lost the image that did run: %q", ranDigest[:19])
	}
}
