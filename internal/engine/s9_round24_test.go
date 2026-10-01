// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/state"
)

// An authoring instance tracks its working directory — invariant 4's one
// declared exception — so the plan the engine reloads is whatever the
// author has saved *since* the containers started. The report's "What
// ran" table was built from that plan, so an edit made after the run
// rewrote the record of it: a service, a module and an image digest no
// container was ever made from, in the one artefact built to leave the
// building. What ran is what the engine wrote down when it made the
// containers, and that is where the table must come from.
func TestTheReportSaysWhatRanNotWhatWasEditedAfter(t *testing.T) {
	h := newHarness(t)
	dir := labDir(t, "edited")
	job, err := h.eng.Create(context.Background(), CreateRequest{Path: dir, Name: "edited"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	services, err := h.store.ListServices("edited")
	if err != nil || len(services) == 0 {
		t.Fatalf("the premise: the engine recorded what it created (%v %v)", services, err)
	}
	ran := services[0].Image
	if !strings.Contains(ran, "@sha256:") {
		t.Fatalf("the recorded image is not a pinned reference: %q", ran)
	}

	// The author saves a different image after the lab is up. Nothing was
	// re-created: the container still running is the one above.
	raw, err := os.ReadFile(filepath.Join(dir, "lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	const invented = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	edited := strings.Replace(string(raw), strings.SplitN(ran, "@", 2)[1], invented, 1)
	if edited == string(raw) {
		t.Fatalf("the premise: the digest to replace was not found in the source")
	}
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}

	html, err := h.eng.Report("edited", Socket)
	if err != nil {
		t.Fatal(err)
	}
	// The table prints a digest shortened to nineteen characters, which
	// is still the part that identifies it.
	shown := func(digest string) string { return digest[:19] }
	if strings.Contains(string(html), shown(invented)) {
		t.Errorf("the report records an image no container was made from: %s", shown(invented))
	}
	if want := shown(strings.SplitN(ran, "@", 2)[1]); !strings.Contains(string(html), want) {
		t.Errorf("the report does not name the image that actually ran: %q", want)
	}
}
