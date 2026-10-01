// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"
	"strings"
	"testing"
)

// Review round 4: the Evidence panel's Journal section was
// rendered only when EvidenceData.Entries was populated, and the only
// production construction of EvidenceData — GET …/checkpoints — leaves
// it nil. So the console's Evidence tab showed each checkpoint's latest
// result and nothing else: no repeated runs, no seeds, no lifecycle
// milestones, no reveal audits. The golden that carried journal rows
// exercised a state no handler could produce.
//
// The binding rule says why it could not simply be filled in there: a
// fragment may render only what its JSON twin contains, and the twin of
// …/checkpoints is {"checkpoints": […]} — it has no journal in it. The
// journal's twin is …/evidence, which had no HTML side at all. This
// gives it one.

func TestTheEvidenceJournalIsServedByTheTwinThatCarriesIt(t *testing.T) {
	srv, eng := newCatalogServer(t)
	code, out := call(t, srv, http.MethodPost, "/instances", map[string]any{"template": "grafana-prometheus-intro", "name": "intro"})
	if code != http.StatusAccepted {
		t.Fatalf("create: %d %v", code, out)
	}
	waitJob(t, eng, out)

	// The scoreboard is the checkpoints twin, and it must not pretend to
	// carry a journal: it points at the twin that does.
	board := readAll(do(t, srv, http.MethodGet, "/instances/intro/checkpoints", map[string]string{"Accept": "text/html"}, ""))
	if !strings.Contains(board, `/instances/intro/evidence`) {
		t.Errorf("the Evidence scoreboard does not reach the journal: no region fetching …/evidence\n%s", board)
	}

	// …/evidence answers HTML now, and what it answers is the journal.
	resp := do(t, srv, http.MethodGet, "/instances/intro/evidence", map[string]string{"Accept": "text/html"}, "")
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("GET …/evidence with Accept: text/html answered %s, want text/html", ct)
	}
	journal := readAll(resp)
	if !strings.Contains(journal, `class="journal`) {
		t.Errorf("the evidence fragment is not the journal:\n%s", journal)
	}
	// A create leaves lifecycle entries behind, so the rows are real.
	if !strings.Contains(journal, "lifecycle") {
		t.Errorf("the journal carries no lifecycle entry from the create:\n%s", journal)
	}
}
