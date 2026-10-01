// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/engine"
)

// A reveal is audited twice on purpose: `Engine.Reveal` appends the
// record to the audit store, which numbers it, and appends the same
// record to the instance journal, which does not — API §2.5 says
// security events land in the evidence stream, and the journal is where
// a client reads them. `Engine.Evidence` then deduplicates the pair by
// value and keeps the journal's copy, so the entry a client actually
// sees is `ev_…` carrying an audit whose `Seq` is zero.
//
// The feed decided which of its two cursors owned an entry by the
// *payload*: anything with an audit was compared against the audit
// sequence. Zero is never greater than zero, so a reveal that happened
// while a client was watching produced no frame at all — the one action
// API §4 documents a dedicated field for.
//
// The sequence a record belongs to is its **id namespace**, which is the
// only thing that says where it came from: `au_<n>` is the audit store's
// numbering, and everything else is the journal's order.
//
// Round 16's test asserted the frame's `secret` field and passed, because
// its fixture appended audit rows straight to the store. Those carry
// sequences. No test had ever run a reveal.
func TestARevealWhileTheClientWatchesReachesIt(t *testing.T) {
	srv, eng, _ := eventsHarness(t)
	ctx := context.Background()
	fixture := secretFixture(t)
	job, err := eng.Create(ctx, engine.CreateRequest{Path: fixture, Name: "revealed"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Wait(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	v, err := eng.View("revealed", engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := eng.Jobs("revealed", engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	body, closeFeed := openFeed(t, srv, "revealed", "")
	defer closeFeed()
	readFrames(t, body, len(v.Services)+1+len(rows), 6*time.Second, closeFeed)

	// The real path, not a hand-written row: this is the case no test
	// had covered.
	if _, err := eng.Reveal(ctx, "revealed", "web-admin", engine.Actor{Subject: "operator", Mechanism: "session"}); err != nil {
		t.Fatal(err)
	}
	// The fixture produced the state the finding describes: one entry for
	// the reveal, from the journal, with no audit sequence on it.
	entries, err := eng.Evidence("revealed", engine.EvidenceFilter{}, engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	reveals := 0
	for _, e := range entries {
		if e.Audit == nil || e.Audit.Action != "reveal" {
			continue
		}
		reveals++
		if !strings.HasPrefix(e.ID, "ev_") {
			t.Fatalf("the reveal reached evidence as %q; this case needs the journal's copy", e.ID)
		}
		if e.Audit.Seq != 0 {
			t.Fatalf("the journal's copy carries sequence %d; this case needs the unnumbered one", e.Audit.Seq)
		}
	}
	if reveals != 1 {
		t.Fatalf("the fixture put %d reveals in evidence, want 1", reveals)
	}

	frames := readFrames(t, body, 1, 6*time.Second, closeFeed)
	var got *sseFrame
	for i := range frames {
		if frames[i].Event == "audit" && frames[i].Data["action"] == "reveal" {
			got = &frames[i]
		}
	}
	if got == nil {
		t.Fatalf("a reveal that happened while the client watched sent no audit frame; frames: %s", describe(frames))
	}
	// The name, never a value (invariant 6) — which is also why nothing
	// here prints what `Reveal` returned.
	if got.Data["secret"] != "web-admin" {
		t.Errorf("the frame names secret %v, want the credential's name; frame: %v", got.Data["secret"], got.Data)
	}
}

// And the same namespace decides a resume. A client that names a
// journalled audit's `ev_…` id is naming a position in the *journal*;
// reading its zero sequence as an audit position left the journal cursor
// empty, which means "nothing sent" — so the reconnect replayed the
// whole journal as new.
func TestAResumeFromAJournalledAuditReplaysOnlyWhatFollows(t *testing.T) {
	srv, eng, _ := eventsHarness(t)
	ctx := context.Background()
	fixture := secretFixture(t)
	job, err := eng.Create(ctx, engine.CreateRequest{Path: fixture, Name: "resumed25"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Wait(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Reveal(ctx, "resumed25", "web-admin", engine.Actor{Subject: "operator", Mechanism: "session"}); err != nil {
		t.Fatal(err)
	}
	entries, err := eng.Evidence("resumed25", engine.EvidenceFilter{}, engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	last := entries[len(entries)-1]
	if last.Audit == nil || last.Audit.Action != "reveal" || !strings.HasPrefix(last.ID, "ev_") {
		t.Fatalf("this case needs the journalled reveal last in evidence, got %s %v", last.ID, last.Type)
	}
	if len(entries) < 3 {
		t.Fatalf("this case needs a history to wrongly replay, got %d entries", len(entries))
	}

	v, err := eng.View("resumed25", engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := eng.Jobs("resumed25", engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	// A client that has seen everything, reconnecting: the snapshots are
	// all it is owed. Read past them and one more, so a replay that
	// should not happen has a frame to arrive in.
	body, closeFeed := openFeed(t, srv, "resumed25", last.ID)
	defer closeFeed()
	frames := readFrames(t, body, len(v.Services)+1+len(rows)+1, 6*time.Second, closeFeed)
	replayed := []string{}
	for _, f := range frames {
		if f.ID != "" {
			replayed = append(replayed, f.ID)
		}
	}
	if len(replayed) > 0 {
		t.Fatalf("a reconnect from the journalled reveal replayed %d entries it had already seen: %v",
			len(replayed), replayed)
	}
}

// secretFixture is hello-nginx with a declared credential, so a test can
// run a real reveal. The image is the same digest-pinned one; the fake
// runtime never pulls it.
func secretFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	manifest := `# SPDX-License-Identifier: AGPL-3.0-only
apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata:
  name: hello-secret
  version: 0.1.0
  title: Hello nginx with a credential (test fixture)
secrets:
  web-admin: { kind: password }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    endpoints: [ { purpose: ui, port: 80 } ]
    embed: iframe
    readiness: { probe: { port: 80, path: /, expect_status: 200 }, typical: 5s, budget: 1m }
    resources: { cpu: 500m, memory: 128MiB }
`
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}
