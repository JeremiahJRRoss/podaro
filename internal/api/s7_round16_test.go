// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/engine"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// API §4 documents a reveal's audit frame as
// `{"action":"reveal","secret":"admin","actor":"operator"}`. The feed
// carried the credential's name under `detail` and nothing under
// `secret`, so a client written against the documented payload found the
// field missing and had to guess that a generic `detail` meant the
// secret for this one action.
//
// It is the *name*, never a value: `engine.Reveal` records the secret's
// name in the audit row's detail, and that is the same string the
// credentials list and the Evidence journal already show. The audit
// stream holds no values at all (invariant 6).
//
// `detail` stays where it is — every other action's audit carries one,
// and this is additive.
func TestARevealAuditFrameCarriesTheSecretAPI4Documents(t *testing.T) {
	srv, eng, store := eventsHarness(t)
	ctx := context.Background()
	fixture, _ := filepath.Abs(filepath.Join("..", "..", "hack", "fixtures", "hello-nginx"))
	job, err := eng.Create(ctx, engine.CreateRequest{Path: fixture, Name: "audited"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Wait(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	body, closeFeed := openFeed(t, srv, "audited", "")
	defer closeFeed()
	v, err := eng.View("audited", engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	readFrames(t, body, len(v.Services)+2, 5*time.Second, closeFeed)

	// A reveal, and an action that is not one: the field belongs to the
	// reveal alone, because only there does `detail` mean a secret.
	now := time.Now().UTC()
	for _, a := range []state.Audit{
		{At: now, Instance: "audited", Action: "reveal", Actor: "operator", Mechanism: "session", Detail: "nginx-admin"},
		{At: now.Add(time.Millisecond), Instance: "audited", Action: "reset", Actor: "operator", Mechanism: "session", Detail: "instance audited"},
	} {
		if err := store.AppendAudit(a); err != nil {
			t.Fatal(err)
		}
	}
	// The fixture produced the state: both rows are in the evidence the
	// feed reads, and the reveal's detail is the secret's name.
	entries, err := eng.Evidence("audited", engine.EvidenceFilter{}, engine.Socket)
	if err != nil {
		t.Fatal(err)
	}
	rows := 0
	for _, e := range entries {
		if e.Audit != nil {
			rows++
			if e.Audit.Action == "reveal" && e.Audit.Detail != "nginx-admin" {
				t.Fatalf("the fixture's reveal does not carry the secret's name: %q", e.Audit.Detail)
			}
		}
	}
	if rows != 2 {
		t.Fatalf("the fixture put %d audit rows in evidence, want 2", rows)
	}

	frames := readFrames(t, body, 2, 6*time.Second, closeFeed)
	var reveal, other *sseFrame
	for i := range frames {
		if frames[i].Event != "audit" {
			continue
		}
		if frames[i].Data["action"] == "reveal" {
			reveal = &frames[i]
		} else {
			other = &frames[i]
		}
	}
	if reveal == nil {
		t.Fatalf("the reveal was never sent as an audit frame; frames: %s", describe(frames))
	}
	if got := reveal.Data["secret"]; got != "nginx-admin" {
		t.Fatalf("a reveal's frame carries secret %v, and API §4 documents the credential's name; frame: %v", got, reveal.Data)
	}
	if got := reveal.Data["detail"]; got != "nginx-admin" {
		t.Errorf("the record's own detail is no longer carried: %v", got)
	}
	if other == nil {
		t.Fatalf("the second audit row was never sent; frames: %s", describe(frames))
	}
	if _, ok := other.Data["secret"]; ok {
		t.Errorf("an audit that is not a reveal carries a secret field: %v", other.Data)
	}
}
