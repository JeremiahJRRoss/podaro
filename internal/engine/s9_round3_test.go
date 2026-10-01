// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/evidence"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// A destroy takes the lab's directory, its journal and its rows — but
// audit rows stay, because they are the security record. So a name used
// twice merged the first lab's `join` and `reveal` rows into the
// second's evidence: its attendees read them (this endpoint is theirs),
// and its forwardable report named people and secrets from a lab they
// were never in.
//
// The third thing to survive a destroy in three rounds. The credential
// went in round 1, the session in round 2, and this is the record.
func TestEvidenceIsThisInstanceNotTheOneBeforeIt(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	body := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: reused, version: 1.0.0 }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }
secrets:
  admin: { kind: password, description: the secret the first lab's attendee revealed }
checkpoints:
  - id: web-up
    adapter: http
    params: { url: http://web:80/ }
    expect: { status: 200 }
    retries: { attempts: 1 }
    hint: Is the web service answering on port 80?
`
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "reused"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	// The first lab's attendee joins and reveals a secret — during its
	// life, which is what makes the rows its own.
	inst, err := h.store.GetInstance("reused")
	if err != nil || inst == nil {
		t.Fatalf("the first instance: %+v %v", inst, err)
	}
	// The dates here are ordinary; what makes these rows the first
	// lab's is that they are appended while it is the one that exists.
	// The line between generations is the audit sequence, not the clock
	// — a host clock that stepped back would otherwise hide a live
	// instance's own rows, which is the mistake review round 69
	// recorded for freshness and this rule would have repeated.
	first := inst.Created.Add(time.Millisecond)
	for _, a := range []state.Audit{
		{At: first, Instance: "reused", Action: "join", Actor: "alice", Mechanism: "instance-access"},
		{At: first.Add(time.Millisecond), Instance: "reused", Action: "reveal", Actor: "alice", Detail: "admin"},
	} {
		if err := h.store.AppendAudit(a); err != nil {
			t.Fatal(err)
		}
	}
	// The premise: this lab's own evidence carries them.
	before, err := h.eng.Evidence("reused", EvidenceFilter{Type: string(evidence.TypeAudit)}, Socket)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) == 0 {
		t.Fatal("premise: the first lab's audit rows are not in its evidence")
	}
	beforeEntries := before

	// It is destroyed and the name is used again.
	dj, err := h.eng.Destroy(ctx, "reused", "reused")
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(dj.ID); j.State != state.JobSucceeded {
		t.Fatalf("destroy: %+v", j)
	}
	job, err = h.eng.Create(ctx, CreateRequest{Path: dir, Name: "reused"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("re-create: %+v", j)
	}

	after, err := h.eng.Evidence("reused", EvidenceFilter{Type: string(evidence.TypeAudit)}, Socket)
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range after {
		if en.Audit != nil && en.Audit.Actor == "alice" {
			t.Errorf("the new lab's evidence carries the old lab's %s by %s", en.Audit.Action, en.Audit.Actor)
		}
	}
	// And so does the report an operator forwards.
	raw, err := h.eng.Report("reused", Socket)
	if err != nil {
		t.Fatal(err)
	}
	page := string(raw)
	// `alice` appears on the page only through a join or a reveal, so it
	// is the whole question. The secret's *name* is not: this template
	// declares `admin`, and the report may name a declared secret —
	// what it must not carry is the previous generation's reveal of it,
	// which is the section below and the count asserted further down.
	if contains(page, "alice") {
		t.Errorf("the report names the attendee of the lab before this one")
	}
	if contains(page, "Credentials revealed") {
		t.Errorf("the report carries a reveal from the lab before this one")
	}

	// Round 4: and not through the other doors either. The single-entry
	// read takes `au_<seq>` ids, which are consecutive integers — an
	// attendee who can fetch one can count downwards — and the secret
	// list carries a reveal count per secret.
	for _, en := range beforeEntries {
		if en.Audit == nil {
			continue
		}
		got, err := h.eng.EvidenceEntry("reused", en.ID, Socket)
		if err == nil && got != nil {
			t.Errorf("%s from the lab before this one is still fetchable by id", en.ID)
		}
	}
	secrets, err := h.eng.Secrets("reused", Socket)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if s.Reveals != 0 {
			t.Errorf("secret %s carries %d reveals from the lab before this one", s.Name, s.Reveals)
		}
	}

	// The whole history is still the operator's, on the audit stream the
	// socket serves: nothing was deleted, only scoped.
	rows, err := h.store.ListAudit("reused")
	if err != nil {
		t.Fatal(err)
	}
	var kept bool
	for _, a := range rows {
		if a.Actor == "alice" {
			kept = true
		}
	}
	if !kept {
		t.Errorf("the destroy erased the security record instead of scoping the reader")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// Round 4: and the line is drawn or the lab is not created. Falling back
// to zero — "everything" — would have been written into the instance row
// permanently, so one transient store error would hand the next
// attendee the previous generation's joins and reveals for the life of
// the instance. A create the operator can retry is the cheaper failure.
func TestACreateRefusesRatherThanLoseTheGenerationLine(t *testing.T) {
	h := newHarness(t)
	faulty := &faultyStore{Store: h.store}
	h.store = faulty
	h.open()
	dir := t.TempDir()
	body := `apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: refused, version: 1.0.0 }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }
`
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	faulty.set(func(f *faultyStore) { f.failLatestSeq = true })
	if _, err := h.eng.Create(context.Background(), CreateRequest{Path: dir, Name: "refused"}); err == nil {
		t.Fatal("the create went ahead without a generation line")
	}
	faulty.set(func(f *faultyStore) { f.failLatestSeq = false })
	if inst, err := h.store.GetInstance("refused"); err == nil && inst != nil {
		t.Errorf("the refused create left an instance behind: %+v", inst)
	}
}
