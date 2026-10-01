// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// swapOnAudit replaces the instance the moment an operation reaches past
// its resolution — reading the audit stream is what `Evidence` does after
// `instanceViewFor` has returned. That is the window round 15 names.
type swapOnAudit struct {
	state.Store
	mu    sync.Mutex
	armed func()
}

func (s *swapOnAudit) ListAudit(instance string) ([]state.Audit, error) {
	rows, err := s.Store.ListAudit(instance)
	s.mu.Lock()
	fire := s.armed
	s.armed = nil // once
	s.mu.Unlock()
	if fire != nil {
		fire()
	}
	return rows, err
}

// Round 14 compared the generation where the instance was resolved. An
// operation then goes on to read resources addressed by name alone — the
// journal, the secret store, the instance's own directory — so the
// comparison covered the resolution and nothing after it.
//
// Every bound operation confirms before it returns. That is sound rather
// than approximate: an instance's `audit_from` only ever increases for a
// name, so equal before and equal after means it was never anything else
// in between.
func TestAReadIsConfirmedBeforeItReturns(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PODARO_FAKE_READY_DELAY", "200ms")
	store := &swapOnAudit{Store: state.NewMemory()}
	h := &harness{t: t, store: store, world: dir + "/world.json", dir: dir}
	h.open()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = h.eng.Shutdown(ctx)
	})
	job, err := h.eng.Create(context.Background(), CreateRequest{Path: fixture, Name: "gen"})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)
	inst, err := h.eng.Instance("gen", Socket)
	if err != nil {
		t.Fatal(err)
	}
	mine := inst.AuditFrom

	// The lab is replaced after the read has resolved it and while the
	// read is still gathering what it will return.
	store.mu.Lock()
	store.armed = func() {
		if err := store.Store.DeleteInstance("gen"); err != nil {
			t.Errorf("destroying: %v", err)
		}
		replacement := *inst
		replacement.AuditFrom = mine + 4242
		if err := store.Store.PutInstance(replacement); err != nil {
			t.Errorf("re-creating: %v", err)
		}
	}
	store.mu.Unlock()

	_, err = h.eng.Evidence("gen", EvidenceFilter{}, Actor{Subject: "alice", Gen: &mine})
	if got := code(err); got != pdr.CodeInstanceNotFound {
		t.Fatalf("the read returned %s, not %s: it gathered the replacement's data after resolving the lab it was entitled to",
			got, pdr.CodeInstanceNotFound)
	}
}

// Review round 15, second finding: a destroy keeps an instance's jobs, so
// a name used twice carries jobs from more than one lab and the name
// alone cannot tell them apart.
func TestRetainedJobsBelongToTheGenerationThatRanThem(t *testing.T) {
	h := newHarness(t)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = h.eng.Shutdown(ctx)
	})
	job, err := h.eng.Create(context.Background(), CreateRequest{Path: fixture, Name: "gen"})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)
	inst, err := h.eng.Instance("gen", Socket)
	if err != nil {
		t.Fatal(err)
	}
	mine := inst.AuditFrom

	// What a previous lab of this name left behind.
	older := state.Job{ID: "j-older", Kind: "create", Instance: "gen", Gen: mine - 1,
		State: state.JobSucceeded, Stage: "ready", Started: time.Now().UTC().Add(-time.Hour)}
	if err := h.store.PutJob(older); err != nil {
		t.Fatal(err)
	}

	by := Actor{Subject: "alice", Gen: &mine}
	if _, err := h.eng.Job("j-older", by); code(err) != pdr.CodeInstanceNotFound {
		t.Errorf("a bearer read the previous lab's job: %v", err)
	}
	if _, err := h.eng.Events("j-older", by); code(err) != pdr.CodeInstanceNotFound {
		t.Errorf("a bearer read the previous lab's journal: %v", err)
	}
	rows, err := h.eng.Jobs("gen", by)
	if err != nil {
		t.Fatal(err)
	}
	for _, j := range rows {
		if j.ID == "j-older" {
			t.Error("the listing offered a bearer the previous lab's job")
		}
	}
	if len(rows) == 0 {
		t.Error("the bearer's own jobs vanished with it")
	}
	// The operator, entitled to no generation in particular, sees both.
	all, err := h.eng.Jobs("gen", Socket)
	if err != nil || len(all) <= len(rows) {
		t.Errorf("the operator must still see the whole history: %d vs %d (%v)", len(all), len(rows), err)
	}
}

// Review round 15, third finding: the gateway classifies a host before
// there is anyone to authenticate, so the dial itself must check.
func TestADialIsRefusedForAnotherGeneration(t *testing.T) {
	h := newHarness(t)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = h.eng.Shutdown(ctx)
	})
	job, err := h.eng.Create(context.Background(), CreateRequest{Path: fixture, Name: "gen"})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(job.ID)
	inst, err := h.eng.Instance("gen", Socket)
	if err != nil {
		t.Fatal(err)
	}
	stale := inst.AuditFrom - 1

	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		t.Error("the proxy dialled a lab this bearer is not entitled to")
		return nil, errors.New("must not dial")
	}
	if _, err := h.eng.DialService(context.Background(), "gen", "web", Actor{Gen: &stale}, dial); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("a dial for another generation returned %v, want ErrNoRoute", err)
	}
}
