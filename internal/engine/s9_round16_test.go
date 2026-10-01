// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// swapOnServices replaces the instance the moment a view reaches past
// its resolution: `view` lists the services first, by name.
type swapOnServices struct {
	state.Store
	mu    sync.Mutex
	armed func()
}

func (s *swapOnServices) ListServices(instance string) ([]state.Service, error) {
	rows, err := s.Store.ListServices(instance)
	s.mu.Lock()
	fire := s.armed
	s.armed = nil // once
	s.mu.Unlock()
	if fire != nil {
		fire()
	}
	return rows, err
}

// Round 15 confirmed every bound operation before it returned — every
// one that resolves through `instanceViewFor`. `View` resolves the
// instance itself, so the deferred confirmation never reached it, and
// `view` goes on to read services, jobs and checkpoint results by name.
// A lab replaced during those reads hands an in-flight attendee the
// replacement's data under the old instance's row.
//
// The miss is mine: round 15's sweep listed View as bound, which it was
// — at resolution. It did not ask the question round 15 had just added.
func TestTheInstanceViewIsConfirmedAfterItIsBuilt(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PODARO_FAKE_READY_DELAY", "200ms")
	store := &swapOnServices{Store: state.NewMemory()}
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

	_, err = h.eng.View("gen", Actor{Subject: "alice", Gen: &mine})
	if got := code(err); got != pdr.CodeInstanceNotFound {
		t.Fatalf("the view returned %s, not %s: it was built from the replacement's services after resolving the lab it was entitled to",
			got, pdr.CodeInstanceNotFound)
	}
	// The operator, entitled to no generation, still gets a view.
	if _, err := h.eng.View("gen", Socket); err != nil {
		t.Errorf("the operator was refused: %v", err)
	}
}
