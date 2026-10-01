// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

// Review round 66: a job id drawn from entropy that failed, or from a
// draw that repeats, must never reach the store. PutJob upserts on the
// id, so an id already in use overwrites the job that holds it — another
// instance's, in the worst case — and one row then answers for two jobs.

// failingReader is an entropy source that refuses.
type failingReader struct{ err error }

func (f failingReader) Read([]byte) (int, error) { return 0, f.err }

// swapJobRand installs an entropy source for one test and restores the
// real one after it.
func swapJobRand(t *testing.T, r io.Reader) {
	t.Helper()
	old := jobRand
	jobRand = r
	t.Cleanup(func() { jobRand = old })
}

func TestAJobIsNotAdmittedOnEntropyThatFailed(t *testing.T) {
	h := newHarness(t)
	swapJobRand(t, failingReader{err: errors.New("entropy source unavailable")})
	_, err := h.eng.Create(context.Background(), CreateRequest{Path: fixture, Name: "t1"})
	if err == nil {
		t.Fatal("a create was admitted while the entropy source refused")
	}
	if code(err) != pdr.CodeRuntimeFailed {
		t.Errorf("want %s, got %v", pdr.CodeRuntimeFailed, err)
	}
	// The failure names the cause without inventing an id.
	if strings.Contains(err.Error(), "job_0000000000000000") {
		t.Errorf("the error carries the all-zero id: %v", err)
	}
	jobs, listErr := h.store.ListJobs("")
	if listErr != nil {
		t.Fatal(listErr)
	}
	for _, j := range jobs {
		if j.ID == "job_0000000000000000" {
			t.Fatalf("an all-zero job id reached the store: %+v", j)
		}
	}
}

// truncatedReader hands out a few bytes and then ends. The old code took
// whatever arrived and filled the rest of the id with zeros; the fix
// reads the eight bytes in full, so an entropy source that stops early is
// a refusal, not a partially predictable id.
type truncatedReader struct{ left int }

func (r *truncatedReader) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > r.left {
		n = r.left
	}
	for i := 0; i < n; i++ {
		p[i] = 0x5A
	}
	r.left -= n
	return n, nil
}

func TestAJobIsNotAdmittedOnEntropyThatStopsShort(t *testing.T) {
	h := newHarness(t)
	swapJobRand(t, &truncatedReader{left: 3})
	_, err := h.eng.Create(context.Background(), CreateRequest{Path: fixture, Name: "t1"})
	if err == nil {
		t.Fatal("a create was admitted on an entropy source that stopped short")
	}
	if code(err) != pdr.CodeRuntimeFailed {
		t.Errorf("want %s, got %v", pdr.CodeRuntimeFailed, err)
	}
	// The five bytes never read must not have become zeros in an id.
	jobs, listErr := h.store.ListJobs("")
	if listErr != nil {
		t.Fatal(listErr)
	}
	for _, j := range jobs {
		if strings.HasSuffix(j.ID, "0000000000") {
			t.Fatalf("an id padded with unread entropy reached the store: %+v", j)
		}
	}
}

// dribbleReader answers one byte at a time. A source that is merely slow
// is not a broken one: the id is read in full across as many reads as it
// takes, and the create proceeds.
type dribbleReader struct{ n byte }

func (r *dribbleReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	r.n++
	p[0] = r.n
	return 1, nil
}

func TestASlowEntropySourceStillYieldsAWholeJobID(t *testing.T) {
	swapJobRand(t, &dribbleReader{})
	id, err := newJobID()
	if err != nil {
		t.Fatalf("a source answering one byte at a time was refused: %v", err)
	}
	if id != "job_0102030405060708" {
		t.Fatalf("the id did not read all eight bytes in order: %s", id)
	}
}

// repeatingReader hands out the same eight bytes for its first n reads,
// then counts up — a source that repeats itself, as a reseeded or
// snapshot-restored generator can.
type repeatingReader struct {
	repeat int
	seen   int
}

func (r *repeatingReader) Read(p []byte) (int, error) {
	r.seen++
	var fill byte = 0xAB
	if r.seen > r.repeat {
		fill = byte(r.seen)
	}
	for i := range p {
		p[i] = fill
	}
	return len(p), nil
}

func TestAJobIdAlreadyInUseIsNeverRecordedOver(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// The first two draws are identical; the third differs.
	swapJobRand(t, &repeatingReader{repeat: 2})

	first, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "one"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(first.ID); j.State != state.JobSucceeded {
		t.Fatalf("first create: %+v", j)
	}
	second, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "two"})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID {
		t.Fatalf("two instances were admitted under one job id %s", first.ID)
	}
	if j := h.wait(second.ID); j.State != state.JobSucceeded {
		t.Fatalf("second create: %+v", j)
	}
	// The first instance's job row still describes the first instance.
	got, err := h.store.GetJob(first.ID)
	if err != nil {
		t.Fatalf("the first job's row is gone: %v", err)
	}
	if got.Instance != "one" {
		t.Fatalf("job %s now names instance %q; the second create overwrote it", first.ID, got.Instance)
	}
	// And both rows exist, one per instance.
	jobs, err := h.store.ListJobs("")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, j := range jobs {
		if j.Kind == "create" {
			seen[j.Instance] = j.ID
		}
	}
	if len(seen) != 2 || seen["one"] == "" || seen["two"] == "" {
		t.Fatalf("one create job row per instance expected, got %v", seen)
	}
}

// A source that never varies cannot be drawn from forever: the engine
// gives up rather than overwrite, and says which database to look at.
func TestAJobIdThatNeverVariesIsRefusedRatherThanReused(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	swapJobRand(t, &repeatingReader{repeat: 1 << 30})
	first, err := h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "one"})
	if err != nil {
		t.Fatal(err)
	}
	h.wait(first.ID)
	_, err = h.eng.Create(ctx, CreateRequest{Path: fixture, Name: "two"})
	if err == nil {
		t.Fatal("a second create was admitted under an id the store already holds")
	}
	if code(err) != pdr.CodeRuntimeFailed {
		t.Errorf("want %s, got %v", pdr.CodeRuntimeFailed, err)
	}
	got, err := h.store.GetJob(first.ID)
	if err != nil {
		t.Fatalf("the first job's row is gone: %v", err)
	}
	if got.Instance != "one" {
		t.Fatalf("job %s now names instance %q", first.ID, got.Instance)
	}
}

// The real source still yields distinct ids; the seam is a test seam.
func TestJobIdsAreDistinctFromTheRealSource(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		id, err := newJobID()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(id, "job_") || len(id) != len("job_")+16 {
			t.Fatalf("malformed id %q", id)
		}
		if seen[id] {
			t.Fatalf("id %s drawn twice in 64 draws", id)
		}
		seen[id] = true
	}
	// And the reader is read in full: eight bytes, not fewer.
	var buf bytes.Buffer
	swapJobRand(t, io.TeeReader(jobRand, &buf))
	if _, err := newJobID(); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 8 {
		t.Errorf("a job id read %d bytes of entropy, want 8", buf.Len())
	}
}
