// SPDX-License-Identifier: AGPL-3.0-only

package evidence

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

func TestJournalAppendListGet(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	j := Open(dir)
	if list, err := j.List(Filter{}); err != nil || len(list) != 0 {
		t.Fatalf("empty journal lists []: %v %v", list, err)
	}
	now := time.Now().UTC()
	e1, err := j.Append(Entry{Type: TypeLifecycle, Instance: "lab", Job: "job_1", Lifecycle: &Lifecycle{Event: "stage", Stage: "healthy"}})
	if err != nil {
		t.Fatal(err)
	}
	e2, _ := j.Append(Entry{Type: TypeCheckpoint, Instance: "lab", Job: "job_1", Authoring: true, Checkpoint: &state.CheckpointResult{ID: "prometheus-ready", Class: "baseline", Status: "pass", Duration: "10ms", At: now}})
	e3, _ := j.Append(Entry{Type: TypeSeed, Instance: "lab", Job: "job_2", Seed: &SeedRun{Name: "query-load", Generator: "http-requests", Kind: "built-in", Count: 200, SeedValue: "9f2c66d1a4e07b53", Duration: "1s"}})
	e4, _ := j.Append(Entry{Type: TypeCheckpoint, Instance: "lab", Job: "job_3", Checkpoint: &state.CheckpointResult{ID: "prometheus-ready", Class: "baseline", Status: "fail", Duration: "10ms", At: now.Add(time.Second)}})
	ids := []string{e1.ID, e2.ID, e3.ID, e4.ID}
	if !sort.StringsAreSorted(ids) || len(ids[0]) != len("ev_")+26 || !strings.HasPrefix(ids[0], "ev_") {
		t.Fatalf("ids must be sortable ULIDs: %v", ids)
	}
	for _, id := range ids {
		fi, err := os.Stat(filepath.Join(dir, id+".json"))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("entry file %s: %v %v", id, fi, err)
		}
	}
	if di, _ := os.Stat(dir); di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", di.Mode().Perm())
	}
	all, err := j.List(Filter{})
	if err != nil || len(all) != 4 || all[0].ID != e1.ID || all[3].ID != e4.ID {
		t.Fatalf("list: %+v %v", all, err)
	}
	if got := all[1]; got.Type != TypeCheckpoint || got.Checkpoint == nil || got.Checkpoint.ID != "prometheus-ready" || !got.Authoring || got.Job != "job_1" || got.At.IsZero() {
		t.Fatalf("round trip: %+v", got)
	}
	if cps, _ := j.List(Filter{Type: TypeCheckpoint}); len(cps) != 2 {
		t.Fatalf("by type: %+v", cps)
	}
	if runs, _ := j.List(Filter{Checkpoint: "prometheus-ready"}); len(runs) != 2 || runs[0].Checkpoint.Status != "pass" || runs[1].Checkpoint.Status != "fail" {
		t.Fatalf("both runs of one checkpoint stay in the journal: %+v", runs)
	}
	if byJob, _ := j.List(Filter{Job: "job_2"}); len(byJob) != 1 || byJob[0].Seed == nil || byJob[0].Seed.Count != 200 {
		t.Fatalf("by job: %+v", byJob)
	}
	if since, _ := j.List(Filter{Since: e3.At}); len(since) < 2 {
		t.Fatalf("since: %+v", since)
	}
	got, err := j.Get(e3.ID)
	if err != nil || got.Seed.SeedValue != "9f2c66d1a4e07b53" {
		t.Fatalf("get: %+v %v", got, err)
	}
	for _, bad := range []string{"nope", "../x", "ev_" + strings.Repeat("0", 26)} {
		if _, err := j.Get(bad); !errors.Is(err, ErrNotFound) {
			t.Fatalf("get %q: %v", bad, err)
		}
	}
	// Append-only: an id already there is never overwritten.
	if _, err := j.Append(Entry{ID: e1.ID, Type: TypeLifecycle, Instance: "lab", Lifecycle: &Lifecycle{Event: "rewrite"}}); err == nil {
		t.Fatal("an existing entry must never be rewritten")
	}
	if got, _ := j.Get(e1.ID); got.Lifecycle.Event != "stage" {
		t.Fatal("entry changed")
	}
	// No temporary files linger.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 4 {
		t.Fatalf("directory holds %d files", len(entries))
	}
	// Ids stay monotonic inside one millisecond.
	var last string
	for i := 0; i < 50; i++ {
		e, _ := j.Append(Entry{Type: TypeLifecycle, Instance: "lab", At: now, Lifecycle: &Lifecycle{Event: "tick"}})
		if e.ID <= last {
			t.Fatalf("id %s not after %s", e.ID, last)
		}
		last = e.ID
	}
}

// Ids keep the append order whatever the clock does: an entry appended
// under a clock that moved back sorts after the one before it, within one
// process and across a reopen — the
// listing sorts by id, and the API defines that order as the append
// order.
func TestEvidenceIDsKeepTheAppendOrderWhateverTheClock(t *testing.T) {
	dir := t.TempDir()
	j := Open(dir)
	base := time.Date(2026, 9, 6, 15, 0, 0, 0, time.UTC)
	first, err := j.Append(Entry{Type: TypeLifecycle, Instance: "x", At: base, Lifecycle: &Lifecycle{Event: "one"}})
	if err != nil {
		t.Fatal(err)
	}
	back, err := j.Append(Entry{Type: TypeLifecycle, Instance: "x", At: base.Add(-time.Second), Lifecycle: &Lifecycle{Event: "two"}})
	if err != nil {
		t.Fatal(err)
	}
	if back.ID <= first.ID {
		t.Fatalf("an entry appended under a clock that moved back must sort after the one before it: %s then %s", first.ID, back.ID)
	}
	// Reopened under a clock still further back: the newest id on disk
	// is where the sequence continues.
	j2 := Open(dir)
	third, err := j2.Append(Entry{Type: TypeLifecycle, Instance: "x", At: base.Add(-time.Minute), Lifecycle: &Lifecycle{Event: "three"}})
	if err != nil {
		t.Fatal(err)
	}
	if third.ID <= back.ID {
		t.Fatalf("a reopened journal continues after its newest id: %s then %s", back.ID, third.ID)
	}
	list, err := j2.List(Filter{})
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, e := range list {
		got = append(got, e.Lifecycle.Event)
	}
	if strings.Join(got, ",") != "one,two,three" {
		t.Fatalf("the listing is the append order: %v", got)
	}
	// Forward time still moves the id's millisecond forward.
	fourth, _ := j2.Append(Entry{Type: TypeLifecycle, Instance: "x", At: base.Add(time.Hour), Lifecycle: &Lifecycle{Event: "four"}})
	if ms, ok := idMillis(strings.TrimPrefix(fourth.ID, "ev_")); !ok || ms != base.Add(time.Hour).UnixMilli() {
		t.Fatalf("a later clock is embedded as written: %s %d", fourth.ID, ms)
	}
}

func TestJUnitRendering(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	results := []state.CheckpointResult{
		{ID: "prometheus-ready", Class: "baseline", Adapter: "http", Status: "pass", Duration: "120ms", At: now, Observed: json.RawMessage(`{"status":200}`), Expected: json.RawMessage(`{"status":200}`), Message: "GET http://prometheus:9090/-/ready → 200"},
		{ID: "grafana-healthy", Class: "baseline", Adapter: "http", Status: "error", Duration: "30s", At: now, Error: &pdr.Error{Code: "PDR-E401", Message: "checkpoint attempt timed out", Cause: "no answer in 30s", Next: "podaro logs lab grafana"}},
		{ID: "dashboard-exists", Class: "objective", Adapter: "http", Status: "fail", Duration: "80ms", At: now, Hint: "Check the title is exactly \"Lab Overview\"", Observed: json.RawMessage(`null`), Message: "json_path $[0].title: no such element"},
		{ID: "routes-understood", Class: "objective", Adapter: "attest", Status: "attested", Duration: "0s", At: now},
		{ID: "never-run", Class: "objective", Adapter: "http", Status: "", Duration: ""},
	}
	raw := JUnit("lab", "grafana-prometheus-intro@1.0.0", results)
	var suites junitSuites
	if err := xml.Unmarshal(raw, &suites); err != nil {
		t.Fatalf("not well-formed XML: %v\n%s", err, raw)
	}
	if suites.Tests != 5 || suites.Failures != 1 || suites.Errors != 1 || suites.Skipped != 2 || len(suites.Suites) != 2 {
		t.Fatalf("totals: %+v", suites)
	}
	base, obj := suites.Suites[0], suites.Suites[1]
	if base.Name != "baseline" || base.Tests != 2 || base.Errors != 1 || base.Timestamp != "2026-09-05T12:00:00Z" {
		t.Fatalf("baseline suite: %+v", base)
	}
	if base.Cases[0].Name != "grafana-healthy" || base.Cases[0].Error == nil || !strings.Contains(base.Cases[0].Error.Message, "PDR-E401") || base.Cases[0].Time != "30.000" {
		t.Fatalf("error case: %+v", base.Cases[0])
	}
	if base.Cases[1].Name != "prometheus-ready" || base.Cases[1].Failure != nil || base.Cases[1].Time != "0.120" || !strings.Contains(base.Cases[1].SystemOut, `observed: {"status":200}`) {
		t.Fatalf("pass case: %+v", base.Cases[1])
	}
	if obj.Cases[0].Name != "dashboard-exists" || obj.Cases[0].Failure == nil || obj.Cases[0].Failure.Body != "Check the title is exactly \"Lab Overview\"" || obj.Cases[0].ClassName != "objective.http" {
		t.Fatalf("fail case: %+v", obj.Cases[0])
	}
	// Cases sort by id: dashboard-exists, never-run, routes-understood.
	if obj.Cases[2].Name != "routes-understood" || obj.Cases[2].Skipped == nil || !strings.Contains(obj.Cases[2].Skipped.Message, "attested") || obj.Cases[2].Failure != nil {
		t.Fatalf("an attested result is skipped, never a pass: %+v", obj.Cases[2])
	}
	if obj.Cases[1].Name != "never-run" || obj.Cases[1].Skipped == nil || obj.Cases[1].Skipped.Message != "not evaluated" {
		t.Fatalf("a pending result is skipped: %+v", obj.Cases[1])
	}
	if !strings.HasPrefix(string(raw), xml.Header) || !strings.Contains(string(raw), `<testsuites name="lab · grafana-prometheus-intro@1.0.0"`) {
		t.Fatalf("header: %s", raw[:120])
	}
}
