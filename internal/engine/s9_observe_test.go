// SPDX-License-Identifier: AGPL-3.0-only

package engine

// Plan S9, threat model B10: the filter the observability export runs
// every record through is the engine's own, built from every instance —
// and it fails closed exactly where the local paths do.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/observe"
	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/state"
)

const sealedLab = "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\nmetadata: { name: sealed, version: 1.0.0 }\nsecrets:\n  tok: { kind: token }\nservices:\n  web:\n    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609\n    endpoints: [ { purpose: ui, port: 80 } ]\n    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }\n"

func labDir(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	body := strings.Replace(sealedLab, "name: sealed", "name: "+name, 1)
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestExportFilterCoversEveryInstance: the export path's filter is every
// instance's filter applied in turn, so a line the engine writes about
// one lab is filtered by that lab's values — and by the next lab's, since
// the export stream is not per instance.
func TestExportFilterCoversEveryInstance(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for _, name := range []string{"one", "two"} {
		job, err := h.eng.Create(ctx, CreateRequest{Path: labDir(t, name), Name: name})
		if err != nil {
			t.Fatal(err)
		}
		if j := h.wait(job.ID); j.State != state.JobSucceeded {
			t.Fatalf("create %s: %+v", name, j)
		}
	}
	var values []string
	for _, name := range []string{"one", "two"} {
		v, err := h.eng.secretStore(name).Values()
		if err != nil {
			t.Fatal(err)
		}
		if v["tok"] == "" {
			t.Fatalf("%s generated no token", name)
		}
		values = append(values, v["tok"])
	}
	if values[0] == values[1] {
		t.Fatalf("two instances generated the same secret — the filter test proves nothing")
	}
	red, err := h.eng.ExportFilter()
	if err != nil {
		t.Fatal(err)
	}
	line := "one answered with " + values[0] + " and two with " + values[1]
	got := red(line)
	for i, v := range values {
		if strings.Contains(got, v) {
			t.Fatalf("instance %d's secret survived the export filter: %q", i, got)
		}
	}
	if !strings.Contains(got, "one answered with") {
		t.Fatalf("the filter ate more than the values: %q", got)
	}
}

// TestExportFilterFailsClosed: an instance whose secret store cannot be
// read refuses the whole filter — the export withholds rather than
// sending text no filter saw (PDR-E412, the same refusal the local
// paths raise).
func TestExportFilterFailsClosed(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	job, err := h.eng.Create(ctx, CreateRequest{Path: labDir(t, "sealed"), Name: "sealed"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	if _, err := h.eng.ExportFilter(); err != nil {
		t.Fatalf("a readable store: %v", err)
	}
	if err := os.RemoveAll(h.eng.secretStore("sealed").Dir()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.eng.secretStore("sealed").Dir(), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = h.eng.ExportFilter()
	if code(err) != pdr.CodeSecretStoreUnreadable {
		t.Fatalf("ExportFilter with an unreadable store: %v — want %s", err, pdr.CodeSecretStoreUnreadable)
	}
}

// recorder is a destination held in this process: the exporter's client
// is given a transport that answers 200 and keeps every body, so the
// test reads exactly what would have gone on the wire.
type recorder struct {
	mu     sync.Mutex
	bodies []string
}

func (r *recorder) client() *http.Client {
	return &http.Client{Transport: roundTrip(func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.bodies = append(r.bodies, req.URL.Path+" "+string(body))
		r.mu.Unlock()
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	})}
}

func (r *recorder) all() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.bodies, "\n")
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// recorderConfig points every signal at a URL the recorder answers.
var recorderConfig = config.Observability{
	Logs:    &config.Signal{Exporter: "http", Endpoint: "https://collector.invalid/logs"},
	Metrics: &config.Signal{Exporter: "otlp", Endpoint: "https://collector.invalid"},
	Traces:  &config.Signal{Exporter: "otlp", Endpoint: "https://collector.invalid"},
}

// TestJobExportsOneSpanAndItsCounts: a finished job is exported as one
// span and two points, carrying what it was and how it ended — and
// never a lab's own text.
func TestJobExportsOneSpanAndItsCounts(t *testing.T) {
	h := newHarness(t)
	rec := &recorder{}
	exp, err := observe.New(observe.Options{
		Config: &recorderConfig,
		Filter: func() (func(string) string, error) { return func(s string) string { return s }, nil },
		Client: rec.client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Wired as `engine serve` wires it: the exporter for this engine's
	// own spans and counts, and a logger already wrapped by
	// `observe.Journal` — the seam is at the point every component is
	// wired, not inside the engine, because the engine's own copy was
	// the only thing it ever reached.
	var local []string
	h.eng = New(Options{Store: h.store, Runtime: h.fake, StateDir: h.dir,
		CatalogDir: filepath.Join("..", "..", "scenarios"), PollInterval: 50 * time.Millisecond,
		Logf:    observe.Journal(func(f string, a ...any) { local = append(local, fmt.Sprintf(f, a...)) }, exp),
		Observe: exp})
	job, err := h.eng.Create(context.Background(), CreateRequest{Path: fixture, Name: "obs"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v", j)
	}
	exp.Flush(context.Background())
	body := rec.all()
	if !strings.Contains(body, "podaro.create") {
		t.Fatalf("no span for the create job:\n%s", body)
	}
	if !strings.Contains(body, "podaro.jobs.finished") || !strings.Contains(body, "podaro.job.duration_seconds") {
		t.Fatalf("the job's counts did not reach the destination:\n%s", body)
	}
	if !strings.Contains(body, `"instance"`) || !strings.Contains(body, "obs") {
		t.Fatalf("the span does not name its instance:\n%s", body)
	}
	// A journal line rides the same export, through the same seam that
	// writes it locally: one line, both places. `hack/observe_export.sh`
	// proves the other half — that `engine serve` gives this logger to
	// the gateway and the sweeper as well, not only to the engine.
	before := len(local)
	h.eng.opts.Logf("a journal line about %s", "obs")
	exp.Flush(context.Background())
	body = rec.all()
	if !strings.Contains(body, `"body":"a journal line about obs"`) {
		t.Fatalf("the engine's journal line did not reach the export:\n%s", body)
	}
	if len(local) != before+1 || local[len(local)-1] != "a journal line about obs" {
		t.Fatalf("local journal = %v — the export must not replace the operator's own journal", local[before:])
	}
}
