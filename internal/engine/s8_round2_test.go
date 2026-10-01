// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/state"
)

// Review round 2, re-homed on a vendor-neutral
// destination by the reconciliation plan's R1.
//
// A built-in generator's events were timestamped from the instance's
// creation instant. A lab's checks read a window ending now, so a
// learner who pressed a step's seed twenty minutes after creating the
// lab sent events already outside every one of them: a count read a
// false zero, a measurement found no input volume at all.
//
// Spec 0002 §5 obliges a generator to derive its randomness from the
// seed value — same instance, same seed, same payload identity. When the
// events were delivered is not part of that identity, and spec 0003 §4
// (the additive line of 2026-09-07) anchors them at the seed run. This
// proves it where a seed lands: the sink holds documents stamped inside
// the fifteen minutes a lab asks about, whatever the instance's age.
func TestASeedsEventsLandInsideTheWindowTheLabAsksAbout(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "playbooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A lab's shape in miniature: a destination takes the delivery and
	// keeps the documents with the timestamp the generator wrote. A seed
	// a playbook step names runs when it is pressed, not at create.
	lab := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Template\n" +
		"metadata: { name: windowed, version: 1.0.0, title: Window fixture }\n" +
		"services:\n" +
		"  sink:\n    image: docker.io/example/ndjson-sink@sha256:" + strings.Repeat("5", 64) + "\n" +
		"    endpoints: [ { purpose: api, port: 8080, scheme: http } ]\n" +
		"    readiness: { probe: { port: 8080 }, typical: 100ms, budget: 10s }\n" +
		"seeds:\n  events: { generator: web-logs, count: 5, params: { service: sink, purpose: api, path: /ingest } }\n"
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(lab), 0o644); err != nil {
		t.Fatal(err)
	}
	pb := "apiVersion: lab.podaro.dev/v1alpha1\nkind: Playbook\nmetadata: { name: p, title: P }\n" +
		"steps:\n  - id: send\n    title: Send\n    body: press it\n    actions: [ { seed: events } ]\n"
	if err := os.WriteFile(filepath.Join(dir, "playbooks", "p.yaml"), []byte(pb), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := h.eng.Create(ctx, CreateRequest{Path: dir, Name: "windowed"})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.State != state.JobSucceeded {
		t.Fatalf("create: %+v\n%s", j, journalOf(h, job.ID))
	}

	// The lab was created two hours ago; the learner is pressing the
	// button now.
	inst, err := h.store.GetInstance("windowed")
	if err != nil || inst == nil {
		t.Fatalf("instance: %v", err)
	}
	inst.Created = time.Now().Add(-2 * time.Hour).UTC()
	if err := h.store.PutInstance(*inst); err != nil {
		t.Fatal(err)
	}

	sj, err := h.eng.SeedAs(ctx, "windowed", "events", Socket)
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(sj.ID); j.State != state.JobSucceeded {
		t.Fatalf("seed: %+v", j)
	}

	// Asked of the destination: the documents it holds carry the
	// `@timestamp` the generator wrote, and a lab's checks read a window
	// ending now.
	port := hostPort(t, h, "windowed", "sink", 8080)
	stamps := sinkTimestamps(t, port)
	if len(stamps) != 5 {
		t.Fatalf("the fixture delivered %d documents to the sink, not 5", len(stamps))
	}
	cutoff := time.Now().Add(-15 * time.Minute)
	for _, at := range stamps {
		if at.Before(cutoff) {
			t.Errorf("an event is stamped %s — %s before now, and outside the fifteen minutes the lab asks about",
				at.Format(time.RFC3339), time.Since(at).Round(time.Minute))
			break
		}
	}
}

// sinkTimestamps reads the sink's documents back and returns the
// `@timestamp` each one carries.
func sinkTimestamps(t *testing.T, port int) []time.Time {
	t.Helper()
	resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/_documents")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out struct {
		Documents []map[string]any `json:"documents"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("the sink answered %s", raw)
	}
	var stamps []time.Time
	for _, doc := range out.Documents {
		text, _ := doc["@timestamp"].(string)
		at, err := time.Parse(time.RFC3339, text)
		if err != nil {
			t.Fatalf("a document carries %q as its @timestamp", text)
		}
		stamps = append(stamps, at)
	}
	return stamps
}

func hostPort(t *testing.T, h *harness, instance, service string, port int) int {
	t.Helper()
	st, err := h.fake.Inspect(context.Background(), containerName(instance, service))
	if err != nil {
		t.Fatal(err)
	}
	mapped, ok := st.Ports[port]
	if !ok {
		t.Fatalf("port %d is not published: %v", port, st.Ports)
	}
	return mapped
}
