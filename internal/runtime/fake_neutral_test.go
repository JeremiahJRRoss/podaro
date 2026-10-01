// SPDX-License-Identifier: AGPL-3.0-only

package runtime

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The reconciliation plan's R1: the platform's TLS mechanism and a
// destination for seeds are proven on vendor-neutral personalities, so
// the coverage needs no product.

// insecureClient accepts the fake's self-signed certificate, as the
// engine's probe and the adapters do for a lab's own.
var insecureClient = &http.Client{Transport: &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // the fake's own certificate
}}

func TestTLSEchoAnswersARealHandshakeOnEveryPort(t *testing.T) {
	f := newTestFake(t)
	ctx := context.Background()
	labels := map[string]string{LabelInstance: "lab", LabelManaged: "true"}
	_ = f.EnsureNetwork(ctx, "pdr-lab", labels, false)
	st := startFake(t, f, ContainerSpec{Name: "pdr-lab-echo", Image: "docker.io/example/tls-echo@sha256:" + strings.Repeat("7", 64),
		Network: "pdr-lab", Alias: "echo", Labels: map[string]string{LabelInstance: "lab", LabelManaged: "true", LabelService: "echo"}, Publish: []int{8443, 9443}})
	for _, port := range []int{8443, 9443} {
		host := "127.0.0.1:" + strconv.Itoa(st.Ports[port])
		resp, err := insecureClient.Get("https://" + host + "/probe")
		if err != nil {
			t.Fatalf("port %d over TLS: %v", port, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "tls") || !strings.Contains(string(body), "/probe") {
			t.Fatalf("port %d answered %d %q", port, resp.StatusCode, body)
		}
		// Plain HTTP meets the handshake: the listener refuses it the way
		// any TLS listener does, so a checkpoint that names https is
		// proven against a port that speaks nothing else.
		plain, err := http.Get("http://" + host + "/probe")
		if err == nil {
			raw, _ := io.ReadAll(plain.Body)
			plain.Body.Close()
			if plain.StatusCode == http.StatusOK {
				t.Fatalf("port %d answered plain HTTP with 200: %q", port, raw)
			}
		}
	}
}

func TestTheSinkKeepsWhatItReceivedAndCountsRequests(t *testing.T) {
	t.Setenv(EnvFakeReadyDelay, "0s")
	path := filepath.Join(t.TempDir(), "world.json")
	f, err := NewFake(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)
	ctx := context.Background()
	labels := map[string]string{LabelInstance: "lab", LabelManaged: "true"}
	_ = f.EnsureNetwork(ctx, "pdr-lab", labels, false)
	spec := ContainerSpec{Name: "pdr-lab-sink", Image: "docker.io/example/ndjson-sink@sha256:" + strings.Repeat("5", 64),
		Network: "pdr-lab", Alias: "sink", Labels: map[string]string{LabelInstance: "lab", LabelManaged: "true", LabelService: "sink"}, Publish: []int{8080}}
	st := startFake(t, f, spec)
	base := "http://127.0.0.1:" + strconv.Itoa(st.Ports[8080])

	// An ingest, the way a built-in generator delivers: one JSON object
	// per line.
	body := `{"seq":1,"@timestamp":"2026-09-23T10:00:00Z"}` + "\n" + `{"seq":2}` + "\n" + `{"seq":3}` + "\n"
	resp, err := http.Post(base+"/ingest", "application/x-ndjson", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var accepted struct {
		Accepted int `json:"accepted"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&accepted)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || accepted.Accepted != 3 {
		t.Fatalf("ingest answered %d, accepted %d", resp.StatusCode, accepted.Accepted)
	}
	// Two plain requests, the way http-requests knocks.
	for i := 0; i < 2; i++ {
		if getJSON(t, base+"/ping", nil) != http.StatusOK {
			t.Fatal("a plain request is answered 200")
		}
	}
	stats := func(base string) (requests, events int) {
		var out struct {
			Requests int `json:"requests"`
			Events   int `json:"events"`
		}
		if getJSON(t, base+"/_stats", &out) != http.StatusOK {
			t.Fatal("stats")
		}
		return out.Requests, out.Events
	}
	if r, e := stats(base); r != 3 || e != 3 {
		t.Fatalf("after one ingest and two pings: %d requests, %d events", r, e)
	}
	var docs struct {
		Count     int              `json:"count"`
		Documents []map[string]any `json:"documents"`
	}
	getJSON(t, base+"/_documents", &docs)
	if docs.Count != 3 || len(docs.Documents) != 3 || docs.Documents[0]["seq"] != float64(1) || docs.Documents[0]["@timestamp"] != "2026-09-23T10:00:00Z" {
		t.Fatalf("the documents are read back as received: %+v", docs)
	}
	// The reads did not count, and neither did the root a readiness
	// probe reads: a verify never moves the number it judges, and the
	// probes alone never turn an objective green.
	if getJSON(t, base+"/", nil) != http.StatusOK {
		t.Fatal("the root answers 200 for readiness")
	}
	if r, _ := stats(base); r != 3 {
		t.Fatalf("a read or a probe counted as a request: %d", r)
	}

	// A stop and a start keep what the sink holds; so does an engine
	// restart — a new Fake over the same world.
	if err := f.Stop(ctx, spec.Name, 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Start(ctx, spec.Name); err != nil {
		t.Fatal(err)
	}
	st2, _ := f.Inspect(ctx, spec.Name)
	if r, e := stats("http://127.0.0.1:" + strconv.Itoa(st2.Ports[8080])); r != 3 || e != 3 {
		t.Fatalf("a stop and a start lost the sink's contents: %d requests, %d events", r, e)
	}
	again, err := NewFake(path)
	if err != nil {
		t.Fatal(err)
	}
	st3, _ := again.Inspect(ctx, spec.Name)
	if r, e := stats("http://127.0.0.1:" + strconv.Itoa(st3.Ports[8080])); r != 3 || e != 3 {
		t.Fatalf("a restart lost the sink's contents: %d requests, %d events", r, e)
	}
	again.Close()

	// A removal drops it: the next container under the name starts empty.
	if err := f.Remove(ctx, spec.Name); err != nil {
		t.Fatal(err)
	}
	st4 := startFake(t, f, spec)
	if r, e := stats("http://127.0.0.1:" + strconv.Itoa(st4.Ports[8080])); r != 0 || e != 0 {
		t.Fatalf("a removed sink kept its contents: %d requests, %d events", r, e)
	}
}
