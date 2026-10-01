// SPDX-License-Identifier: AGPL-3.0-only

package runtime

// A vendor-neutral destination for the fake runtime (the reconciliation
// plan's R1): `example/ndjson-sink`. It stands where a product's ingest
// endpoint would, so the platform's own behaviour — a seed delivered
// where a step names it, a checkpoint judged over what arrived, the seed
// epoch, a reset that empties a destination — is proven with no product
// in the picture.
//
// What it does is exactly what a checkpoint or a seed can observe:
//   - a POST or a PUT to any path is an ingest: the body is
//     newline-delimited JSON, one object per line, kept in the order
//     received;
//   - every other request is counted and answered 200, so the
//     `http-requests` generator moves a number a checkpoint can read —
//     except the root, which readiness probes read and which is
//     answered without counting, so the probes alone never move it;
//   - GET /_stats answers {"requests": n, "events": m}, and GET
//     /_documents answers {"count": m, "documents": [...]} — the last
//     500 at most, as received; the two reads are not counted, so a
//     verify never moves the number it judges.
//
// What a sink holds lives in the world file, by container, as a fake
// Grafana's dashboards do: a stop and a start keep it, an engine restart
// keeps it, a replacement or a removal drops it — the contract a lab's
// destinations have on a host with no volume under them.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// maxSinkDocuments bounds what one sink keeps; the newest are kept, the
// way an ingest endpoint's retention would.
const maxSinkDocuments = 500

// sinkState is what one sink container holds.
type sinkState struct {
	Requests  int              `json:"requests"`
	Documents []map[string]any `json:"documents,omitempty"`
}

type fakeSink struct {
	f    *Fake
	name string
}

func (s *fakeSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/_stats" && r.Method == http.MethodGet:
		requests, docs := s.f.sinkHeld(s.name)
		writeFakeJSON(w, http.StatusOK, map[string]any{"requests": requests, "events": len(docs)})
	case r.URL.Path == "/_documents" && r.Method == http.MethodGet:
		_, docs := s.f.sinkHeld(s.name)
		writeFakeJSON(w, http.StatusOK, map[string]any{"count": len(docs), "documents": docs})
	case r.Method == http.MethodPost || r.Method == http.MethodPut:
		dec := json.NewDecoder(io.LimitReader(r.Body, 8<<20))
		var docs []map[string]any
		for {
			var doc map[string]any
			if err := dec.Decode(&doc); err != nil {
				break
			}
			docs = append(docs, doc)
		}
		requests, held := s.f.sinkRecord(s.name, docs)
		writeFakeJSON(w, http.StatusOK, map[string]any{"accepted": len(docs), "requests": requests, "events": held})
	case r.URL.Path == "/":
		requests, docs := s.f.sinkHeld(s.name)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "fake %s ok · %d requests · %d events held\n", s.name, requests, len(docs))
	default:
		requests, held := s.f.sinkRecord(s.name, nil)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "fake %s ok · request %d · %d events held · path %s\n", s.name, requests, held, r.URL.Path)
	}
}

// sinkRecord counts one request and keeps the documents it carried.
func (f *Fake) sinkRecord(container string, docs []map[string]any) (requests, held int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.world.Sinks[container]
	if st == nil {
		st = &sinkState{}
		f.world.Sinks[container] = st
	}
	st.Requests++
	st.Documents = append(st.Documents, docs...)
	if n := len(st.Documents); n > maxSinkDocuments {
		st.Documents = append([]map[string]any(nil), st.Documents[n-maxSinkDocuments:]...)
	}
	_ = f.save()
	return st.Requests, len(st.Documents)
}

// sinkHeld reads a sink back without counting the read.
func (f *Fake) sinkHeld(container string) (int, []map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.world.Sinks[container]
	if st == nil {
		return 0, []map[string]any{}
	}
	return st.Requests, append([]map[string]any{}, st.Documents...)
}
