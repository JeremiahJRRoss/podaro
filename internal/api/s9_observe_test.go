// SPDX-License-Identifier: AGPL-3.0-only

package api

// Plan S9, API §5: the observability export's own two endpoints — what
// is configured, and a probe that reports what the destination said.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/config"
	"github.com/jeremiahjrross/podaro/internal/observe"
)

// TestObservePostureOffByDefault: an engine with no destinations
// configured answers honestly rather than 404 — off is a posture, and
// the operator asking is entitled to see it.
func TestObservePostureOffByDefault(t *testing.T) {
	srv, _ := newServer(t)
	code, out := call(t, srv, http.MethodGet, "/system/observe", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /system/observe: %d %v", code, out)
	}
	for _, sig := range []string{"logs", "metrics", "traces"} {
		s, _ := out[sig].(map[string]any)
		if s["exporter"] != "off" {
			t.Fatalf("%s = %v — want off", sig, s)
		}
	}
	code, out = call(t, srv, http.MethodPost, "/system/observe/test", nil)
	if code != http.StatusOK {
		t.Fatalf("POST /system/observe/test: %d %v", code, out)
	}
	probes, _ := out["probes"].([]any)
	if len(probes) != 0 {
		t.Fatalf("probes = %v — want none when export is off", probes)
	}
}

// TestObserveReportsWhatTheDestinationAnswered: the endpoint never
// summarizes a probe that failed as anything but a failure.
func TestObserveReportsWhatTheDestinationAnswered(t *testing.T) {
	status := http.StatusOK
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	defer dest.Close()
	exp, err := observe.New(observe.Options{
		Config: &config.Observability{Logs: &config.Signal{Exporter: "http", Endpoint: dest.URL}},
		Filter: func() (func(string) string, error) { return func(s string) string { return s }, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Options{Observe: exp}).SocketHandler())
	defer srv.Close()

	code, out := call(t, srv, http.MethodGet, "/system/observe", nil)
	logs, _ := out["logs"].(map[string]any)
	if code != http.StatusOK || logs["exporter"] != "http" || logs["endpoint"] != dest.URL {
		t.Fatalf("posture = %d %v", code, out)
	}
	code, out = call(t, srv, http.MethodPost, "/system/observe/test", nil)
	probes, _ := out["probes"].([]any)
	if code != http.StatusOK || len(probes) != 1 {
		t.Fatalf("probes = %d %v", code, out)
	}
	p, _ := probes[0].(map[string]any)
	if p["ok"] != true || p["signal"] != "logs" {
		t.Fatalf("probe = %v — want the logs signal landing", p)
	}

	status = http.StatusUnauthorized
	_, out = call(t, srv, http.MethodPost, "/system/observe/test", nil)
	probes, _ = out["probes"].([]any)
	p, _ = probes[0].(map[string]any)
	if p["ok"] != false {
		t.Fatalf("probe = %v — want the refusal reported as one", p)
	}
	if s, _ := p["error"].(string); s == "" {
		t.Fatalf("a failed probe carries what the destination answered: %v", p)
	}
}
