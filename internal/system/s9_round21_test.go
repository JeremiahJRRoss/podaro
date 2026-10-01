// SPDX-License-Identifier: AGPL-3.0-only

package system

import (
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Review round 21, third finding — beside the row I
// made a warning last round.
//
// `reattached` decoded whatever came back. A `500` carrying the API's
// own error envelope decodes into the instance struct without complaint,
// because unknown fields are ignored and `instances` is simply absent —
// so the list came back empty and the upgrade board printed
// "instances … none" as a pass, in the one situation the warning row
// exists for. Round 19 made the *error* path a warning and left this
// one, which is the same mistake one line further along.
func TestAReattachThatFailsIsNotAnEmptyList(t *testing.T) {
	sock := socketPath(t)
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// The engine's own error envelope (API §3), served with the status
	// that goes with it.
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"code":"PDR-E204","message":"the state database cannot be read"}}`))
		})}
	go func() { _ = srv.Serve(l) }()
	defer srv.Close()

	names, _, err := reattached()
	if err == nil {
		t.Errorf("a %d answer was read as a healthy engine holding %d instance(s): the board calls that a pass",
			http.StatusInternalServerError, len(names))
	}
	if err != nil && !strings.Contains(err.Error(), "500") {
		t.Errorf("the failure does not name what the engine answered: %v", err)
	}

	// The healthy answer still reads: the check refuses a status, not a
	// body it can parse.
	srv.Close()
	l.Close()
	_ = os.Remove(sock)
	l2, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	ok := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"instances":[{"name":"pii-lab"},{"name":"intro"},{"name":"old-lab","unsupported":"retired template"}]}`))
		})}
	go func() { _ = ok.Serve(l2) }()
	defer ok.Close()
	names, unsupported, err := reattached()
	if err != nil || len(names) != 2 || names[0] != "pii-lab" {
		t.Errorf("a healthy engine's instances = %v %v", names, err)
	}
	// An instance the engine reports unsupported — an earlier build's
	// instance of a retired template — is not called reattached (the
	// reconciliation plan's R3).
	if len(unsupported) != 1 || unsupported[0] != "old-lab" {
		t.Errorf("the unsupported instances = %v, want [old-lab] apart from the reattached ones", unsupported)
	}
}

// `observe.Journal` queues every operational line from the moment the
// logger is wrapped, and a queue nobody flushes is a line that never
// leaves. The export loop was started — and its flush-on-close deferred
// — after the whole fallible start-up: `claimSocket`, the listener, and
// `eng.Start`, which logs a resumed job before it can fail on a later
// store read. So a start-up that failed wrote its lines to the journal
// and never attempted to export them, with the export configured.
//
// This is an assertion about order in the source rather than about
// behaviour, and deliberately so: `Serve` is one sequence with no seam
// to inject a failing start into, and the property *is* the order — the
// export must be running before anything exists that can log. The
// behavioural half, that an armed exporter delivers what it is given,
// is `hack/observe_export.sh`.
func TestTheExportIsArmedBeforeAnythingThatCanLog(t *testing.T) {
	raw, err := os.ReadFile("serve.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	at := func(needle string) int {
		i := strings.Index(src, needle)
		if i < 0 {
			t.Fatalf("serve.go no longer contains %q — if the wiring moved, this test must move with it", needle)
		}
		return i
	}
	built := at("observe.New(")
	run := at("go exporter.Run()")
	closed := at("defer exporter.Close()")
	// The first thing that can log: the engine is handed the wrapped
	// logger, and everything after it is fallible.
	firstLogger := at("engine.New(engine.Options{")

	if run < built || closed < built {
		t.Errorf("the export loop is armed before the exporter exists (New at %d, Run at %d, Close at %d)", built, run, closed)
	}
	if run > firstLogger {
		t.Errorf("the export loop starts after the first component that can log: a line written by a start-up that fails is queued and never flushed")
	}
	if closed > firstLogger {
		t.Errorf("the flush-on-close is deferred after the first component that can log: a start-up that fails returns without it")
	}
}
