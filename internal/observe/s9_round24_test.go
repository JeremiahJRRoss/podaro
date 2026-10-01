// SPDX-License-Identifier: AGPL-3.0-only

package observe

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/config"
)

// Review round 24, third finding — mine from round 23.
//
// Round 23 turned an OTLP rejection into an ordinary error, and `send`
// answers an error by counting the *whole* batch lost. A receiver that
// refuses one record of two hundred therefore reported two hundred
// dropped and nothing exported, which overstates the loss by the width
// of the batch. The counters exist to be acted on: one that says
// everything was lost when almost everything landed is as wrong as the
// silent success it replaced.
func TestOnlyTheRejectedRecordsAreCountedLost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"partialSuccess":{"rejectedLogRecords":"1"}}`))
	}))
	defer srv.Close()

	e, err := New(Options{Config: &config.Observability{
		Logs: &config.Signal{Exporter: "otlp", Endpoint: srv.URL},
	}, Filter: identity})
	if err != nil {
		t.Fatal(err)
	}
	const n = 10
	for i := range n {
		e.Log("info", fmt.Sprintf("line %d", i), nil)
	}
	e.Flush(context.Background())

	p := e.Posture()
	if p.Dropped != 1 {
		t.Errorf("dropped = %d after a receiver rejected one record of %d", p.Dropped, n)
	}
	if p.Exported != n-1 {
		t.Errorf("exported = %d — the receiver kept %d of them", p.Exported, n-1)
	}
	if p.Failures != 1 {
		t.Errorf("failures = %d — a batch that was not fully accepted is one failure", p.Failures)
	}
}

// Review round 24, fourth finding — also mine from round 23.
//
// `otlpRejected` read the first 4 KiB of the answer and treated a body
// it could not parse as full acceptance. OTLP puts no order on the
// fields, so a receiver whose `errorMessage` precedes its counts — and
// echoes a large request, which is exactly what a message about rejected
// records does — pushed the counts past the cut. The unmarshal then
// failed and the batch was counted exported: a fail-open path the
// destination itself decides to take.
func TestAnAnswerTooLargeToReadIsNotAnAcceptance(t *testing.T) {
	huge := strings.Repeat("x", 8<<10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"partialSuccess":{"errorMessage":%q,"rejectedLogRecords":"2"}}`, huge)
	}))
	defer srv.Close()

	e, err := New(Options{Config: &config.Observability{
		Logs: &config.Signal{Exporter: "otlp", Endpoint: srv.URL},
	}, Filter: identity})
	if err != nil {
		t.Fatal(err)
	}
	e.Log("info", "one", nil)
	e.Log("info", "two", nil)
	e.Flush(context.Background())

	p := e.Posture()
	if p.Exported != 0 {
		t.Errorf("exported = %d: the rejection was past the read limit and the batch was called exported", p.Exported)
	}
	if p.Dropped != 2 || p.Failures != 1 {
		t.Errorf("dropped = %d, failures = %d — want the rejected records counted lost", p.Dropped, p.Failures)
	}
	// And the receiver's message is still not quoted back, however it
	// arrived (D161).
	if strings.Contains(p.LastErr, "xxxx") {
		t.Errorf("the receiver's message reached the posture: %.80q", p.LastErr)
	}
}
