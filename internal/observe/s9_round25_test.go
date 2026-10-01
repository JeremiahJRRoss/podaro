// SPDX-License-Identifier: AGPL-3.0-only

package observe

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/jeremiahjrross/podaro/internal/config"
)

// truncating answers 200 with a Content-Length it does not deliver, then
// closes: the shape a reset connection or a mismatched length has on the
// client, where the read fails part-way.
func truncating(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				// A body that promises more than it sends, cut off at
				// the point a receiver's message would still be running.
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 400\r\n\r\n" +
					`{"partialSuccess":{"errorMessage":"` + strings.Repeat("x", 60)))
			}(c)
		}
	}()
	return "http://" + l.Addr().String()
}

// Review round 25, second finding — a hole in round
// 24's own fix.
//
// Round 24 bounded the answer and refused one past the bound, and still
// threw away the error from reading it. A body that stops early — a
// reset, a length that does not match — leaves partial bytes and an
// error; the partial bytes are not OTLP's JSON, and "not OTLP's JSON"
// was the branch that means "nothing here says a record was refused".
// So a receiver whose acceptance is *unknown* was counted as one that
// accepted everything.
func TestAnAnswerThatCouldNotBeReadIsNotAnAcceptance(t *testing.T) {
	e, err := New(Options{Config: &config.Observability{
		Logs: &config.Signal{Exporter: "otlp", Endpoint: truncating(t)},
	}, Filter: identity, Client: &http.Client{}})
	if err != nil {
		t.Fatal(err)
	}
	e.Log("info", "one", nil)
	e.Log("info", "two", nil)
	e.Flush(context.Background())

	p := e.Posture()
	if p.Exported != 0 {
		t.Errorf("exported = %d: the answer stopped part-way and the batch was called exported", p.Exported)
	}
	if p.Dropped != 2 || p.Failures != 1 {
		t.Errorf("dropped = %d, failures = %d — an acceptance nobody could read is not an acceptance", p.Dropped, p.Failures)
	}
	if strings.Contains(p.LastErr, "xxxx") {
		t.Errorf("the receiver's message reached the posture: %.80q", p.LastErr)
	}
}
