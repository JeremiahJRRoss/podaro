// SPDX-License-Identifier: AGPL-3.0-only

package seed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The delivery treated every status below 400 as sent. The runner's own
// client is built with `http.ErrUseLastResponse`, so it deliberately
// does NOT follow a redirect — a 302 or 307 is a batch that went
// nowhere. It was counted as delivered, so a seed job reported success
// over events no destination ever received. That is what round 2 fixed
// in the acceptance script; this is the same thing in the product, where
// it also decides whether an objective is judged against data that
// arrived.
func TestASeedBatchThatWasRedirectedIsNotDelivered(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer srv.Close()

	r := &Runner{Resolver: &stubResolver{addr: strings.TrimPrefix(srv.URL, "http://"), port: 8088}}
	run := Run{Instance: "lab", Name: "web-logs", Generator: "web-logs", Count: 10,
		Params:    map[string]any{"service": "collector", "path": "/services/collector/raw", "purpose": "http-in"},
		SeedValue: SeedValue("s", "web-logs")}
	rep, perr := r.Run(context.Background(), run)
	if perr == nil {
		t.Fatalf("a redirected batch was reported as delivered: %+v (the destination answered 302 to %d request(s))", rep, hits)
	}
	if !strings.Contains(perr.Error(), "302") {
		t.Errorf("the refusal should name the status the destination gave: %v", perr)
	}

	// The premise, so this cannot pass by refusing everything: a plain
	// 200 is still a delivery.
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer ok.Close()
	r2 := &Runner{Resolver: &stubResolver{addr: strings.TrimPrefix(ok.URL, "http://"), port: 8088}}
	if rep, perr := r2.Run(context.Background(), run); perr != nil || rep.Sent["events"] != 10 {
		t.Fatalf("a 200 is a delivery: %+v %v", rep, perr)
	}
}
