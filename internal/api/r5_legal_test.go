// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/pdr"
)

// The reconciliation plan's R5 (API §2, §5; threat model B1): GET
// /system/legal answers without a credential — an attendee and a visitor
// at the sign-in page must reach the source offer — with the licence, the
// owner's two statements and the offer, as JSON and, to Accept:
// text/html, as the fragment of the same value. It writes nothing: the
// audit stream is as long after it as before. Every other route still
// denies until authenticated.
func TestTheLegalRouteAnswersWithoutACredential(t *testing.T) {
	srv, api, _ := newNetworkServer(t)
	before, err := engineOf[api].Audit("")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(srv.URL + Prefix + "/system/legal")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /system/legal without a credential: %d", resp.StatusCode)
	}
	var out struct {
		Legal struct {
			License   string `json:"license"`
			Copyright string `json:"copyright"`
			Licensing string `json:"licensing"`
			Source    struct {
				Offer      string `json:"offer"`
				Repository string `json:"repository"`
			} `json:"source"`
		} `json:"legal"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	l := out.Legal
	if l.License != "AGPL-3.0-only" || !strings.HasPrefix(l.Copyright, "Copyright © 2026 Jeremiah Ross, to the extent copyright subsists") ||
		!strings.HasPrefix(l.Licensing, "To the extent copyright subsists") || l.Source.Offer == "" || !strings.HasPrefix(l.Source.Repository, "https://") {
		t.Fatalf("the legal summary: %+v", l)
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+Prefix+"/system/legal", nil)
	req.Header.Set("Accept", "text/html")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	page, _ := io.ReadAll(resp2.Body)
	if resp2.StatusCode != http.StatusOK || !strings.Contains(string(page), `<h1 id="legal-title">Licence and source</h1>`) || !strings.Contains(string(page), l.Source.Repository) {
		t.Fatalf("the HTML twin: %d %s", resp2.StatusCode, page)
	}
	after, err := engineOf[api].Audit("")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("the public route wrote to the audit stream: %d records, then %d", len(before), len(after))
	}
	for _, path := range []string{"/system", "/instances", "/healthz", "/auth/tokens"} {
		r, err := http.Get(srv.URL + Prefix + path)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s without a credential: %d, want 401 — only the legal route is public", path, r.StatusCode)
		}
	}
	if r, err := http.Post(srv.URL+Prefix+"/system/legal", "application/json", strings.NewReader("{}")); err != nil {
		t.Fatal(err)
	} else {
		r.Body.Close()
		if r.StatusCode == http.StatusOK {
			t.Error("the public route is GET only")
		}
	}
}

// Rate-limited per source like the login form (threat model B1): a burst,
// then one request every publicRefill; past it, 429 with PDR-E315 and a
// Retry-After, in the envelope. Another source is not affected, and time
// restores the allowance. The source is the peer address, never a
// forwarded header.
func TestTheLegalRouteIsRateLimitedPerSource(t *testing.T) {
	_, api, _ := newNetworkServer(t)
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	api.public.now = func() time.Time { return now }
	h := api.NetworkHandler()
	get := func(remote, forwarded string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, Prefix+"/system/legal", nil)
		req.RemoteAddr = remote
		if forwarded != "" {
			req.Header.Set("X-Forwarded-For", forwarded)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for i := 0; i < publicBurst; i++ {
		if rec := get("198.51.100.7:40000", fmt.Sprintf("203.0.113.%d", i)); rec.Code != http.StatusOK {
			t.Fatalf("request %d of the burst: %d", i+1, rec.Code)
		}
	}
	rec := get("198.51.100.7:40001", "203.0.113.200")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("past the burst (a forwarded header changes nothing): %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "2" {
		t.Errorf("Retry-After = %q, want 2", rec.Header().Get("Retry-After"))
	}
	var out map[string]map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["error"]["code"] != pdr.CodePublicThrottled {
		t.Fatalf("the refusal's envelope: %s", rec.Body.String())
	}
	if rec := get("192.0.2.9:5000", ""); rec.Code != http.StatusOK {
		t.Fatalf("another source is limited by the first: %d", rec.Code)
	}
	now = now.Add(publicRefill)
	if rec := get("198.51.100.7:40002", ""); rec.Code != http.StatusOK {
		t.Fatalf("the allowance did not refill: %d", rec.Code)
	}
	if rec := get("198.51.100.7:40003", ""); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("one refill admits one request: %d", rec.Code)
	}
}

// The local socket is the operator's own door: the allowance does not
// apply there.
func TestTheSocketDoorIsNotRateLimited(t *testing.T) {
	srv, _ := newServer(t)
	for i := 0; i < publicBurst+10; i++ {
		if code, out := call(t, srv, http.MethodGet, "/system/legal", nil); code != http.StatusOK {
			t.Fatalf("request %d at the socket: %d %v", i+1, code, out)
		}
	}
}

// The allowance holds memory for a bounded number of sources: a source
// whose allowance has refilled is forgotten first, and past the bound a
// new source waits rather than growing the table.
func TestThePublicAllowanceIsBounded(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	l := newPublicLimiter()
	l.now = func() time.Time { return now }
	for i := 0; i < publicSources; i++ {
		if _, ok := l.allow(fmt.Sprintf("10.0.%d.%d", i/256, i%256)); !ok {
			t.Fatalf("source %d refused below the bound", i)
		}
	}
	if _, ok := l.allow("192.0.2.1"); ok {
		t.Fatal("a new source past the bound grew the table")
	}
	if _, ok := l.allow("10.0.0.1"); !ok {
		t.Fatal("a known source was refused because the table is full")
	}
	now = now.Add(publicBurst * publicRefill)
	if _, ok := l.allow("192.0.2.1"); !ok {
		t.Fatal("refilled sources were not forgotten to make room")
	}
	if len(l.buckets) > publicSources {
		t.Fatalf("the table holds %d sources", len(l.buckets))
	}
}
