// SPDX-License-Identifier: AGPL-3.0-only

package system

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremiahjrross/podaro/internal/pdr"
	"github.com/jeremiahjrross/podaro/internal/render"
)

// Round 9 redacted the release location in five messages and I wrote
// down that it was redacted in all five. There were nine. I had
// enumerated by looking for `o.Base`, and the location also travels as a
// value derived from it — `releaseURL(o.Base, …)` becomes the `url`
// argument of `fetch` and `download`, which print it on any non-200.
// Two more branches of `latestVersion` print `o.Base` itself, and both
// are what a mirror still being filled actually answers.
//
// The question that finds them all is not "where is o.Base mentioned"
// but "where can a URL derived from it reach a message".
func TestEveryMirrorFailureKeepsTheCredentialOut(t *testing.T) {
	const cred = "s3cr3t-in-a-url" // a fixture, not a secret this tree holds
	exe, _ := upgradeEnv(t)

	// Each of these is what a mirror that is present but not ready
	// answers, and each took a different branch.
	for _, c := range []struct {
		name    string
		handler http.HandlerFunc
		pin     string
	}{
		{"an empty latest", func(w http.ResponseWriter, _ *http.Request) {}, ""},
		{"a latest that is not a version", func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("v\n"))
		}, ""},
		{"a 404 for the asset", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "no such release", http.StatusNotFound)
		}, "9.9.9"},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(c.handler)
			defer srv.Close()
			base := "http://svc:" + cred + "@" + strings.TrimPrefix(srv.URL, "http://")

			err := Upgrade(render.New(io.Discard, false, false), UpgradeOptions{
				Base: base, Version: c.pin, Exe: exe,
				Client:  &http.Client{Timeout: 5 * time.Second},
				Restart: func() error { return nil },
			})
			if err == nil {
				t.Fatal("expected the upgrade to fail")
			}
			whole := err.Error()
			var e *pdr.Error
			if errors.As(err, &e) {
				whole += e.Cause + e.Next
			}
			if strings.Contains(whole, cred) {
				t.Error("the failure repeated the mirror's credential")
			}
			if !strings.Contains(whole, "127.0.0.1") {
				t.Errorf("the failure no longer says which mirror it asked: %v", err)
			}
		})
	}
}
