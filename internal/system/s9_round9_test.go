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

// Mine, found sweeping round 9's finding about an observability
// endpoint's userinfo — the same question asked of the other URL an
// operator hands this engine.
//
// `--from` may point at a private mirror behind basic auth, so the
// credential is real and belongs in the request. It does not belong in
// the sentence that comes back: the release location is concatenated
// into an error's action, into a `Next` hint, and into three messages of
// `latestVersion`, all of which reach the operator's terminal and, from
// there, a bug report.
//
// Go's own client already replaces a password in the URL of a transport
// error with `***`. These are our own strings, and nothing replaced
// anything in them.
func TestAMirrorsCredentialStaysOutOfTheMessage(t *testing.T) {
	const cred = "s3cr3t-in-a-url" // a fixture, not a secret this tree holds
	// Port 1 answers nothing, so every path below is the failure path.
	base := "https://svc:" + cred + "@127.0.0.1:1/releases"

	_, err := latestVersion(UpgradeOptions{Base: base, Client: &http.Client{Timeout: 2 * time.Second}})
	if err == nil {
		t.Fatal("expected the unreachable mirror to fail")
	}
	if strings.Contains(err.Error(), cred) {
		t.Error("latestVersion repeated the mirror's credential in its error")
	}

	// A mirror that answers, badly: `latestVersion` prints the location
	// back in each of its three refusals, and those it reaches only when
	// something replies. Go's client strips a password from a transport
	// error's URL, so an unreachable host never exercised them.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("<html>not a version</html>"))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	if _, err := latestVersion(UpgradeOptions{
		Base:   "http://svc:" + cred + "@" + host,
		Client: &http.Client{Timeout: 2 * time.Second},
	}); err == nil {
		t.Error("a page is not a version and should have been refused")
	} else if strings.Contains(err.Error(), cred) {
		t.Error("latestVersion repeated the mirror's credential when refusing its answer")
	}

	err = Upgrade(render.New(io.Discard, false, false), UpgradeOptions{Base: base, Client: &http.Client{Timeout: 2 * time.Second}})
	if err == nil {
		t.Fatal("expected the unreachable mirror to fail the upgrade")
	}
	if strings.Contains(err.Error(), cred) {
		t.Error("the upgrade repeated the mirror's credential in its message")
	}
	// A PDR error carries its cause and its next step separately, and
	// both are printed.
	var e *pdr.Error
	if errors.As(err, &e) {
		if strings.Contains(e.Cause, cred) || strings.Contains(e.Next, cred) {
			t.Error("the upgrade repeated the mirror's credential in its cause or next step")
		}
		// It must still say where it was looking.
		if !strings.Contains(e.Message+e.Cause+e.Next, "127.0.0.1:1") {
			t.Errorf("the error no longer says which mirror it asked: %+v", e)
		}
	}
}
